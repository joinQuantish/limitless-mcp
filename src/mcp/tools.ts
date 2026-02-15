/**
 * MCP Tools for Limitless MCP
 * All tools for prediction market trading on Base via Limitless Exchange
 * Tool names prefixed with 'limitless_' to avoid collision with other MCPs
 *
 * Phase 6.1: Authentication & Setup (6 tools)
 * - limitless_signup
 * - limitless_request_api_key
 * - limitless_setup_wallet
 * - limitless_import_wallet
 * - limitless_get_wallet_import_instructions
 * - limitless_import_private_key
 *
 * Phase 6.2: Wallet Info (4 tools)
 * - limitless_get_wallet_info
 * - limitless_get_wallet_status
 * - limitless_get_balances
 * - limitless_get_deposit_address
 *
 * Phase 6.3: Market Discovery (6 tools)
 * - limitless_get_markets
 * - limitless_search_markets
 * - limitless_get_market
 * - limitless_get_orderbook
 * - limitless_get_price_history
 * - limitless_get_categories
 *
 * Phase 6.4: Trading (8 tools)
 * - limitless_place_order
 * - limitless_cancel_order
 * - limitless_cancel_all_orders
 * - limitless_get_orders
 * - limitless_check_approvals
 * - limitless_set_approvals
 * - limitless_get_locked_balance
 * - limitless_get_quote
 *
 * Phase 6.5: Positions (4 tools)
 * - limitless_get_positions
 * - limitless_get_trades
 * - limitless_get_portfolio_history
 * - limitless_sync_positions
 *
 * Phase 6.5b: On-Chain Position Tracking (3 tools)
 * - limitless_get_onchain_shares
 * - limitless_check_token_balance
 * - limitless_get_public_positions
 *
 * Phase 6.6: Transfers (3 tools)
 * - limitless_send_eth
 * - limitless_send_usdc
 * - limitless_export_private_key
 *
 * Phase 6.7: API Key Management (3 tools)
 * - limitless_list_api_keys
 * - limitless_create_api_key
 * - limitless_revoke_api_key
 */

import { getPrismaClient } from '../db/index.js';
import { getApiKeyService } from '../services/apikey.service.js';
import { getUserService } from '../services/user.service.js';
import { getBaseWalletService, WalletImportBundle } from '../wallet/base-wallet.service.js';
import { getEncryptionService } from '../crypto/encryption.js';
import { getLimitlessClient } from '../limitless/client.js';
import { getLimitlessOrderService } from '../limitless/order.service.js';
import { getLimitlessApprovalService } from '../limitless/approval.service.js';
import { getPortfolioService } from '../limitless/portfolio.service.js';
import { config } from '../config/index.js';

export interface ToolContext {
  userId?: string;
}

/**
 * Input validation helpers for MCP tools
 * Prevents NaN, Infinity, and unreasonable values
 */

/**
 * Validates a positive number (for amounts, sizes, prices)
 * Checks for: typeof number, positive, finite, not NaN
 *
 * @param value - Value to validate
 * @param fieldName - Name of the field for error messages
 * @param options - Validation options
 * @returns void - throws Error if validation fails
 */
function validatePositiveNumber(
  value: unknown,
  fieldName: string,
  options: { min?: number; max?: number; maxDecimals?: number } = {}
): void {
  if (typeof value !== 'number' || !Number.isFinite(value) || Number.isNaN(value)) {
    throw new Error(`${fieldName} must be a valid number`);
  }
  if (value <= 0) {
    throw new Error(`${fieldName} must be a positive number`);
  }
  if (options.min !== undefined && value < options.min) {
    throw new Error(`${fieldName} must be at least ${options.min}`);
  }
  if (options.max !== undefined && value > options.max) {
    throw new Error(`${fieldName} must be at most ${options.max}`);
  }
  if (options.maxDecimals !== undefined) {
    const decimalPlaces = (value.toString().split('.')[1] || '').length;
    if (decimalPlaces > options.maxDecimals) {
      throw new Error(`${fieldName} has too many decimal places (max ${options.maxDecimals})`);
    }
  }
}

/**
 * Validates an integer for pagination
 * Checks for: typeof number, positive, integer, within bounds
 *
 * @param value - Value to validate
 * @param fieldName - Name of the field for error messages
 * @param options - Validation options
 * @returns number - validated and clamped value
 */
function validatePaginationInt(
  value: unknown,
  defaultValue: number,
  options: { min?: number; max?: number } = {}
): number {
  if (value === undefined || value === null) {
    return defaultValue;
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || Number.isNaN(value)) {
    return defaultValue;
  }
  const intValue = Math.floor(value);
  const min = options.min ?? 1;
  const max = options.max ?? 100;
  return Math.min(Math.max(min, intValue), max);
}

/**
 * All MCP tool definitions
 * Phase 6.1: Authentication & Setup tools
 */
export const limitlessTools = [
  // ============================================
  // AUTHENTICATION & SETUP (Phase 6.1)
  // ============================================
  {
    name: 'limitless_signup',
    description:
      'Create a new Limitless account with a fresh Base wallet. No access code required. Returns API credentials for all future requests.',
    inputSchema: {
      type: 'object',
      properties: {
        externalId: {
          type: 'string',
          description:
            'Your unique identifier (e.g., email, telegram:123456, or any unique string)',
        },
        keyName: {
          type: 'string',
          description: 'Optional friendly name for your API key',
        },
      },
      required: ['externalId'],
    },
  },
  {
    name: 'limitless_request_api_key',
    description:
      'Request a new API key for an existing Limitless user. Requires HMAC signature from existing API secret for security.',
    inputSchema: {
      type: 'object',
      properties: {
        externalId: {
          type: 'string',
          description: 'Your external user identifier',
        },
        signature: {
          type: 'string',
          description: 'HMAC-SHA256 signature of "externalId:timestamp" using your API secret',
        },
        timestamp: {
          type: 'string',
          description: 'Unix timestamp in milliseconds (must be within 5 minutes)',
        },
        keyName: {
          type: 'string',
          description: 'Optional friendly name for this API key',
        },
      },
      required: ['externalId', 'signature', 'timestamp'],
    },
  },
  {
    name: 'limitless_setup_wallet',
    description:
      'Generate a new Base wallet for your Limitless account. The private key is encrypted and stored securely.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_import_wallet',
    description:
      'Import an existing Base/Ethereum wallet for Limitless trading. Send an encrypted bundle - we never see your raw private key.',
    inputSchema: {
      type: 'object',
      properties: {
        encryptedKey: {
          type: 'string',
          description: 'Encrypted private key blob',
        },
        salt: {
          type: 'string',
          description: 'Salt used for encryption (hex encoded)',
        },
        iv: {
          type: 'string',
          description: 'IV used for encryption (hex encoded)',
        },
        publicKey: {
          type: 'string',
          description: 'Your Ethereum/Base wallet address for verification',
        },
        version: {
          type: 'string',
          description: 'Bundle version (default: 1.0)',
        },
      },
      required: ['encryptedKey', 'salt', 'iv', 'publicKey'],
    },
  },
  {
    name: 'limitless_get_wallet_import_instructions',
    description:
      'Get instructions for how to securely export and encrypt your Ethereum/Base wallet for import into Limitless.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_import_private_key',
    description:
      'Import an existing private key directly (simpler than encrypted import). Creates a new wallet linked to your account.',
    inputSchema: {
      type: 'object',
      properties: {
        externalId: {
          type: 'string',
          description: 'Your unique identifier (e.g., telegram:123456789)',
        },
        privateKey: {
          type: 'string',
          description: 'Hex-encoded Ethereum private key (with or without 0x prefix)',
        },
        keyName: {
          type: 'string',
          description: 'Optional friendly name for the API key',
        },
      },
      required: ['externalId', 'privateKey'],
    },
  },

  // ============================================
  // WALLET INFO (Phase 6.2)
  // ============================================
  {
    name: 'limitless_get_wallet_info',
    description:
      'Get your Limitless wallet information including Base address and wallet type (generated or imported).',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_get_wallet_status',
    description:
      'Get comprehensive wallet status including address, type, balances, and account status. Good for a quick overview.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_get_balances',
    description:
      'Get your ETH and USDC balances on Base. ETH is used for gas fees, USDC for trading on Limitless Exchange.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_get_deposit_address',
    description:
      'Get your wallet address for depositing ETH (gas) and USDC (trading). Shows the Base network address to send funds to.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },

  // ============================================
  // MARKET DISCOVERY (Phase 6.3)
  // ============================================
  {
    name: 'limitless_get_markets',
    description:
      'List active prediction markets on Limitless Exchange. Returns markets with prices, volume, and venue data for trading. Supports pagination for browsing all markets.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of markets to return (default 20, max 100)',
        },
        page: {
          type: 'number',
          description: 'Page number for pagination (default 1, starts at 1).',
        },
        category: {
          type: 'string',
          description: 'Optional category ID to filter markets (use limitless_get_categories to see available categories)',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_search_markets',
    description:
      'Search prediction markets using semantic/natural language search. Find markets by topic, question, or keywords. Better than get_markets when looking for specific topics.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query - can be natural language like "Will Bitcoin hit 100k" or keywords like "election 2024"',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of results (default 20, max 50)',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'limitless_get_market',
    description:
      'Get detailed information about a specific market including current prices, venue data for trading, token IDs, and market status. Use the market slug from get_markets or search_markets.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: {
          type: 'string',
          description: 'Market slug or address (e.g., "will-btc-reach-100k-in-2025")',
        },
      },
      required: ['slug'],
    },
  },
  {
    name: 'limitless_get_orderbook',
    description:
      'Get the current orderbook for a CLOB market showing all open buy and sell orders. Use this to see available liquidity and price levels before placing orders.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to get orderbook for',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_get_price_history',
    description:
      'Get historical price data for a market. Useful for analyzing price trends and market activity over time.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to get price history for',
        },
        interval: {
          type: 'string',
          description: 'Time interval for data points: "1m", "5m", "15m", "1h", "4h", "1d" (default "1h")',
        },
        limit: {
          type: 'number',
          description: 'Number of data points to return (default 100, max 1000)',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_get_categories',
    description:
      'Get list of market categories with the count of active markets in each. Use category IDs to filter markets in limitless_get_markets.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },

  // ============================================
  // TRADING (Phase 6.4)
  // ============================================
  {
    name: 'limitless_place_order',
    description:
      'Place a limit order on a Limitless prediction market. Requires market to be CLOB-enabled (not AMM). Check approvals first with limitless_check_approvals.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug (e.g., "will-btc-reach-100k-in-2025"). Get from limitless_get_markets or limitless_search_markets.',
        },
        tokenId: {
          type: 'string',
          description: 'Token ID to trade (YES or NO outcome). Get from limitless_get_market venue tokens.',
        },
        side: {
          type: 'string',
          enum: ['BUY', 'SELL'],
          description: 'BUY to purchase outcome shares, SELL to sell shares you own.',
        },
        price: {
          type: 'number',
          description: 'Limit price per share between 0.01 and 0.99 (e.g., 0.65 = 65 cents).',
        },
        size: {
          type: 'number',
          description: 'Number of shares (contracts) to buy/sell. Minimum $1 total (price * size >= 1).',
        },
        orderType: {
          type: 'string',
          enum: ['GTC', 'FOK', 'GTD', 'IOC'],
          description: 'GTC (Good Till Cancelled, default), FOK (Fill Or Kill), GTD (Good Till Date), IOC (Immediate Or Cancel).',
        },
        expirationSeconds: {
          type: 'number',
          description: 'For GTD orders: seconds from now until expiration. Ignored for other order types.',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only. Not needed for generated wallets.',
        },
      },
      required: ['marketSlug', 'tokenId', 'side', 'price', 'size'],
    },
  },
  {
    name: 'limitless_cancel_order',
    description:
      'Cancel a single open order. Get the order ID from limitless_get_orders. Filled orders cannot be cancelled.',
    inputSchema: {
      type: 'object',
      properties: {
        orderId: {
          type: 'string',
          description: 'The order ID to cancel (from limitless_get_orders).',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only.',
        },
      },
      required: ['orderId'],
    },
  },
  {
    name: 'limitless_cancel_all_orders',
    description:
      'Cancel all open orders in a specific market. Useful for clearing all positions before market close.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to cancel all orders in.',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only.',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_get_orders',
    description:
      'Get your open and historical orders for a specific market. Shows order status, fill amount, and prices.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to get orders for.',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_check_approvals',
    description:
      'Check if your wallet has the required token approvals to trade on a market. Must approve USDC and CTF (outcome tokens) before placing orders.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to check approvals for. Each market may have different venue contracts.',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_set_approvals',
    description:
      'Set token approvals to enable trading on a market. Approves USDC and CTF (outcome tokens) for the market venue. Costs ETH for gas.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to set approvals for.',
        },
        force: {
          type: 'boolean',
          description: 'If true, re-approve even if already approved. Default false.',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only.',
        },
      },
      required: ['marketSlug'],
    },
  },
  {
    name: 'limitless_get_locked_balance',
    description:
      'Get the amount of USDC locked in open orders. This shows funds that are reserved for pending orders and not available for new trades.',
    inputSchema: {
      type: 'object',
      properties: {
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_get_quote',
    description:
      'Estimate the fill price and cost for an order before placing it. Shows expected price impact based on current orderbook.',
    inputSchema: {
      type: 'object',
      properties: {
        marketSlug: {
          type: 'string',
          description: 'Market slug to get quote for.',
        },
        tokenId: {
          type: 'string',
          description: 'Token ID (YES or NO outcome).',
        },
        side: {
          type: 'string',
          enum: ['BUY', 'SELL'],
          description: 'BUY or SELL.',
        },
        size: {
          type: 'number',
          description: 'Number of shares to get quote for.',
        },
      },
      required: ['marketSlug', 'tokenId', 'side', 'size'],
    },
  },

  // ============================================
  // POSITIONS (Phase 6.5)
  // ============================================
  {
    name: 'limitless_get_positions',
    description:
      'Get your active prediction market positions. Shows all markets where you hold YES or NO shares, including entry prices, current values, and P&L.',
    inputSchema: {
      type: 'object',
      properties: {
        includeSettled: {
          type: 'boolean',
          description: 'Include positions in resolved/settled markets. Default false (only active positions).',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_get_trades',
    description:
      'Get your trade history showing all executed trades. Includes buy/sell, prices, sizes, fees, and P&L for each trade.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of trades to return (default 50, max 200).',
        },
        offset: {
          type: 'number',
          description: 'Number of trades to skip for pagination (default 0).',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_get_portfolio_history',
    description:
      'Get your full portfolio activity history including trades, splits, merges, conversions, and settlements. More detailed than get_trades.',
    inputSchema: {
      type: 'object',
      properties: {
        page: {
          type: 'number',
          description: 'Page number for pagination (1-indexed, default 1).',
        },
        limit: {
          type: 'number',
          description: 'Items per page (default 50, max 100).',
        },
        from: {
          type: 'string',
          description: 'Start date filter in ISO 8601 format (e.g., "2024-01-01T00:00:00Z").',
        },
        to: {
          type: 'string',
          description: 'End date filter in ISO 8601 format (e.g., "2024-12-31T23:59:59Z").',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_sync_positions',
    description:
      'Sync your positions from the Limitless API to the local database. Use this to refresh position data and ensure P&L calculations are accurate.',
    inputSchema: {
      type: 'object',
      properties: {
        password: {
          type: 'string',
          description: 'Password for imported wallets only (needed for session auth).',
        },
      },
      required: [],
    },
  },

  // ============================================
  // ON-CHAIN POSITION TRACKING (Phase 6.5b)
  // ============================================
  {
    name: 'limitless_get_onchain_shares',
    description:
      'Scan the Base blockchain directly for ERC-1155 outcome tokens held by your wallet. Finds ALL shares including those NOT tracked by the Limitless API (e.g., from CLOB fills or transfers). Maps each token to its market name and outcome (YES/NO). Use this when get_positions returns empty but you know you have positions.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_check_token_balance',
    description:
      'Check the on-chain balance of a specific ERC-1155 token ID on Base. Returns the exact balance and maps it to the corresponding market. Use this to verify a specific position exists on-chain.',
    inputSchema: {
      type: 'object',
      properties: {
        tokenId: {
          type: 'string',
          description: 'The ERC-1155 token ID to check balance for',
        },
      },
      required: ['tokenId'],
    },
  },
  {
    name: 'limitless_get_public_positions',
    description:
      'Get positions for any wallet address using the public Limitless API (no authentication required). Useful as a fallback when session-based position queries return empty, or to check any address.',
    inputSchema: {
      type: 'object',
      properties: {
        walletAddress: {
          type: 'string',
          description: 'Base/Ethereum wallet address (0x...) to check. If not provided, uses your own wallet address.',
        },
      },
      required: [],
    },
  },

  // ============================================
  // TRANSFERS (Phase 6.6)
  // ============================================
  {
    name: 'limitless_send_eth',
    description:
      'Send ETH to another address on Base. Use this to transfer ETH for gas or withdraw to an external wallet. Transaction requires ETH for gas fees.',
    inputSchema: {
      type: 'object',
      properties: {
        toAddress: {
          type: 'string',
          description: 'Destination Base/Ethereum address (0x...)',
        },
        amount: {
          type: 'number',
          description: 'Amount of ETH to send (e.g., 0.01 for 0.01 ETH)',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only',
        },
      },
      required: ['toAddress', 'amount'],
    },
  },
  {
    name: 'limitless_send_usdc',
    description:
      'Send USDC to another address on Base. Use this to transfer USDC or withdraw to an external wallet. Requires ETH for gas fees.',
    inputSchema: {
      type: 'object',
      properties: {
        toAddress: {
          type: 'string',
          description: 'Destination Base/Ethereum address (0x...)',
        },
        amount: {
          type: 'number',
          description: 'Amount of USDC to send (e.g., 10 for $10)',
        },
        password: {
          type: 'string',
          description: 'Password for imported wallets only',
        },
      },
      required: ['toAddress', 'amount'],
    },
  },
  {
    name: 'limitless_export_private_key',
    description:
      'Export your wallet private key for backup. WARNING: Anyone with this key controls your wallet. Handle with extreme care and never share it.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },

  // ============================================
  // API KEY MANAGEMENT (Phase 6.7)
  // ============================================
  {
    name: 'limitless_list_api_keys',
    description:
      'List all your API keys without exposing the actual keys. Shows key ID, name, status, creation date, and last used timestamp for each key.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'limitless_create_api_key',
    description:
      'Create a new API key for your account. Useful for separate integrations or rotating keys. The new key and secret are only shown once at creation.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Optional friendly name for this API key (e.g., "Production Bot", "Testing")',
        },
      },
      required: [],
    },
  },
  {
    name: 'limitless_revoke_api_key',
    description:
      'Revoke an API key to permanently disable it. Useful for security rotation or when a key is compromised. Cannot be undone.',
    inputSchema: {
      type: 'object',
      properties: {
        keyId: {
          type: 'string',
          description: 'The ID of the API key to revoke (get from limitless_list_api_keys)',
        },
      },
      required: ['keyId'],
    },
  },
];

/**
 * List of tools that don't require authentication
 * All other tools require a valid API key in the x-api-key header
 */
export const unauthenticatedTools = [
  'limitless_signup',
  'limitless_get_wallet_import_instructions',
  'limitless_import_private_key',
  // Market discovery tools - public data, no auth required
  'limitless_get_markets',
  'limitless_search_markets',
  'limitless_get_market',
  'limitless_get_orderbook',
  'limitless_get_price_history',
  'limitless_get_categories',
];

/**
 * Execute a tool with context
 *
 * @param name - Tool name
 * @param args - Tool arguments from MCP request
 * @param context - Execution context with optional userId
 * @returns Tool execution result
 */
export async function executeTool(
  name: string,
  args: Record<string, unknown>,
  context: ToolContext
): Promise<unknown> {
  const prisma = getPrismaClient();
  const { userId } = context;

  // ============================================
  // UNAUTHENTICATED TOOLS
  // ============================================

  if (name === 'limitless_signup') {
    const { externalId, keyName } = args as {
      externalId: string;
      keyName?: string;
    };

    if (!externalId) {
      throw new Error('externalId is required');
    }

    // Check if user already exists (direct users have platformId: null)
    const existingUser = await prisma.user.findFirst({
      where: { externalId, platformId: null },
    });

    if (existingUser) {
      throw new Error(
        'User with this externalId already exists. Use limitless_request_api_key to get a new key, or use a different externalId.'
      );
    }

    // Use UserService to handle full signup flow
    const userService = getUserService();
    const result = await userService.signup(externalId, null, keyName || 'Default Key');

    // Log the activity
    await userService.logActivity(result.userId, 'signup', 'user', result.userId, {
      externalId,
      walletAddress: result.wallet?.address,
    });

    return {
      message: 'Account created successfully. Save your API key and secret - they cannot be recovered!',
      apiKey: result.apiKey,
      apiSecret: result.apiSecret,
      walletAddress: result.wallet?.address,
      walletType: result.wallet?.type,
      network: result.wallet?.network,
      chainId: result.wallet?.chainId,
      nextSteps: {
        mcp: {
          description: 'Add this to your MCP config:',
          config: {
            quantish_limitless: {
              url: 'https://limitless-mcp-production.up.railway.app/mcp',
              headers: {
                'x-api-key': result.apiKey,
              },
            },
          },
        },
        funding: {
          description: 'Fund your wallet with ETH (for gas) and USDC (for trading)',
          address: result.wallet?.address,
          network: 'Base (chainId 8453)',
        },
      },
    };
  }

  if (name === 'limitless_get_wallet_import_instructions') {
    return {
      instructions: {
        overview:
          'To import your wallet, you must encrypt your private key client-side. We never see your raw private key.',
        steps: [
          '1. Export your private key from MetaMask, Rainbow, or other wallet',
          '2. Run the encryption script below on YOUR machine (not on our servers)',
          '3. Call limitless_import_wallet with the encrypted bundle',
          '4. Your password is required for each transaction',
        ],
      },
      encryptionExample: `
// Run this in Node.js on YOUR machine (not on our servers)
const crypto = require('crypto');

function encryptWallet(privateKeyHex, password) {
  // Generate random salt
  const salt = crypto.randomBytes(32);

  // Derive key from password using scrypt
  const key = crypto.scryptSync(password, salt, 32);

  // Generate random IV
  const iv = crypto.randomBytes(16);

  // Encrypt using AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(privateKeyHex, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Combine ciphertext + authTag
  const encryptedWithTag = Buffer.concat([encrypted, authTag]);

  return {
    encryptedKey: encryptedWithTag.toString('hex'),
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    publicKey: 'YOUR_WALLET_ADDRESS_HERE',
    version: '1.0'
  };
}

// Usage:
const bundle = encryptWallet('0xYourPrivateKeyHere', 'YourSecurePassword');
console.log(JSON.stringify(bundle, null, 2));
`,
      securityNotes: [
        'Never share your raw private key with anyone',
        'The encryption happens on YOUR machine - we never see the raw key',
        'You will need your password for every transaction',
        'Store your password securely - we cannot recover it',
      ],
    };
  }

  if (name === 'limitless_import_private_key') {
    const { externalId, privateKey, keyName } = args as {
      externalId: string;
      privateKey: string;
      keyName?: string;
    };

    if (!externalId) {
      throw new Error('externalId is required');
    }

    if (!privateKey) {
      throw new Error('privateKey is required');
    }

    // Check if user already exists (direct users have platformId: null)
    const existingUser = await prisma.user.findFirst({
      where: { externalId, platformId: null },
    });

    if (existingUser) {
      throw new Error('User with this externalId already exists. Use a different externalId.');
    }

    // Create user first
    const userService = getUserService();
    const user = await userService.createUser({
      externalId,
      generateWallet: false, // We'll import the private key instead
    });

    // Import the private key
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.importPrivateKey(user.id, privateKey);

    // Create API key
    const apiKeyService = getApiKeyService();
    const keyResult = await apiKeyService.createApiKey(user.id, keyName || 'Imported Wallet');

    // Log the import
    await userService.logActivity(user.id, 'private_key_import', 'wallet', null, {
      walletAddress: walletInfo.address,
    });

    return {
      success: true,
      apiKey: keyResult.apiKey,
      apiSecret: keyResult.apiSecret,
      walletAddress: walletInfo.address,
      walletType: walletInfo.type,
      network: 'base',
      chainId: 8453,
      message: 'Private key imported successfully. Save your API key and secret - they cannot be recovered!',
    };
  }

  // ============================================
  // MARKET DISCOVERY TOOLS (Phase 6.3)
  // These are public - no authentication required
  // ============================================

  // limitless_get_markets - List active markets with optional category filter
  if (name === 'limitless_get_markets') {
    const { limit, page, category } = args as {
      limit?: number;
      page?: number;
      category?: string;
    };

    const client = getLimitlessClient();
    // Validate pagination with safe bounds (max 100 per page)
    const actualLimit = validatePaginationInt(limit, 20, { min: 1, max: 100 });
    // API uses 1-indexed pages (max 1000 pages)
    const actualPage = validatePaginationInt(page, 1, { min: 1, max: 1000 });

    // If category is specified, use the category endpoint
    let markets;
    if (category) {
      // Fetch from category-specific endpoint
      const response = await fetch(
        `${config.limitless.apiUrl}/markets/active/${encodeURIComponent(category)}?limit=${actualLimit}&page=${actualPage}`
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch markets for category ${category}: ${response.status}`);
      }
      const json = await response.json() as { data?: unknown[] };
      markets = 'data' in json && Array.isArray(json.data) ? json.data : json;
    } else {
      markets = await client.getActiveMarkets(actualLimit, actualPage);
    }

    // Transform markets to a more user-friendly format
    const formattedMarkets = (markets as Array<{
      id: number;
      title: string;
      slug?: string;
      description?: string;
      prices: number[];
      tradeType: 'amm' | 'clob';
      status: string;
      category?: string;
      volume?: number;
      venue?: { exchange: string; adapter: string | null };
      expirationTimestamp: number;
    }>).map((market) => ({
      id: market.id,
      title: market.title,
      slug: market.slug,
      description: market.description,
      prices: {
        yes: market.prices?.[0],
        no: market.prices?.[1],
      },
      tradeType: market.tradeType,
      status: market.status,
      category: market.category,
      volume: market.volume,
      hasClobVenue: !!market.venue?.exchange,
      expiresAt: market.expirationTimestamp
        ? new Date(market.expirationTimestamp).toISOString()
        : null,
    }));

    return {
      markets: formattedMarkets,
      pagination: {
        limit: actualLimit,
        page: actualPage,
        count: formattedMarkets.length,
        hasMore: formattedMarkets.length === actualLimit,
      },
      note: 'Use the slug to get detailed market info with limitless_get_market',
    };
  }

  // limitless_search_markets - Semantic search for markets
  if (name === 'limitless_search_markets') {
    const { query, limit } = args as {
      query: string;
      limit?: number;
    };

    if (!query || query.trim().length === 0) {
      throw new Error('Search query is required');
    }

    const client = getLimitlessClient();
    // Validate limit with safe bounds (max 50 for search)
    const actualLimit = validatePaginationInt(limit, 20, { min: 1, max: 50 });

    const markets = await client.searchMarkets(query.trim(), actualLimit);

    // Transform markets to a more user-friendly format
    const formattedMarkets = markets.map((market) => ({
      id: market.id,
      title: market.title,
      slug: market.slug,
      description: market.description,
      prices: {
        yes: market.prices?.[0],
        no: market.prices?.[1],
      },
      tradeType: market.tradeType,
      status: market.status,
      category: market.category,
      hasClobVenue: !!market.venue?.exchange,
    }));

    return {
      query: query.trim(),
      markets: formattedMarkets,
      count: formattedMarkets.length,
      note: 'Results are ranked by semantic similarity to your query',
    };
  }

  // limitless_get_market - Get detailed market info including venue
  if (name === 'limitless_get_market') {
    const { slug } = args as { slug: string };

    if (!slug) {
      throw new Error('Market slug is required');
    }

    const client = getLimitlessClient();
    const market = await client.getMarket(slug);

    // Build detailed response
    return {
      market: {
        id: market.id,
        title: market.title,
        slug: market.slug,
        description: market.description,
        status: market.status,
        tradeType: market.tradeType,
        marketType: market.marketType,
        category: market.category,
        prices: {
          yes: market.prices?.[0],
          no: market.prices?.[1],
        },
        tokens: market.tokens || [
          { id: market.yesTokenId, outcome: 'Yes' },
          { id: market.noTokenId, outcome: 'No' },
        ],
        collateralToken: market.collateralToken,
        volume: market.volume,
        liquidity: market.liquidity,
        expiresAt: market.expirationTimestamp
          ? new Date(market.expirationTimestamp * 1000).toISOString()
          : null,
      },
      venue: market.venue
        ? {
            exchange: market.venue.exchange,
            adapter: market.venue.adapter,
            canPlaceOrders: true,
            note: 'Use venue.exchange as verifyingContract for EIP-712 order signing',
          }
        : {
            canPlaceOrders: false,
            note: 'This is an AMM market - order placement not supported',
          },
      contractAddress: market.address,
      conditionId: market.conditionId,
    };
  }

  // limitless_get_orderbook - Get current orderbook for a market
  if (name === 'limitless_get_orderbook') {
    const { marketSlug } = args as { marketSlug: string };

    if (!marketSlug) {
      throw new Error('Market slug is required');
    }

    const client = getLimitlessClient();

    // First check if this is a CLOB market
    const isCLOB = await client.isClobMarket(marketSlug);
    if (!isCLOB) {
      return {
        marketSlug,
        error: 'This is an AMM market - no orderbook available',
        suggestion: 'AMM markets use automated pricing. Check market prices with limitless_get_market instead.',
      };
    }

    const orderbook = await client.getOrderbook(marketSlug);

    // Calculate summary statistics
    const bestBid = orderbook.bids?.[0]?.price || null;
    const bestAsk = orderbook.asks?.[0]?.price || null;
    const spread = bestBid !== null && bestAsk !== null ? bestAsk - bestBid : null;
    const bidDepth = orderbook.bids?.reduce((sum, b) => sum + (b.size || 0), 0) || 0;
    const askDepth = orderbook.asks?.reduce((sum, a) => sum + (a.size || 0), 0) || 0;

    return {
      marketSlug,
      summary: {
        bestBid,
        bestAsk,
        spread,
        spreadPercent: spread !== null && bestBid !== null ? (spread / bestBid) * 100 : null,
        bidDepth,
        askDepth,
        timestamp: orderbook.timestamp || Date.now(),
      },
      orderbook: {
        bids: orderbook.bids || [],
        asks: orderbook.asks || [],
      },
      note: 'Bids are buy orders (sorted high to low), asks are sell orders (sorted low to high)',
    };
  }

  // limitless_get_price_history - Get historical price data
  if (name === 'limitless_get_price_history') {
    const { marketSlug, interval, limit } = args as {
      marketSlug: string;
      interval?: string;
      limit?: number;
    };

    if (!marketSlug) {
      throw new Error('Market slug is required');
    }

    const client = getLimitlessClient();
    const actualInterval = interval || '1h';
    const actualLimit = Math.min(Math.max(1, limit || 100), 1000);

    const history = await client.getHistoricalPrice(marketSlug, actualInterval, actualLimit);

    // Format the response
    return {
      marketSlug,
      interval: actualInterval,
      dataPoints: history.length,
      history: history.map((point) => ({
        timestamp: point.timestamp,
        datetime: new Date(point.timestamp * 1000).toISOString(),
        yesPrice: point.yesPrice,
        noPrice: point.noPrice,
        volume: point.volume,
      })),
      summary: history.length > 0
        ? {
            firstTimestamp: new Date(history[0].timestamp * 1000).toISOString(),
            lastTimestamp: new Date(history[history.length - 1].timestamp * 1000).toISOString(),
            currentYesPrice: history[history.length - 1].yesPrice,
            currentNoPrice: history[history.length - 1].noPrice,
            priceChange: history[history.length - 1].yesPrice - history[0].yesPrice,
          }
        : null,
    };
  }

  // limitless_get_categories - Get market categories with counts
  if (name === 'limitless_get_categories') {
    // Fetch categories from the API
    const response = await fetch(`${config.limitless.apiUrl}/markets/categories/count`);

    if (!response.ok) {
      throw new Error(`Failed to fetch categories: ${response.status}`);
    }

    const categoriesData = await response.json() as {
      totalMarkets?: number;
      categories?: Array<{ id: string; name: string; count: number }>;
    };

    return {
      categories: categoriesData.categories || [],
      totalMarkets: categoriesData.totalMarkets || 0,
      note: 'Use the category id with limitless_get_markets to filter by category',
    };
  }

  // ============================================
  // AUTHENTICATED TOOLS
  // ============================================

  if (!userId) {
    throw new Error('Authentication required. Please provide a valid API key in the x-api-key header.');
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new Error('User not found');
  }

  // limitless_request_api_key - requires existing API key to validate HMAC signature
  if (name === 'limitless_request_api_key') {
    const { externalId, signature, timestamp, keyName } = args as {
      externalId: string;
      signature: string;
      timestamp: string;
      keyName?: string;
    };

    if (!externalId || !signature || !timestamp) {
      throw new Error('externalId, signature, and timestamp are required');
    }

    // Verify this is the user's externalId
    if (user.externalId !== externalId) {
      throw new Error('externalId does not match authenticated user');
    }

    // Use UserService to handle returning user API key request
    const userService = getUserService();
    const result = await userService.requestApiKeyForReturningUser(
      externalId,
      user.platformId,
      signature,
      timestamp,
      keyName
    );

    return {
      message: 'API key created successfully',
      apiKey: result.apiKey,
      apiSecret: result.apiSecret,
      keyPrefix: result.keyPrefix,
    };
  }

  // limitless_setup_wallet - generate new wallet for authenticated user
  if (name === 'limitless_setup_wallet') {
    const walletService = getBaseWalletService();
    const existingWallet = await walletService.getWalletInfo(userId);

    if (existingWallet) {
      return {
        message: 'Wallet already exists',
        wallet: {
          address: existingWallet.address,
          type: existingWallet.type,
          network: 'base',
          chainId: 8453,
        },
      };
    }

    const wallet = await walletService.generateWallet(userId);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'wallet_generated', 'wallet', null, {
      walletAddress: wallet.address,
    });

    return {
      message: 'Base wallet generated successfully',
      wallet: {
        address: wallet.address,
        type: wallet.type,
        network: 'base',
        chainId: 8453,
      },
      note: 'Your private key is encrypted and stored securely. Fund this address with ETH (for gas) and USDC (for trading) on Base.',
    };
  }

  // limitless_import_wallet - import encrypted wallet bundle
  if (name === 'limitless_import_wallet') {
    const { encryptedKey, salt, iv, publicKey, version } = args as {
      encryptedKey: string;
      salt: string;
      iv: string;
      publicKey: string;
      version?: string;
    };

    if (!encryptedKey || !salt || !iv || !publicKey) {
      throw new Error('encryptedKey, salt, iv, and publicKey are required');
    }

    const bundle: WalletImportBundle = {
      encryptedKey,
      salt,
      iv,
      publicKey,
      version: version || '1.0',
    };

    const walletService = getBaseWalletService();
    const wallet = await walletService.importWallet(userId, bundle);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'wallet_imported', 'wallet', null, {
      walletAddress: wallet.address,
    });

    return {
      message: 'Wallet imported successfully',
      wallet: {
        address: wallet.address,
        type: wallet.type,
        network: 'base',
        chainId: 8453,
      },
      note: 'You will need to provide your password each time you make a transaction.',
    };
  }

  // ============================================
  // WALLET INFO TOOLS (Phase 6.2)
  // ============================================

  // limitless_get_wallet_info - Get basic wallet information
  if (name === 'limitless_get_wallet_info') {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);

    if (!walletInfo) {
      return {
        hasWallet: false,
        message: 'No wallet configured. Use limitless_setup_wallet to generate a new wallet or limitless_import_wallet to import an existing one.',
      };
    }

    return {
      hasWallet: true,
      wallet: {
        address: walletInfo.address,
        type: walletInfo.type,
        createdAt: walletInfo.createdAt.toISOString(),
        network: 'base',
        chainId: 8453,
      },
    };
  }

  // limitless_get_wallet_status - Get comprehensive wallet status
  if (name === 'limitless_get_wallet_status') {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);

    if (!walletInfo) {
      return {
        hasWallet: false,
        accountStatus: user.status,
        message: 'No wallet configured. Use limitless_setup_wallet to generate a new wallet.',
      };
    }

    // Fetch balances
    let balances: { eth: string; usdc: string; ethRaw: bigint; usdcRaw: bigint } | null = null;
    let balanceError: string | null = null;

    try {
      balances = await walletService.getBalances(walletInfo.address);
    } catch (error) {
      balanceError = error instanceof Error ? error.message : 'Failed to fetch balances';
    }

    return {
      hasWallet: true,
      wallet: {
        address: walletInfo.address,
        type: walletInfo.type,
        createdAt: walletInfo.createdAt.toISOString(),
        network: 'base',
        chainId: 8453,
      },
      accountStatus: user.status,
      balances: balances
        ? {
            eth: balances.eth,
            usdc: balances.usdc,
            hasGas: parseFloat(balances.eth) > 0.0001, // Minimum ETH for gas
            canTrade: parseFloat(balances.usdc) >= 1, // Minimum $1 USDC
          }
        : null,
      balanceError: balanceError,
      readyToTrade:
        user.status === 'READY' &&
        balances !== null &&
        parseFloat(balances.eth) > 0.0001 &&
        parseFloat(balances.usdc) >= 1,
    };
  }

  // limitless_get_balances - Get ETH and USDC balances
  if (name === 'limitless_get_balances') {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);

    if (!walletInfo) {
      throw new Error('No wallet configured. Use limitless_setup_wallet to generate a wallet first.');
    }

    const balances = await walletService.getBalances(walletInfo.address);

    return {
      address: walletInfo.address,
      network: 'base',
      chainId: 8453,
      balances: {
        eth: {
          balance: balances.eth,
          symbol: 'ETH',
          description: 'Native gas token on Base',
          sufficient: parseFloat(balances.eth) > 0.0001,
        },
        usdc: {
          balance: balances.usdc,
          symbol: 'USDC',
          description: 'Trading collateral on Limitless Exchange',
          sufficient: parseFloat(balances.usdc) >= 1,
          contractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        },
      },
      recommendations: [
        parseFloat(balances.eth) < 0.0001 ? 'Deposit ETH for gas fees (at least 0.001 ETH recommended)' : null,
        parseFloat(balances.usdc) < 1 ? 'Deposit USDC for trading (minimum $1 per order)' : null,
      ].filter(Boolean),
    };
  }

  // limitless_get_deposit_address - Get address for funding the wallet
  if (name === 'limitless_get_deposit_address') {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);

    if (!walletInfo) {
      throw new Error('No wallet configured. Use limitless_setup_wallet to generate a wallet first.');
    }

    return {
      address: walletInfo.address,
      network: {
        name: 'Base',
        chainId: 8453,
        explorer: `https://basescan.org/address/${walletInfo.address}`,
      },
      supportedTokens: [
        {
          symbol: 'ETH',
          name: 'Ethereum',
          purpose: 'Gas fees for transactions',
          recommended: '0.01 ETH minimum',
        },
        {
          symbol: 'USDC',
          name: 'USD Coin',
          purpose: 'Trading collateral on Limitless',
          contractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          recommended: '$10+ for testing, $100+ for active trading',
        },
      ],
      importantNotes: [
        'ONLY send tokens on the BASE network (not Ethereum mainnet)',
        'ETH is needed for gas fees on every transaction',
        'USDC is used as collateral for trading on Limitless',
        'Double-check the network before sending - funds sent on wrong network may be lost',
      ],
    };
  }

  // ============================================
  // TRADING TOOLS (Phase 6.4)
  // ============================================

  // limitless_place_order - Place a limit order on a market
  if (name === 'limitless_place_order') {
    const { marketSlug, tokenId, side, price, size, orderType, expirationSeconds, password } = args as {
      marketSlug: string;
      tokenId: string;
      side: 'BUY' | 'SELL';
      price: number;
      size: number;
      orderType?: 'GTC' | 'FOK' | 'GTD' | 'IOC';
      expirationSeconds?: number;
      password?: string;
    };

    // Validate required fields
    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }
    if (!tokenId) {
      throw new Error('tokenId is required. Get token IDs from limitless_get_market.');
    }
    if (!side || !['BUY', 'SELL'].includes(side)) {
      throw new Error('side must be BUY or SELL');
    }

    // Validate price: must be between 0.01 and 0.99, finite, not NaN
    validatePositiveNumber(price, 'price', { min: 0.01, max: 0.99, maxDecimals: 4 });

    // Validate size: must be positive, finite, not NaN, reasonable upper bound
    validatePositiveNumber(size, 'size', { min: 0.001, max: 1000000 });

    // Validate minimum order size ($1) and maximum ($100,000)
    const orderValue = price * size;
    if (orderValue < 1) {
      throw new Error(`Order value ($${orderValue.toFixed(2)}) is below minimum ($1). Increase size or price.`);
    }
    if (orderValue > 100000) {
      throw new Error(`Order value ($${orderValue.toFixed(2)}) exceeds maximum ($100,000). Reduce size or price.`);
    }

    const orderService = getLimitlessOrderService();

    // Place the order
    const result = await orderService.placeOrder(
      userId,
      {
        marketSlug,
        tokenId,
        side,
        price,
        size,
        orderType,
        expirationSeconds,
      },
      password
    );

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'order_placed', 'order', result.id, {
      marketSlug,
      side,
      price,
      size,
      orderType: orderType || 'GTC',
    });

    return {
      success: true,
      order: {
        id: result.id,
        limitlessOrderId: result.limitlessOrderId,
        status: result.status,
        createdAt: result.createdAt.toISOString(),
      },
      details: {
        marketSlug,
        side,
        price,
        size,
        orderType: orderType || 'GTC',
        estimatedCost: side === 'BUY' ? `$${orderValue.toFixed(2)}` : undefined,
        estimatedProceeds: side === 'SELL' ? `$${orderValue.toFixed(2)}` : undefined,
      },
      note: 'Order placed successfully. Use limitless_get_orders to check status.',
    };
  }

  // limitless_cancel_order - Cancel a single order
  if (name === 'limitless_cancel_order') {
    const { orderId, password } = args as {
      orderId: string;
      password?: string;
    };

    if (!orderId) {
      throw new Error('orderId is required');
    }

    const client = getLimitlessClient();

    // Look up the order in our database - try local ID first, then Limitless order ID
    let dbOrder = await prisma.order.findUnique({
      where: { id: orderId },
    });

    // If not found by local ID, try finding by Limitless order ID
    if (!dbOrder) {
      dbOrder = await prisma.order.findFirst({
        where: { limitlessOrderId: orderId, userId },
      });
    }

    // Determine which ID to use for the Limitless API call
    const limitlessOrderId = dbOrder?.limitlessOrderId || orderId;

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Cancel the order
    await client.cancelOrder(sessionCookie, limitlessOrderId);

    // Update our database if we found the order
    if (dbOrder) {
      await prisma.order.update({
        where: { id: dbOrder.id },
        data: { status: 'CANCELLED' },
      });
    }

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'order_cancelled', 'order', orderId, {
      limitlessOrderId,
    });

    return {
      success: true,
      message: 'Order cancelled successfully',
      orderId,
      limitlessOrderId,
    };
  }

  // limitless_cancel_all_orders - Cancel all orders in a market
  if (name === 'limitless_cancel_all_orders') {
    const { marketSlug, password } = args as {
      marketSlug: string;
      password?: string;
    };

    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }

    const client = getLimitlessClient();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Cancel all orders in the market
    await client.cancelAllOrders(sessionCookie, marketSlug);

    // Update our database - mark all open orders as cancelled
    const updatedOrders = await prisma.order.updateMany({
      where: {
        userId,
        marketSlug,
        status: 'OPEN',
      },
      data: {
        status: 'CANCELLED',
      },
    });

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'orders_cancelled_all', 'order', null, {
      marketSlug,
      count: updatedOrders.count,
    });

    return {
      success: true,
      message: `Cancelled all open orders in market ${marketSlug}`,
      marketSlug,
      ordersAffected: updatedOrders.count,
    };
  }

  // limitless_get_orders - Get orders for a market
  if (name === 'limitless_get_orders') {
    const { marketSlug, password } = args as {
      marketSlug: string;
      password?: string;
    };

    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }

    const client = getLimitlessClient();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Get orders from Limitless API
    const orders = await client.getOrders(sessionCookie, marketSlug);

    // Also get our local orders for this market
    const localOrders = await prisma.order.findMany({
      where: {
        userId,
        marketSlug,
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    return {
      marketSlug,
      apiOrders: orders,
      localOrders: localOrders.map((o) => ({
        id: o.id,
        limitlessOrderId: o.limitlessOrderId,
        side: o.side,
        price: o.price,
        size: o.size,
        status: o.status,
        orderType: o.orderType,
        createdAt: o.createdAt.toISOString(),
      })),
      note: 'apiOrders are from Limitless API, localOrders are from our database.',
    };
  }

  // limitless_check_approvals - Check token approvals for a market
  if (name === 'limitless_check_approvals') {
    const { marketSlug } = args as { marketSlug: string };

    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }

    const approvalService = getLimitlessApprovalService();
    const status = await approvalService.checkApprovals(userId, marketSlug);

    return {
      marketSlug,
      venue: {
        exchange: status.venue.exchange,
        adapter: status.venue.adapter,
      },
      approvals: {
        usdc: {
          approved: status.usdcApproved,
          allowance: status.usdcAllowance,
          description: 'USDC approval for venue.exchange',
        },
        ctf: {
          approved: status.ctfApproved,
          description: 'CTF (outcome token) approval for venue.exchange',
        },
        ctfAdapter: status.isNegRisk
          ? {
              approved: status.ctfAdapterApproved,
              description: 'CTF approval for venue.adapter (NegRisk market)',
            }
          : null,
      },
      isNegRisk: status.isNegRisk,
      allApproved: status.allApproved,
      readyToTrade: status.allApproved,
      nextStep: status.allApproved
        ? 'All approvals in place. You can place orders with limitless_place_order.'
        : 'Run limitless_set_approvals to enable trading on this market.',
    };
  }

  // limitless_set_approvals - Set token approvals for a market
  if (name === 'limitless_set_approvals') {
    const { marketSlug, force, password } = args as {
      marketSlug: string;
      force?: boolean;
      password?: string;
    };

    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }

    const approvalService = getLimitlessApprovalService();

    // First check current status
    const currentStatus = await approvalService.checkApprovals(userId, marketSlug);

    // If all already approved and not forcing, return early
    if (currentStatus.allApproved && !force) {
      return {
        success: true,
        message: 'All approvals already in place. No transactions needed.',
        marketSlug,
        venue: currentStatus.venue,
        alreadyApproved: true,
      };
    }

    // Estimate gas cost before approving
    const estimatedGas = await approvalService.estimateApprovalGas(userId, marketSlug);

    // Set approvals
    const result = await approvalService.setApprovals(userId, marketSlug, force || false, password);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'approvals_set', 'wallet', null, {
      marketSlug,
      venue: currentStatus.venue.exchange,
      usdcApproval: result.usdcApproval?.success,
      ctfApproval: result.ctfApproval?.success,
      ctfAdapterApproval: result.ctfAdapterApproval?.success,
    });

    return {
      success: result.allSuccessful,
      marketSlug,
      venue: currentStatus.venue,
      approvalResults: {
        usdc: result.usdcApproval
          ? {
              success: result.usdcApproval.success,
              txHash: result.usdcApproval.txHash,
              gasUsed: result.usdcApproval.gasUsed,
              error: result.usdcApproval.error,
            }
          : { skipped: true, reason: 'Already approved' },
        ctf: result.ctfApproval
          ? {
              success: result.ctfApproval.success,
              txHash: result.ctfApproval.txHash,
              gasUsed: result.ctfApproval.gasUsed,
              error: result.ctfApproval.error,
            }
          : { skipped: true, reason: 'Already approved' },
        ctfAdapter:
          currentStatus.isNegRisk && result.ctfAdapterApproval
            ? {
                success: result.ctfAdapterApproval.success,
                txHash: result.ctfAdapterApproval.txHash,
                gasUsed: result.ctfAdapterApproval.gasUsed,
                error: result.ctfAdapterApproval.error,
              }
            : null,
      },
      estimatedGasCost: estimatedGas,
      note: result.allSuccessful
        ? 'All approvals set successfully. You can now place orders with limitless_place_order.'
        : 'Some approvals failed. Check the error messages above.',
    };
  }

  // limitless_get_locked_balance - Get USDC locked in open orders
  if (name === 'limitless_get_locked_balance') {
    const { password } = args as { password?: string };

    const client = getLimitlessClient();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Get positions which includes locked balance info
    const positions = await client.getPositionsRaw(sessionCookie);

    // Calculate total locked from all positions
    let totalLocked = 0;
    const lockedByMarket: Array<{ market: string; locked: number }> = [];

    // CLOB positions have orders with totalCollateralLocked
    for (const pos of positions.clob || []) {
      const locked = pos.orders?.totalCollateralLocked
        ? parseFloat(pos.orders.totalCollateralLocked)
        : 0;
      if (locked > 0) {
        totalLocked += locked;
        lockedByMarket.push({
          market: pos.market.slug,
          locked: locked / 1_000_000, // Convert from raw to USDC
        });
      }
    }

    // Get wallet info for available balance context
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);
    let availableBalance = '0';
    if (walletInfo) {
      const balances = await walletService.getBalances(walletInfo.address);
      availableBalance = balances.usdc;
    }

    return {
      lockedBalance: {
        total: totalLocked / 1_000_000, // Convert to USDC
        formatted: `$${(totalLocked / 1_000_000).toFixed(2)}`,
      },
      byMarket: lockedByMarket,
      availableBalance: {
        usdc: availableBalance,
        formatted: `$${parseFloat(availableBalance).toFixed(2)}`,
      },
      note: 'Locked balance is USDC reserved for open orders. Cancel orders to free up funds.',
    };
  }

  // limitless_get_quote - Get quote for an order
  if (name === 'limitless_get_quote') {
    const { marketSlug, tokenId, side, size } = args as {
      marketSlug: string;
      tokenId: string;
      side: 'BUY' | 'SELL';
      size: number;
    };

    if (!marketSlug) {
      throw new Error('marketSlug is required');
    }
    if (!tokenId) {
      throw new Error('tokenId is required');
    }
    if (!side || !['BUY', 'SELL'].includes(side)) {
      throw new Error('side must be BUY or SELL');
    }

    // Validate size: must be positive, finite, not NaN, reasonable upper bound
    validatePositiveNumber(size, 'size', { min: 0.001, max: 1000000 });

    const client = getLimitlessClient();

    // Get orderbook to calculate quote
    const orderbook = await client.getOrderbook(marketSlug);

    // Get market info for context
    const market = await client.getMarket(marketSlug);

    // Calculate fill price based on orderbook
    let filledSize = 0;
    let totalCost = 0;
    let orders: Array<{ price: number; size: number }> = [];

    // For BUY, we look at asks (sell orders)
    // For SELL, we look at bids (buy orders)
    const relevantOrders = side === 'BUY' ? orderbook.asks : orderbook.bids;

    // Sort orders appropriately
    // BUY: sort asks ascending (cheapest first)
    // SELL: sort bids descending (highest first)
    const sortedOrders = [...(relevantOrders || [])].sort((a, b) =>
      side === 'BUY' ? a.price - b.price : b.price - a.price
    );

    for (const order of sortedOrders) {
      if (filledSize >= size) break;

      const remainingSize = size - filledSize;
      const fillSize = Math.min(remainingSize, order.size);

      filledSize += fillSize;
      totalCost += fillSize * order.price;
      orders.push({ price: order.price, size: fillSize });
    }

    const avgPrice = filledSize > 0 ? totalCost / filledSize : 0;
    const canFillFully = filledSize >= size;

    // Calculate price impact
    const bestPrice = sortedOrders[0]?.price || 0;
    const priceImpact = bestPrice > 0 ? ((avgPrice - bestPrice) / bestPrice) * 100 : 0;

    return {
      marketSlug,
      tokenId,
      side,
      requestedSize: size,
      quote: {
        avgPrice: avgPrice,
        totalCost: side === 'BUY' ? totalCost : undefined,
        totalProceeds: side === 'SELL' ? totalCost : undefined,
        canFillFully,
        filledSize,
        unfillableSize: size - filledSize,
        priceImpact: Math.abs(priceImpact).toFixed(2) + '%',
        fillDetails: orders,
      },
      orderbook: {
        bestBid: orderbook.bids?.[0]?.price || null,
        bestAsk: orderbook.asks?.[0]?.price || null,
        spread:
          orderbook.bids?.[0]?.price && orderbook.asks?.[0]?.price
            ? orderbook.asks[0].price - orderbook.bids[0].price
            : null,
      },
      market: {
        title: market.title,
        currentPrice: market.prices?.[0],
      },
      note: canFillFully
        ? `Order can be filled at average price of ${avgPrice.toFixed(4)}`
        : `Only ${filledSize} of ${size} shares available in orderbook`,
    };
  }

  // ============================================
  // POSITION TOOLS (Phase 6.5)
  // ============================================

  // limitless_get_positions - Get active positions
  if (name === 'limitless_get_positions') {
    const { includeSettled, password } = args as {
      includeSettled?: boolean;
      password?: string;
    };

    const client = getLimitlessClient();
    const portfolioService = getPortfolioService();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Get positions from API in unified format
    const { positions, summary } = await portfolioService.getUnifiedPositions(sessionCookie);

    // Filter out settled positions if not requested
    const filteredPositions = includeSettled
      ? positions
      : positions.filter((p) => !p.isSettled);

    // Format for response
    const formattedPositions = filteredPositions.map((pos) => ({
      id: pos.id,
      market: {
        slug: pos.marketSlug,
        title: pos.marketTitle,
      },
      outcome: pos.outcomeSide,
      shares: pos.balance,
      entry: {
        avgPrice: pos.avgEntryPrice,
        totalInvested: pos.totalInvested,
      },
      current: {
        price: pos.currentPrice,
        value: pos.currentValue,
      },
      pnl: {
        unrealized: pos.unrealizedPnl,
        unrealizedPercent:
          parseFloat(pos.totalInvested) > 0
            ? ((parseFloat(pos.unrealizedPnl) / parseFloat(pos.totalInvested)) * 100).toFixed(2) + '%'
            : '0%',
        realized: pos.realizedPnl,
      },
      tradeType: pos.tradeType,
      isSettled: pos.isSettled,
      lastUpdated: pos.lastUpdated.toISOString(),
    }));

    // If API returned positions, return them
    if (formattedPositions.length > 0) {
      return {
        positions: formattedPositions,
        summary: {
          totalPositions: filteredPositions.length,
          totalValue: `$${parseFloat(summary.totalValue).toFixed(2)}`,
          totalInvested: `$${parseFloat(summary.totalInvested).toFixed(2)}`,
          unrealizedPnl: `$${parseFloat(summary.totalUnrealizedPnl).toFixed(2)}`,
          realizedPnl: `$${parseFloat(summary.totalRealizedPnl).toFixed(2)}`,
          activeMarkets: summary.activeMarkets,
        },
        filters: {
          includeSettled: includeSettled || false,
        },
        source: 'api',
        note: 'Positions reflect current market prices. Use limitless_sync_positions to refresh.',
      };
    }

    // Fallback 1: Try public API (fast, no blockchain needed)
    try {
      const walletService = getBaseWalletService();
      const walletInfo = await walletService.getWalletInfo(userId);

      if (walletInfo) {
        const pubPositions = await portfolioService.getPublicPositions(walletInfo.address);

        if (pubPositions) {
          const allPubPositions: Array<{
            id: string;
            market: { slug: string; title: string };
            outcome: string;
            shares: string;
            entry: { avgPrice: string; totalInvested: string };
            current: { price: string; value: string };
            pnl: { unrealized: string; unrealizedPercent: string; realized: string };
            tradeType: string;
            isSettled: boolean;
          }> = [];

          // Map CLOB positions (tokensBalance and positions data are in raw units with 6 decimals)
          for (const pos of pubPositions.clob || []) {
            const yesBalanceRaw = parseFloat(pos.tokensBalance?.yes || '0');
            const noBalanceRaw = parseFloat(pos.tokensBalance?.no || '0');
            const yesBalance = yesBalanceRaw / 1e6;
            const noBalance = noBalanceRaw / 1e6;
            const yesData = (pos as any).positions?.yes;
            const noData = (pos as any).positions?.no;
            const latestTrade = (pos as any).latestTrade;

            if (yesBalance > 0) {
              const fillPrice = yesData?.fillPrice ? (parseFloat(yesData.fillPrice) / 1e6) : undefined;
              const cost = yesData?.cost ? (parseFloat(yesData.cost) / 1e6) : undefined;
              const marketValue = yesData?.marketValue ? (parseFloat(yesData.marketValue) / 1e6) : undefined;
              const currentPrice = latestTrade?.latestYesPrice || fillPrice;

              allPubPositions.push({
                id: `${pos.market.slug}-yes`,
                market: { slug: pos.market.slug, title: pos.market.title },
                outcome: 'YES',
                shares: yesBalance.toFixed(6),
                entry: {
                  avgPrice: fillPrice ? `$${fillPrice.toFixed(4)}` : 'unknown',
                  totalInvested: cost ? `$${cost.toFixed(4)}` : 'unknown',
                },
                current: {
                  price: currentPrice ? `$${currentPrice.toFixed(4)}` : 'unknown',
                  value: marketValue ? `$${marketValue.toFixed(4)}` : (currentPrice ? `$${(yesBalance * currentPrice).toFixed(4)}` : 'unknown'),
                },
                pnl: {
                  unrealized: (marketValue && cost) ? `$${(marketValue - cost).toFixed(4)}` : 'unknown',
                  unrealizedPercent: (marketValue && cost && cost > 0) ? `${(((marketValue - cost) / cost) * 100).toFixed(2)}%` : 'unknown',
                  realized: yesData?.realisedPnl ? `$${(parseFloat(yesData.realisedPnl) / 1e6).toFixed(4)}` : '$0',
                },
                tradeType: 'clob',
                isSettled: pos.market.status === 'resolved',
              });
            }
            if (noBalance > 0) {
              const fillPrice = noData?.fillPrice ? (parseFloat(noData.fillPrice) / 1e6) : undefined;
              const cost = noData?.cost ? (parseFloat(noData.cost) / 1e6) : undefined;
              const marketValue = noData?.marketValue ? (parseFloat(noData.marketValue) / 1e6) : undefined;
              const currentPrice = latestTrade?.latestNoPrice || fillPrice;

              allPubPositions.push({
                id: `${pos.market.slug}-no`,
                market: { slug: pos.market.slug, title: pos.market.title },
                outcome: 'NO',
                shares: noBalance.toFixed(6),
                entry: {
                  avgPrice: fillPrice ? `$${fillPrice.toFixed(4)}` : 'unknown',
                  totalInvested: cost ? `$${cost.toFixed(4)}` : 'unknown',
                },
                current: {
                  price: currentPrice ? `$${currentPrice.toFixed(4)}` : 'unknown',
                  value: marketValue ? `$${marketValue.toFixed(4)}` : (currentPrice ? `$${(noBalance * currentPrice).toFixed(4)}` : 'unknown'),
                },
                pnl: {
                  unrealized: (marketValue && cost) ? `$${(marketValue - cost).toFixed(4)}` : 'unknown',
                  unrealizedPercent: (marketValue && cost && cost > 0) ? `${(((marketValue - cost) / cost) * 100).toFixed(2)}%` : 'unknown',
                  realized: noData?.realisedPnl ? `$${(parseFloat(noData.realisedPnl) / 1e6).toFixed(4)}` : '$0',
                },
                tradeType: 'clob',
                isSettled: pos.market.status === 'resolved',
              });
            }
          }

          // Map AMM positions
          for (const pos of pubPositions.amm || []) {
            const amount = parseFloat(pos.outcomeTokenAmount || '0');
            if (amount > 0) {
              allPubPositions.push({
                id: `${pos.market.slug}-amm`,
                market: { slug: pos.market.slug, title: pos.market.title },
                outcome: pos.outcomeIndex === 0 ? 'YES' : 'NO',
                shares: amount.toFixed(6),
                entry: { avgPrice: pos.averageFillPrice || 'unknown', totalInvested: 'unknown' },
                current: { price: 'unknown', value: 'unknown' },
                pnl: { unrealized: pos.unrealizedPnl || 'unknown', unrealizedPercent: 'unknown', realized: 'unknown' },
                tradeType: 'amm',
                isSettled: pos.market.status === 'resolved',
              });
            }
          }

          if (allPubPositions.length > 0) {
            return {
              positions: allPubPositions,
              summary: {
                totalPositions: allPubPositions.length,
                totalValue: 'unknown',
                totalInvested: 'unknown',
                unrealizedPnl: 'unknown',
                realizedPnl: 'unknown',
                activeMarkets: new Set(allPubPositions.map((p) => p.market.slug)).size,
              },
              filters: { includeSettled: includeSettled || false },
              source: 'public-api',
              note: 'Positions retrieved from public API (no session auth). Entry prices may be limited.',
            };
          }
        }
      }
    } catch (pubError) {
      console.error('Public API fallback failed:', pubError);
    }

    // Fallback 2: Try on-chain shares (slowest, but most reliable)
    try {
      const onChainResult = await portfolioService.getOnChainShares(userId);

      if (onChainResult.shares.length > 0) {
        const onChainPositions = onChainResult.shares
          .filter((s) => s.balanceFormatted > 0)
          .map((s) => ({
            id: s.tokenId,
            market: {
              slug: s.market?.slug || 'unknown',
              title: s.market?.title || `Token ${s.tokenId.slice(0, 8)}...`,
            },
            outcome: s.market?.outcome || 'unknown',
            shares: s.balanceFormatted.toString(),
            entry: { avgPrice: 'unknown', totalInvested: 'unknown' },
            current: {
              price: s.market?.currentPrice?.toString() || 'unknown',
              value: s.market?.currentPrice
                ? `$${(s.balanceFormatted * s.market.currentPrice).toFixed(4)}`
                : 'unknown',
            },
            pnl: { unrealized: 'unknown', unrealizedPercent: 'unknown', realized: 'unknown' },
            tradeType: 'on-chain',
            isSettled: s.market?.status === 'resolved',
          }));

        const totalValue = onChainResult.shares.reduce((sum, s) => {
          return sum + (s.balanceFormatted * (s.market?.currentPrice || 0));
        }, 0);

        return {
          positions: onChainPositions,
          summary: {
            totalPositions: onChainPositions.length,
            totalValue: `$${totalValue.toFixed(2)}`,
            totalInvested: 'unknown',
            unrealizedPnl: 'unknown',
            realizedPnl: 'unknown',
            activeMarkets: new Set(onChainPositions.map((p) => p.market.slug)).size,
          },
          filters: { includeSettled: includeSettled || false },
          source: 'on-chain',
          note: 'Positions retrieved from on-chain data. Entry prices unavailable.',
        };
      }
    } catch (onChainError) {
      console.error('On-chain fallback failed:', onChainError);
    }

    return {
      positions: [],
      summary: {
        totalPositions: 0,
        totalValue: '$0.00',
        totalInvested: '$0.00',
        unrealizedPnl: '$0.00',
        realizedPnl: '$0.00',
        activeMarkets: 0,
      },
      filters: {
        includeSettled: includeSettled || false,
      },
      source: 'none',
      note: 'No positions found. Place orders with limitless_place_order to open positions.',
    };
  }

  // limitless_get_trades - Get trade history
  if (name === 'limitless_get_trades') {
    const { limit, offset, password } = args as {
      limit?: number;
      offset?: number;
      password?: string;
    };

    const client = getLimitlessClient();
    const portfolioService = getPortfolioService();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Validate pagination with safe bounds
    const actualLimit = validatePaginationInt(limit, 50, { min: 1, max: 200 });
    const actualOffset = validatePaginationInt(offset, 0, { min: 0, max: 10000 });

    const { trades, pagination } = await portfolioService.getTrades(
      sessionCookie,
      actualLimit,
      actualOffset
    );

    // Format trades for response
    const formattedTrades = trades.map((trade) => ({
      id: trade.id,
      market: {
        slug: trade.marketSlug,
        title: trade.marketTitle,
      },
      side: trade.side,
      outcome: trade.outcomeIndex === 0 ? 'YES' : 'NO',
      price: trade.price,
      size: trade.size,
      total: trade.total,
      fee: trade.fee,
      pnl: trade.pnl,
      type: trade.type, // OPEN or CLOSE
      tradeType: trade.tradeType, // amm or clob
      txHash: trade.txHash,
      timestamp: trade.timestamp,
      datetime: new Date(trade.timestamp * 1000).toISOString(),
    }));

    // Calculate summary statistics
    const totalBuys = formattedTrades.filter((t) => t.side === 'BUY').length;
    const totalSells = formattedTrades.filter((t) => t.side === 'SELL').length;
    const totalFees = trades.reduce((sum, t) => sum + parseFloat(t.fee || '0'), 0);
    const totalPnl = trades.reduce((sum, t) => sum + parseFloat(t.pnl || '0'), 0);

    return {
      trades: formattedTrades,
      pagination: {
        limit: actualLimit,
        offset: actualOffset,
        returned: formattedTrades.length,
        hasMore: pagination?.hasMore ?? formattedTrades.length === actualLimit,
        total: pagination?.total,
      },
      summary: {
        tradesReturned: formattedTrades.length,
        buys: totalBuys,
        sells: totalSells,
        totalFees: `$${totalFees.toFixed(4)}`,
        totalPnl: `$${totalPnl.toFixed(4)}`,
      },
      note: formattedTrades.length === 0
        ? 'No trades found. Place orders with limitless_place_order.'
        : 'Trade history sorted by most recent first.',
    };
  }

  // limitless_get_portfolio_history - Get full portfolio history
  if (name === 'limitless_get_portfolio_history') {
    const { page, limit, from, to, password } = args as {
      page?: number;
      limit?: number;
      from?: string;
      to?: string;
      password?: string;
    };

    const client = getLimitlessClient();
    const portfolioService = getPortfolioService();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Validate pagination with safe bounds
    const actualPage = validatePaginationInt(page, 1, { min: 1, max: 1000 });
    const actualLimit = validatePaginationInt(limit, 50, { min: 1, max: 100 });

    // Get portfolio history from API
    const { history, pagination } = await portfolioService.getPortfolioHistory(
      sessionCookie,
      actualPage,
      actualLimit,
      from,
      to
    );

    // Format history items for response
    const formattedHistory = history.map((item) => ({
      type: item.type,
      market: {
        slug: item.marketSlug,
        title: item.marketTitle,
      },
      details: {
        side: item.details.side,
        outcome: item.details.outcomeIndex !== undefined
          ? item.details.outcomeIndex === 0 ? 'YES' : 'NO'
          : undefined,
        amount: item.details.amount,
        price: item.details.price,
        pnl: item.details.pnl,
        txHash: item.details.txHash,
      },
      timestamp: item.timestamp,
      datetime: new Date(item.timestamp * 1000).toISOString(),
    }));

    // Count activity types
    const typeCounts = formattedHistory.reduce((acc, item) => {
      acc[item.type] = (acc[item.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      history: formattedHistory,
      pagination: {
        page: actualPage,
        limit: actualLimit,
        returned: formattedHistory.length,
        total: pagination.total,
        hasMore: pagination.hasMore,
      },
      filters: {
        from: from || null,
        to: to || null,
      },
      summary: {
        activityTypes: typeCounts,
        totalItems: formattedHistory.length,
      },
      note: formattedHistory.length === 0
        ? 'No portfolio activity found for the specified period.'
        : 'Activity includes trades, splits, merges, conversions, and settlements.',
    };
  }

  // limitless_sync_positions - Sync positions from API to local database
  if (name === 'limitless_sync_positions') {
    const { password } = args as { password?: string };

    const client = getLimitlessClient();
    const portfolioService = getPortfolioService();

    // Get session for authenticated request
    const sessionCookie = await client.getSession(userId, password);

    // Sync positions to local database
    const syncedCount = await portfolioService.syncPositions(userId, sessionCookie);

    // Get stored positions after sync
    const storedPositions = await portfolioService.getStoredPositions(userId, true);

    // Calculate portfolio value from synced data
    const portfolioValue = await portfolioService.calculatePortfolioValue(userId);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'positions_synced', 'portfolio', null, {
      syncedCount,
      totalPositions: storedPositions.length,
    });

    return {
      success: true,
      message: `Synced ${syncedCount} positions from Limitless API`,
      syncedPositions: syncedCount,
      totalActivePositions: storedPositions.length,
      portfolioValue: {
        totalValue: `$${parseFloat(portfolioValue.totalValue).toFixed(2)}`,
        totalInvested: `$${parseFloat(portfolioValue.totalInvested).toFixed(2)}`,
        unrealizedPnl: `$${parseFloat(portfolioValue.totalUnrealizedPnl).toFixed(2)}`,
        realizedPnl: `$${parseFloat(portfolioValue.totalRealizedPnl).toFixed(2)}`,
        activeMarkets: portfolioValue.activeMarkets,
      },
      positions: storedPositions.map((pos) => ({
        market: pos.marketSlug,
        outcome: pos.outcomeSide,
        balance: pos.balance.toString(),
        avgEntryPrice: pos.avgEntryPrice?.toString() || '0',
        currentPrice: pos.currentPrice?.toString() || 'unknown',
        unrealizedPnl: pos.unrealizedPnl.toString(),
        isOpen: pos.isOpen,
        lastUpdated: pos.updatedAt.toISOString(),
      })),
      note: 'Positions synced to local database for faster access. P&L calculations use live market prices.',
    };
  }

  // ============================================
  // ON-CHAIN POSITION TRACKING (Phase 6.5b)
  // ============================================

  // limitless_get_onchain_shares - Scan blockchain for ERC-1155 tokens
  if (name === 'limitless_get_onchain_shares') {
    const portfolioService = getPortfolioService();

    const result = await portfolioService.getOnChainShares(userId);

    return {
      walletAddress: result.walletAddress,
      shares: result.shares.map((s) => ({
        tokenId: s.tokenId,
        balance: s.balanceFormatted,
        balanceRaw: s.balance,
        market: s.market
          ? {
              slug: s.market.slug,
              title: s.market.title,
              outcome: s.market.outcome,
              currentPrice: s.market.currentPrice,
              status: s.market.status,
            }
          : { note: 'Could not identify market for this token. Use the tokenId to investigate.' },
        trackedByApi: s.inApiPositions,
      })),
      summary: {
        totalTokenTypes: result.totalShares,
        trackedByApi: result.shares.filter((s) => s.inApiPositions).length,
        notTrackedByApi: result.shares.filter((s) => !s.inApiPositions).length,
      },
      contract: config.contracts.CTF,
      chain: 'Base (chainId 8453)',
      note: result.note,
    };
  }

  // limitless_check_token_balance - Check balance of specific token ID
  if (name === 'limitless_check_token_balance') {
    const { tokenId } = args as { tokenId: string };

    if (!tokenId) {
      throw new Error('tokenId is required');
    }

    const portfolioService = getPortfolioService();
    const result = await portfolioService.checkTokenBalance(userId, tokenId);

    return {
      walletAddress: result.walletAddress,
      tokenId: result.tokenId,
      balance: result.balanceFormatted,
      balanceRaw: result.balance,
      hasBalance: result.balanceFormatted > 0,
      market: result.market
        ? {
            slug: result.market.slug,
            title: result.market.title,
            outcome: result.market.outcome,
            currentPrice: result.market.currentPrice,
            status: result.market.status,
            estimatedValue: result.market.currentPrice
              ? `$${(result.balanceFormatted * result.market.currentPrice).toFixed(4)}`
              : 'unknown',
          }
        : null,
      contract: config.contracts.CTF,
      note: result.balanceFormatted > 0
        ? `Found ${result.balanceFormatted} shares on-chain.`
        : 'No balance found for this token ID.',
    };
  }

  // limitless_get_public_positions - Get positions via public API (no auth)
  if (name === 'limitless_get_public_positions') {
    const { walletAddress: inputAddress } = args as { walletAddress?: string };

    const portfolioService = getPortfolioService();
    let address = inputAddress;

    // If no address provided, use the user's own wallet
    if (!address) {
      const walletService = getBaseWalletService();
      const walletInfo = await walletService.getWalletInfo(userId);
      if (!walletInfo) {
        throw new Error('No wallet found and no walletAddress provided.');
      }
      address = walletInfo.address;
    }

    const positions = await portfolioService.getPublicPositions(address);

    if (!positions) {
      return {
        walletAddress: address,
        positions: { amm: [], clob: [], group: [] },
        note: 'Public positions API returned no data. Try limitless_get_onchain_shares for on-chain verification.',
      };
    }

    // Format the response
    const clobCount = positions.clob?.length || 0;
    const ammCount = positions.amm?.length || 0;
    const groupCount = positions.group?.length || 0;
    const totalPositions = clobCount + ammCount + groupCount;

    return {
      walletAddress: address,
      positions: {
        clob: (positions.clob || []).map((p) => ({
          market: { slug: p.market.slug, title: p.market.title, status: p.market.status },
          tokensBalance: p.tokensBalance,
          positions: p.positions,
          liveOrders: p.orders?.liveOrders?.length || 0,
        })),
        amm: (positions.amm || []).map((p) => ({
          market: { slug: p.market.slug, title: p.market.title, status: p.market.status },
          outcome: p.outcomeIndex === 0 ? 'YES' : 'NO',
          tokenAmount: p.outcomeTokenAmount,
          avgFillPrice: p.averageFillPrice,
          unrealizedPnl: p.unrealizedPnl,
        })),
        group: (positions.group || []).map((p) => ({
          market: { slug: p.market.slug, title: p.market.title, status: p.market.status },
          positions: p.positions,
        })),
      },
      summary: {
        totalPositions,
        clobPositions: clobCount,
        ammPositions: ammCount,
        groupPositions: groupCount,
      },
      note: totalPositions === 0
        ? 'No positions found via public API. Try limitless_get_onchain_shares for on-chain verification.'
        : `Found ${totalPositions} positions via public API (no authentication required).`,
    };
  }

  // ============================================
  // TRANSFER TOOLS (Phase 6.6)
  // ============================================

  // limitless_send_eth - Send ETH to another address
  if (name === 'limitless_send_eth') {
    const { toAddress, amount, password } = args as {
      toAddress: string;
      amount: number;
      password?: string;
    };

    if (!toAddress) {
      throw new Error('toAddress is required');
    }

    // Validate amount: positive, finite, not NaN, reasonable bounds (up to 1000 ETH)
    validatePositiveNumber(amount, 'amount', { min: 0.000001, max: 1000, maxDecimals: 18 });

    const walletService = getBaseWalletService();

    // Send ETH
    const result = await walletService.sendEth(userId, toAddress, amount, password);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'eth_sent', 'wallet', null, {
      toAddress,
      amount: amount.toString(),
      txHash: result.txHash,
    });

    return {
      success: true,
      message: `Sent ${amount} ETH to ${toAddress}`,
      transaction: {
        txHash: result.txHash,
        fromAddress: result.fromAddress,
        toAddress: result.toAddress,
        amount: `${result.amount} ETH`,
        gasUsed: result.gasUsed,
      },
      explorerUrl: result.explorerUrl,
      note: 'Transaction confirmed on Base. View on BaseScan for details.',
    };
  }

  // limitless_send_usdc - Send USDC to another address
  if (name === 'limitless_send_usdc') {
    const { toAddress, amount, password } = args as {
      toAddress: string;
      amount: number;
      password?: string;
    };

    if (!toAddress) {
      throw new Error('toAddress is required');
    }

    // Validate amount: positive, finite, not NaN, reasonable bounds (up to $1M USDC)
    validatePositiveNumber(amount, 'amount', { min: 0.000001, max: 1000000, maxDecimals: 6 });

    const walletService = getBaseWalletService();

    // Send USDC
    const result = await walletService.sendUsdc(userId, toAddress, amount, password);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'usdc_sent', 'wallet', null, {
      toAddress,
      amount: amount.toString(),
      txHash: result.txHash,
    });

    return {
      success: true,
      message: `Sent $${amount} USDC to ${toAddress}`,
      transaction: {
        txHash: result.txHash,
        fromAddress: result.fromAddress,
        toAddress: result.toAddress,
        amount: `${result.amount} USDC`,
        gasUsed: result.gasUsed,
      },
      explorerUrl: result.explorerUrl,
      usdcContractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      note: 'Transaction confirmed on Base. View on BaseScan for details.',
    };
  }

  // limitless_export_private_key - Export wallet private key
  if (name === 'limitless_export_private_key') {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);

    if (!walletInfo) {
      throw new Error('No wallet configured. Use limitless_setup_wallet to generate a wallet first.');
    }

    // Only allow export for generated wallets (imported wallets - user already has the key)
    if (walletInfo.type === 'imported') {
      throw new Error('Cannot export imported wallet key. You already have the private key for this wallet.');
    }

    const privateKey = await walletService.exportPrivateKey(userId);

    // Log the activity (but not the key itself!)
    const userService = getUserService();
    await userService.logActivity(userId, 'private_key_exported', 'wallet', null, {
      walletAddress: walletInfo.address,
      exportedAt: new Date().toISOString(),
    });

    return {
      warning: 'CRITICAL: This is your private key. Anyone with this key can steal all funds. Never share it!',
      walletAddress: walletInfo.address,
      privateKey: privateKey,
      network: 'Base',
      chainId: 8453,
      securityReminders: [
        'Store this key in a secure password manager or hardware wallet',
        'Never paste this key into untrusted websites or apps',
        'Never share this key with anyone, including Quantish support',
        'If compromised, transfer all funds to a new wallet immediately',
        'Consider using a hardware wallet for large amounts',
      ],
    };
  }

  // ============================================
  // API KEY MANAGEMENT TOOLS (Phase 6.7)
  // ============================================

  // limitless_list_api_keys - List all API keys for the user
  if (name === 'limitless_list_api_keys') {
    const apiKeyService = getApiKeyService();
    const keys = await apiKeyService.listApiKeys(userId);

    return {
      apiKeys: keys.map((key) => ({
        id: key.id,
        keyPrefix: key.keyPrefix,
        name: key.name || '(unnamed)',
        isActive: key.isActive,
        lastUsedAt: key.lastUsedAt ? key.lastUsedAt.toISOString() : null,
        expiresAt: key.expiresAt ? key.expiresAt.toISOString() : null,
        createdAt: key.createdAt.toISOString(),
        status: key.isActive
          ? key.expiresAt && key.expiresAt < new Date()
            ? 'expired'
            : 'active'
          : 'revoked',
      })),
      totalKeys: keys.length,
      activeKeys: keys.filter((k) => k.isActive).length,
      note: 'API keys are shown with prefix only. Full keys are not retrievable after creation.',
    };
  }

  // limitless_create_api_key - Create a new API key
  if (name === 'limitless_create_api_key') {
    const { name: keyName } = args as { name?: string };

    const apiKeyService = getApiKeyService();

    // Check how many active keys the user has (optional: limit to prevent abuse)
    const activeKeyCount = await apiKeyService.getActiveKeyCount(userId);
    const maxKeys = 10; // Reasonable limit

    if (activeKeyCount >= maxKeys) {
      throw new Error(
        `You have reached the maximum number of API keys (${maxKeys}). Revoke unused keys with limitless_revoke_api_key before creating new ones.`
      );
    }

    // Create the new key
    const result = await apiKeyService.createApiKey(userId, keyName);

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'api_key_created', 'api_key', result.keyId, {
      keyName: keyName || '(unnamed)',
      keyPrefix: result.keyPrefix,
    });

    return {
      success: true,
      message: 'API key created successfully. Save these credentials - they cannot be recovered!',
      apiKey: result.apiKey,
      apiSecret: result.apiSecret,
      keyId: result.keyId,
      keyPrefix: result.keyPrefix,
      name: keyName || '(unnamed)',
      securityNotes: [
        'This is the ONLY time the full API key and secret will be shown',
        'Store them securely in a password manager or environment variables',
        'Never commit API keys to version control',
        'If compromised, revoke immediately with limitless_revoke_api_key',
      ],
    };
  }

  // limitless_revoke_api_key - Revoke an API key
  if (name === 'limitless_revoke_api_key') {
    const { keyId } = args as { keyId: string };

    if (!keyId) {
      throw new Error('keyId is required. Get key IDs from limitless_list_api_keys.');
    }

    const apiKeyService = getApiKeyService();

    // Get current active key count first
    const activeKeyCount = await apiKeyService.getActiveKeyCount(userId);

    // Attempt to revoke
    const success = await apiKeyService.revokeApiKey(userId, keyId);

    if (!success) {
      throw new Error(
        'API key not found or you do not have permission to revoke it. Check the keyId with limitless_list_api_keys.'
      );
    }

    // Log the activity
    const userService = getUserService();
    await userService.logActivity(userId, 'api_key_revoked', 'api_key', keyId, {
      revokedKeyId: keyId,
    });

    // Warn if this was potentially the current key
    const remainingActiveKeys = activeKeyCount - 1;

    return {
      success: true,
      message: 'API key revoked successfully. It can no longer be used for authentication.',
      revokedKeyId: keyId,
      remainingActiveKeys,
      warnings: remainingActiveKeys === 0
        ? [
            'You have no active API keys remaining!',
            'You will need to use limitless_create_api_key to generate a new key.',
            'If you revoked the key you are currently using, this session will end.',
          ]
        : ['Revoked keys cannot be restored. Create a new key if needed.'],
    };
  }

  throw new Error(`Unknown tool: ${name}`);
}
