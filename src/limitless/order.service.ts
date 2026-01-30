/**
 * Limitless Order Service
 *
 * Handles order creation, signing (EIP-712), and submission to Limitless Exchange.
 *
 * CRITICAL: This implementation uses DYNAMIC venue addresses per market.
 * Never use hardcoded contract addresses - always fetch from market.venue!
 *
 * Order Flow:
 * 1. Get market venue (venue.exchange is the verifyingContract)
 * 2. Build order payload with proper scaling (1e6 for USDC)
 * 3. Sign with EIP-712 using dynamic domain from venue
 * 4. Submit to Limitless API
 */

import { TypedDataDomain, TypedDataField } from 'ethers';
import { getPrismaClient } from '../db/index.js';
import { getLimitlessClient, Venue, Market } from './client.js';
import { getBaseWalletService } from '../wallet/base-wallet.service.js';

// ============================================
// EIP-712 ORDER TYPES
// ============================================

/**
 * EIP-712 type definition for Limitless CTF Exchange orders.
 * This structure MUST match the contract's Order struct exactly.
 * Based on Polymarket CTF Exchange standard.
 */
export const ORDER_TYPES: Record<string, TypedDataField[]> = {
  Order: [
    { name: 'salt', type: 'uint256' },
    { name: 'maker', type: 'address' },
    { name: 'signer', type: 'address' },
    { name: 'taker', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'makerAmount', type: 'uint256' },
    { name: 'takerAmount', type: 'uint256' },
    { name: 'expiration', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'feeRateBps', type: 'uint256' },
    { name: 'side', type: 'uint8' },
    { name: 'signatureType', type: 'uint8' },
  ],
};

// ============================================
// TYPE DEFINITIONS
// ============================================

/**
 * Order payload for Limitless Exchange.
 *
 * IMPORTANT: The Limitless API expects specific types for each field.
 * This structure matches the official @limitless-exchange/sdk exactly.
 *
 * Field types must match:
 * - salt: number (timestamp-based)
 * - makerAmount/takerAmount: number (scaled integers)
 * - nonce/feeRateBps: number
 * - expiration/tokenId: string
 */
export interface OrderPayload {
  salt: number; // Unique entropy (timestamp-based pattern)
  maker: string; // Source of funds (checksummed address)
  signer: string; // Signing address (usually same as maker for EOA)
  taker: string; // Recipient (0x0...0 for public orders)
  tokenId: string; // CTF ERC1155 token ID (YES/NO outcome)
  makerAmount: number; // Amount of collateral (USDC) in raw units (1e6) - MUST be number
  takerAmount: number; // Amount of shares in raw units - MUST be number
  expiration: string; // Block timestamp when order expires ("0" = no expiry)
  nonce: number; // On-chain cancellation nonce - MUST be number
  feeRateBps: number; // Fee rate in basis points - MUST be number
  side: number; // 0 = BUY, 1 = SELL
  signatureType: number; // 0 = EOA, 1 = POLY_PROXY, 2 = POLY_GNOSIS_SAFE
  price?: number; // Price per share (required for GTC orders)
}

/**
 * Signed order ready for submission to Limitless API
 */
export interface SignedOrder extends OrderPayload {
  signature: string;
}

/**
 * Order creation parameters (human-readable)
 */
export interface CreateOrderParams {
  marketSlug: string;
  tokenId: string;
  side: 'BUY' | 'SELL';
  price: number; // 0.01 to 0.99
  size: number; // Number of shares
  orderType?: 'GTC' | 'FOK' | 'GTD' | 'IOC';
  expirationSeconds?: number; // For GTD orders, seconds from now
}

/**
 * Order result from Limitless API
 */
export interface OrderResult {
  id: string;
  limitlessOrderId?: string;
  status: string;
  filledAmount?: number;
  avgPrice?: number;
  createdAt: Date;
}

/**
 * Market type for determining order signing
 */
export type MarketType = 'CLOB' | 'NEGRISK';

// ============================================
// CONSTANTS
// ============================================

/** USDC has 6 decimals */
export const USDC_DECIMALS = 6;

/** Scaling factor for USDC amounts (1e6) */
export const USDC_SCALE = BigInt(10 ** USDC_DECIMALS);

/** Share scaling factor (1e6, same as USDC for 1:1 at price=1.0) */
export const SHARE_SCALE = BigInt(10 ** 6);

/** Zero address for public orders (any taker) */
export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** EIP-712 domain name for Limitless CTF Exchange */
export const DOMAIN_NAME = 'Limitless CTF Exchange';

/** EIP-712 domain version */
export const DOMAIN_VERSION = '1';

/** Base chain ID */
export const CHAIN_ID = 8453;

/** Signature types for orders */
export const SignatureType = {
  EOA: 0, // Externally Owned Account (default)
  POLY_PROXY: 1, // Polymarket proxy wallet
  POLY_GNOSIS_SAFE: 2, // Gnosis Safe wallet
  POLY_1271: 3, // EIP-1271 smart contract signature
} as const;

/** Order sides */
export const OrderSide = {
  BUY: 0,
  SELL: 1,
} as const;

// ============================================
// ORDER SERVICE CLASS
// ============================================

export class LimitlessOrderService {
  constructor() {}

  // ============================================
  // DOMAIN & VENUE (CRITICAL!)
  // ============================================

  /**
   * Get the EIP-712 domain for a specific market.
   *
   * CRITICAL: The verifyingContract MUST be the venue.exchange from the market!
   * Never use hardcoded addresses - each market has its own venue.
   *
   * @param venue - Venue data from the market (contains exchange address)
   * @returns EIP-712 domain for signing
   */
  getDomain(venue: Venue): TypedDataDomain {
    return {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      chainId: CHAIN_ID,
      verifyingContract: venue.exchange, // DYNAMIC from market venue!
    };
  }

  /**
   * Get venue and validate market supports CLOB orders.
   *
   * @param marketSlug - Market slug
   * @returns Venue and market data
   * @throws Error if market doesn't support CLOB
   */
  async getMarketVenue(marketSlug: string): Promise<{ venue: Venue; market: Market }> {
    const client = getLimitlessClient();

    const market = await client.getMarket(marketSlug);

    if (!market.venue?.exchange) {
      throw new Error(
        `Market ${marketSlug} does not support CLOB orders. ` +
          `Trade type: ${market.tradeType}. Only CLOB markets can accept limit orders.`
      );
    }

    return { venue: market.venue, market };
  }

  /**
   * Determine market type from market data.
   * NegRisk markets have a groupAddress or specific marketType.
   *
   * @param market - Market data
   * @returns 'CLOB' or 'NEGRISK'
   */
  getMarketType(market: Market): MarketType {
    // Check if it's a NegRisk market
    if (market.groupAddress || market.marketType === 'group-negrisk') {
      return 'NEGRISK';
    }
    return 'CLOB';
  }

  // ============================================
  // ORDER CREATION
  // ============================================

  /**
   * Generate a unique salt for order identification.
   *
   * This follows the official Limitless SDK pattern:
   * salt = timestamp * 1000 + nanoOffset + 24h
   *
   * This ensures uniqueness even when creating orders rapidly
   * while staying within JavaScript's safe integer range.
   *
   * @returns Salt as number (timestamp-based)
   */
  generateSalt(): number {
    const timestamp = Date.now();
    // Add some randomness within a range to avoid collisions
    const nanoOffset = Math.floor(Math.random() * 1000000);
    const oneDayMs = 1000 * 60 * 60 * 24;
    return timestamp * 1000 + nanoOffset + oneDayMs;
  }

  /**
   * Calculate maker and taker amounts for an order.
   *
   * For BUY orders:
   * - makerAmount = USDC to spend (price × size)
   * - takerAmount = shares to receive
   *
   * For SELL orders:
   * - makerAmount = shares to sell
   * - takerAmount = USDC to receive (price × size)
   *
   * IMPORTANT: Returns numbers (not bigints) to match official Limitless SDK format.
   * The API expects these as number types in the JSON payload.
   *
   * @param side - BUY or SELL
   * @param price - Price per share (0.01-0.99)
   * @param size - Number of shares
   * @returns Object with makerAmount and takerAmount as number (scaled integers)
   */
  calculateAmounts(
    side: 'BUY' | 'SELL',
    price: number,
    size: number
  ): { makerAmount: number; takerAmount: number } {
    // Validate inputs
    if (price <= 0 || price >= 1) {
      throw new Error('Price must be between 0 and 1 (exclusive)');
    }
    if (size <= 0) {
      throw new Error('Size must be positive');
    }

    // Calculate USDC amount (scaled by 1e6) - as number for API compatibility
    const usdcAmount = Math.round(price * size * Number(USDC_SCALE));
    // Calculate shares amount (also scaled by 1e6) - as number for API compatibility
    const sharesAmount = Math.round(size * Number(SHARE_SCALE));

    if (side === 'BUY') {
      // BUY: Spend USDC to get shares
      return {
        makerAmount: usdcAmount, // USDC to spend
        takerAmount: sharesAmount, // Shares to receive
      };
    } else {
      // SELL: Spend shares to get USDC
      return {
        makerAmount: sharesAmount, // Shares to sell
        takerAmount: usdcAmount, // USDC to receive
      };
    }
  }

  /**
   * Create an unsigned order payload.
   *
   * IMPORTANT: Field types MUST match the official Limitless SDK exactly:
   * - salt, makerAmount, takerAmount, nonce, feeRateBps: number
   * - expiration, tokenId: string
   * - price: number (for GTC orders)
   *
   * @param params - Order creation parameters
   * @param makerAddress - Address of the order maker (wallet address)
   * @param feeRateBps - Fee rate in basis points (from user's Limitless account)
   * @returns OrderPayload ready for signing
   */
  createOrderPayload(
    params: CreateOrderParams,
    makerAddress: string,
    feeRateBps: number = 0
  ): OrderPayload {
    const { side, price, size, expirationSeconds } = params;

    // Generate unique salt (timestamp-based pattern, returns number)
    const salt = this.generateSalt();

    // Calculate amounts (returns numbers, not bigints)
    const { makerAmount, takerAmount } = this.calculateAmounts(side, price, size);

    // Calculate expiration ("0" = no expiry for GTC)
    let expiration = '0';
    if (expirationSeconds && expirationSeconds > 0) {
      const expirationTimestamp = Math.floor(Date.now() / 1000) + expirationSeconds;
      expiration = expirationTimestamp.toString();
    }

    return {
      salt, // number (timestamp-based)
      maker: makerAddress,
      signer: makerAddress, // For EOA wallets, signer is same as maker
      taker: ZERO_ADDRESS, // Public order (any taker)
      tokenId: params.tokenId, // string
      makerAmount, // number (scaled integer)
      takerAmount, // number (scaled integer)
      expiration, // string
      nonce: 0, // number (0 for new orders)
      feeRateBps, // number
      side: side === 'BUY' ? OrderSide.BUY : OrderSide.SELL,
      signatureType: SignatureType.EOA,
      price, // number (required for GTC orders)
    };
  }

  /**
   * Convert OrderPayload to message data for EIP-712 signing.
   *
   * NOTE: For EIP-712 signing, ethers.js automatically handles number types
   * for uint256 fields. The official Limitless SDK passes numbers directly
   * without converting to BigInt.
   *
   * @param payload - Order payload
   * @returns Message data for signTypedData
   */
  prepareMessageData(payload: OrderPayload): Record<string, unknown> {
    // The official SDK passes these as numbers directly to signTypedData
    // ethers.js handles the conversion for uint256 types
    return {
      salt: payload.salt,
      maker: payload.maker,
      signer: payload.signer,
      taker: payload.taker,
      tokenId: payload.tokenId, // string for tokenId (can be large)
      makerAmount: payload.makerAmount,
      takerAmount: payload.takerAmount,
      expiration: payload.expiration,
      nonce: payload.nonce,
      feeRateBps: payload.feeRateBps,
      side: payload.side,
      signatureType: payload.signatureType,
    };
  }

  // ============================================
  // ORDER SIGNING
  // ============================================

  /**
   * Sign an order using EIP-712 typed data.
   * Uses the dynamic venue.exchange as verifyingContract.
   *
   * @param userId - User's database ID
   * @param orderPayload - Order to sign
   * @param venue - Market venue (for domain)
   * @param password - Password for imported wallets (optional)
   * @returns Signature string
   */
  async signOrder(
    userId: string,
    orderPayload: OrderPayload,
    venue: Venue,
    password?: string
  ): Promise<string> {
    const walletService = getBaseWalletService();

    // Get dynamic domain from venue
    const domain = this.getDomain(venue);

    // Prepare message data
    const messageData = this.prepareMessageData(orderPayload);

    // Sign with EIP-712
    const signature = await walletService.signTypedData(
      userId,
      domain,
      ORDER_TYPES,
      messageData,
      password
    );

    return signature;
  }

  /**
   * Create and sign an order in one step.
   *
   * @param userId - User's database ID
   * @param params - Order creation parameters
   * @param feeRateBps - Fee rate in basis points
   * @param password - Password for imported wallets (optional)
   * @returns SignedOrder ready for submission
   */
  async createAndSignOrder(
    userId: string,
    params: CreateOrderParams,
    feeRateBps: number = 0,
    password?: string
  ): Promise<{ signedOrder: SignedOrder; venue: Venue; market: Market }> {
    const walletService = getBaseWalletService();

    // Get wallet address
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user. Create or import a wallet first.');
    }

    // Get venue for the market (CRITICAL: dynamic per market)
    const { venue, market } = await this.getMarketVenue(params.marketSlug);

    // Create unsigned order payload
    const orderPayload = this.createOrderPayload(params, walletInfo.address, feeRateBps);

    // Sign the order
    const signature = await this.signOrder(userId, orderPayload, venue, password);

    const signedOrder: SignedOrder = {
      ...orderPayload,
      signature,
    };

    return { signedOrder, venue, market };
  }

  // ============================================
  // ORDER SUBMISSION
  // ============================================

  /**
   * Submit a signed order to Limitless API.
   *
   * IMPORTANT: The API payload format MUST match the official Limitless SDK exactly.
   * Key requirements:
   * - salt, makerAmount, takerAmount, nonce, feeRateBps: number (not string)
   * - expiration, tokenId: string
   * - price: number (for GTC orders)
   *
   * @param userId - User's database ID
   * @param signedOrder - Signed order to submit
   * @param marketSlug - Market slug
   * @param price - Order price (human-readable, 0.01-0.99)
   * @param orderType - Order type (GTC, FOK, GTD, IOC)
   * @param venue - Market venue (for database storage)
   * @param password - Password for re-auth if session expired (optional)
   * @returns OrderResult from Limitless API
   */
  async submitOrder(
    userId: string,
    signedOrder: SignedOrder,
    marketSlug: string,
    price: number,
    orderType: 'GTC' | 'FOK' | 'GTD' | 'IOC' = 'GTC',
    venue: Venue,
    password?: string
  ): Promise<OrderResult> {
    const client = getLimitlessClient();
    const prisma = getPrismaClient();

    // Get session (auto-refreshes if expired)
    const sessionCookie = await client.getSession(userId, password);

    // Get user's Limitless account ID for the API
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        walletAddress: true,
        importedWalletAddress: true,
        limitlessUserId: true,
        limitlessFeeRate: true,
      },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Limitless user ID is required for order submission
    if (!user.limitlessUserId) {
      throw new Error('Limitless user ID not found. Session may need to be refreshed.');
    }

    // Build submission payload - MUST match official Limitless SDK format exactly
    // All numeric fields must be numbers (not strings) to match SDK behavior
    const submissionPayload = {
      order: {
        // These fields are NUMBERS (not strings) per official SDK
        salt: signedOrder.salt,
        makerAmount: signedOrder.makerAmount,
        takerAmount: signedOrder.takerAmount,
        nonce: signedOrder.nonce,
        feeRateBps: signedOrder.feeRateBps,
        side: signedOrder.side,
        signatureType: signedOrder.signatureType,
        // These fields are STRINGS
        maker: signedOrder.maker,
        signer: signedOrder.signer,
        taker: signedOrder.taker,
        tokenId: signedOrder.tokenId,
        expiration: signedOrder.expiration,
        signature: signedOrder.signature,
        // Price is a number for GTC orders
        ...(signedOrder.price !== undefined ? { price: signedOrder.price } : {}),
      },
      ownerId: user.limitlessUserId, // Limitless user ID (number)
      orderType,
      marketSlug,
    };

    // Submit to Limitless API
    // Response format: { order: { id, createdAt, ... }, ... }
    const response = await client.authenticatedPost<{
      order?: { id: string; createdAt?: string };
      id?: string;
      status?: string;
    }>('/orders', sessionCookie, submissionPayload);

    // Extract order ID - API may return nested or flat response
    const orderId = response.order?.id || response.id;

    // Store order in our database
    const dbOrder = await prisma.order.create({
      data: {
        userId,
        limitlessOrderId: orderId,
        marketSlug,
        tokenId: signedOrder.tokenId,
        venueExchange: venue.exchange,
        venueAdapter: venue.adapter,
        side: signedOrder.side === OrderSide.BUY ? 'BUY' : 'SELL',
        orderType: orderType as 'GTC' | 'GTD' | 'FOK' | 'IOC',
        price: price,
        size: signedOrder.takerAmount / Number(SHARE_SCALE),
        makerAmount: signedOrder.makerAmount.toString(),
        takerAmount: signedOrder.takerAmount.toString(),
        signature: signedOrder.signature,
        salt: signedOrder.salt.toString(),
        status: 'OPEN',
      },
    });

    return {
      id: dbOrder.id,
      limitlessOrderId: orderId,
      status: response.status || 'OPEN',
      createdAt: dbOrder.createdAt,
    };
  }

  /**
   * Full order flow: create, sign, and submit.
   * This is the main entry point for placing orders.
   *
   * @param userId - User's database ID
   * @param params - Order parameters
   * @param password - Password for imported wallets (optional)
   * @returns OrderResult
   */
  async placeOrder(userId: string, params: CreateOrderParams, password?: string): Promise<OrderResult> {
    const client = getLimitlessClient();
    const prisma = getPrismaClient();

    // Get user's fee rate from their Limitless session
    // IMPORTANT: The API validates feeRateBps against the user's fee band.
    // If the fee rate doesn't match, the order will be rejected with "feeRateBps[0] is out of user's band"
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { limitlessFeeRate: true, limitlessSession: true },
    });

    // If user doesn't have a fee rate stored, we need to authenticate first to get it
    let feeRateBps = user?.limitlessFeeRate ?? 0;

    // If no fee rate stored, we need to force re-authentication to get the user's actual fee rate
    // The getSession() method returns early if the session is valid, so we must clear it first
    if (feeRateBps === 0) {
      // Clear the existing session to force re-authentication
      await client.clearSession(userId);
      // This will now re-authenticate since the session was cleared
      await client.getSession(userId, password);
      const refreshedUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { limitlessFeeRate: true },
      });
      feeRateBps = refreshedUser?.limitlessFeeRate ?? 0;

      // If still 0 after re-auth, the user might be new - use default 100 (1%)
      if (feeRateBps === 0) {
        console.warn(`[LimitlessOrderService] User ${userId} has feeRateBps=0 after re-auth, using default 100 (1%)`);
        feeRateBps = 100; // Default 1% fee rate
      }
    }

    // Create and sign the order with the user's actual fee rate
    const { signedOrder, venue } = await this.createAndSignOrder(
      userId,
      params,
      feeRateBps,
      password
    );

    // Submit the order
    return await this.submitOrder(
      userId,
      signedOrder,
      params.marketSlug,
      params.price,
      params.orderType || 'GTC',
      venue,
      password
    );
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let orderServiceInstance: LimitlessOrderService | null = null;

/**
 * Get the singleton LimitlessOrderService instance
 */
export function getLimitlessOrderService(): LimitlessOrderService {
  if (!orderServiceInstance) {
    orderServiceInstance = new LimitlessOrderService();
  }
  return orderServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetLimitlessOrderService(): void {
  orderServiceInstance = null;
}
