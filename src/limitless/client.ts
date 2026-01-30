/**
 * Limitless Exchange API Client
 *
 * Handles all interactions with the Limitless Exchange API including:
 * - Authentication (signing message + login)
 * - Session management
 * - Market data fetching
 * - Venue system (dynamic contract addresses per market)
 *
 * CRITICAL: Each market has its own venue with unique contract addresses!
 * The venue.exchange is the verifyingContract for EIP-712 order signing.
 */

import { config } from '../config/index.js';
import { getPrismaClient } from '../db/index.js';
import { getEncryptionService } from '../crypto/encryption.js';
import { getBaseWalletService } from '../wallet/base-wallet.service.js';

const API_BASE = config.limitless.apiUrl;

// Retry configuration for API calls
const RETRY_CONFIG = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
};

// ============================================
// TYPE DEFINITIONS
// ============================================

export interface Venue {
  exchange: string; // verifyingContract for EIP-712
  adapter: string | null; // For NegRisk sell orders
}

export interface CollateralToken {
  address: string;
  decimals: number;
  symbol: string;
}

export interface Market {
  id: number;
  address: string;
  conditionId: string;
  title: string;
  description?: string;
  slug?: string;
  collateralToken: CollateralToken;
  expirationTimestamp: number;
  status: string;
  prices: number[];
  tradeType: 'amm' | 'clob';
  venue?: Venue;
  // Additional fields
  category?: string;
  volume?: number;
  liquidity?: number;
  yesTokenId?: string;
  noTokenId?: string;
  tokens?: MarketToken[];
  marketType?: string;
  groupAddress?: string;
  tags?: string[];
}

export interface MarketToken {
  id: string;
  outcome: string;
  price: number;
}

export interface AuthResult {
  sessionCookie: string;
  userData: {
    id: number;
    account: string;
    rank?: {
      feeRateBps: number;
    };
  };
}

export interface OrderBook {
  bids: OrderBookEntry[];
  asks: OrderBookEntry[];
  timestamp?: number;
}

export interface OrderBookEntry {
  price: number;
  size: number;
  cumSize?: number;
}

export interface HistoricalPrice {
  timestamp: number;
  yesPrice: number;
  noPrice: number;
  volume?: number;
}

export interface UserSession {
  sessionCookie: string;
  account: string;
  userId: number;
  feeRateBps: number;
  expiresAt?: Date;
}

// ============================================
// PORTFOLIO RAW TYPES (for client methods)
// Full typed versions in portfolio.service.ts
// ============================================

/**
 * Raw portfolio positions response from API
 */
export interface PortfolioPositionsRaw {
  amm: PortfolioPositionRaw[];
  clob: PortfolioPositionRaw[];
  group: PortfolioPositionRaw[];
  points?: string;
  accumulativePoints?: string;
  rewards?: {
    todaysRewards: string;
    rewardsByEpoch: unknown[];
    rewardsChartData: unknown[];
    totalUnpaidRewards: string;
    totalUserRewardsLastEpoch: string;
  };
}

/**
 * Raw position from API (flexible to accommodate different position types)
 */
export interface PortfolioPositionRaw {
  market: {
    id: number;
    slug: string;
    title: string;
    description?: string;
    status: string;
    expirationTimestamp?: number;
    collateralToken?: {
      address: string;
      symbol: string;
      decimals: number;
    };
    tradeType?: 'amm' | 'clob';
  };
  makerAddress?: string;
  account?: string;
  outcomeIndex?: number;
  positions?: {
    yes?: {
      contractsAmount: string;
      currentValue: string;
      avgPrice: string;
      unrealizedPnl: string;
      realizedPnl: string;
    };
    no?: {
      contractsAmount: string;
      currentValue: string;
      avgPrice: string;
      unrealizedPnl: string;
      realizedPnl: string;
    };
  };
  tokensBalance?: {
    yes: string;
    no: string;
  };
  collateralAmount?: string;
  outcomeTokenAmount?: string;
  averageFillPrice?: string;
  totalBuysCost?: string;
  totalSellsCost?: string;
  realizedPnl?: string;
  unrealizedPnl?: string;
  latestTrade?: {
    price?: string;
    outcomeTokenPrice?: string;
    timestamp?: number;
    side?: 'BUY' | 'SELL';
  };
  orders?: {
    liveOrders: unknown[];
    totalCollateralLocked: string;
  };
}

/**
 * Raw trade from API
 */
export interface TradeRaw {
  id: string;
  marketSlug: string;
  marketTitle?: string;
  side: 'BUY' | 'SELL';
  outcomeIndex: number;
  price: string;
  size: string;
  total: string;
  fee: string;
  timestamp: number;
  txHash?: string;
  type?: 'OPEN' | 'CLOSE';
  pnl?: string;
  tradeType?: 'amm' | 'clob';
}

/**
 * Raw portfolio history response
 */
export interface PortfolioHistoryRaw {
  history: {
    timestamp: number;
    type: string;
    marketSlug: string;
    marketTitle?: string;
    details: {
      side?: 'BUY' | 'SELL';
      outcomeIndex?: number;
      amount?: string;
      price?: string;
      pnl?: string;
      txHash?: string;
    };
  }[];
  pagination?: {
    page: number;
    limit: number;
    total: number;
    hasMore: boolean;
  };
}

/**
 * Raw trading allowance response
 */
export interface TradingAllowanceRaw {
  usdc?: {
    allowance: string;
    isApproved: boolean;
  };
  ctf?: {
    isApprovedForAll: boolean;
  };
  adapter?: {
    isApprovedForAll: boolean;
  };
}

// ============================================
// RETRY HELPER
// ============================================

async function withRetry<T>(
  fn: () => Promise<T>,
  operation: string,
  maxRetries: number = RETRY_CONFIG.maxRetries
): Promise<T> {
  let lastError: Error | unknown;
  let delay = RETRY_CONFIG.initialDelayMs;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      lastError = error;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check if this is a retryable error
      const isRetryable =
        errorMessage.includes('rate limit') ||
        errorMessage.includes('429') ||
        errorMessage.includes('503') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('ETIMEDOUT') ||
        errorMessage.includes('ECONNRESET') ||
        errorMessage.includes('network');

      if (!isRetryable || attempt === maxRetries) {
        throw error;
      }

      console.warn(
        `${operation} failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms: ${errorMessage}`
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
    }
  }

  throw lastError;
}

// ============================================
// LIMITLESS CLIENT CLASS
// ============================================

export class LimitlessClient {
  // In-memory venue cache (per market slug)
  private venueCache: Map<string, { venue: Venue; fetchedAt: Date }> = new Map();
  private readonly venueCacheTtlMs = 60 * 60 * 1000; // 1 hour (venues rarely change)

  constructor() {}

  // ============================================
  // AUTHENTICATION
  // ============================================

  /**
   * Get signing message from Limitless API
   * This is the nonce to sign for authentication
   */
  async getSigningMessage(): Promise<string> {
    const response = await withRetry(
      () =>
        fetch(`${API_BASE}/auth/signing-message`, {
          method: 'GET',
          headers: {
            Accept: 'text/plain',
          },
        }),
      'Get signing message'
    );

    if (!response.ok) {
      throw new Error(`Failed to get signing message: ${response.status} ${response.statusText}`);
    }

    return await response.text();
  }

  /**
   * Authenticate with Limitless using wallet signature
   *
   * @param userId - The user's database ID (for wallet access)
   * @param password - Password for imported wallets (optional)
   * @returns AuthResult with session cookie and user data
   */
  async authenticate(userId: string, password?: string): Promise<AuthResult> {
    const walletService = getBaseWalletService();

    // Get user's wallet address
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user. Create or import a wallet first.');
    }

    const address = walletInfo.address;

    // Step 1: Get signing message (nonce)
    const signingMessage = await this.getSigningMessage();

    // Step 2: Sign the message with user's wallet
    const signature = await walletService.signMessage(userId, signingMessage, password);

    // Step 3: Convert message to hex for the API
    const hexMessage = '0x' + Buffer.from(signingMessage, 'utf-8').toString('hex');

    // Ensure signature has 0x prefix
    const sigHex = signature.startsWith('0x') ? signature : '0x' + signature;

    // Step 4: Login with Limitless
    const response = await withRetry(
      () =>
        fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: {
            'x-account': address, // Must be EIP-55 checksummed (wallet service does this)
            'x-signing-message': hexMessage,
            'x-signature': sigHex,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ client: 'eoa' }),
        }),
      'Login to Limitless'
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Authentication failed: ${response.status} - ${errorText}`);
    }

    // Extract session cookie from Set-Cookie header
    const setCookie = response.headers.get('set-cookie');
    let sessionCookie = '';
    if (setCookie) {
      const match = setCookie.match(/limitless_session=([^;]+)/);
      if (match) {
        sessionCookie = match[1];
      }
    }

    if (!sessionCookie) {
      throw new Error('Authentication succeeded but no session cookie received');
    }

    const userData = (await response.json()) as AuthResult['userData'];

    return { sessionCookie, userData };
  }

  /**
   * Authenticate and store session in database
   *
   * @param userId - The user's database ID
   * @param password - Password for imported wallets (optional)
   * @returns UserSession with all session info
   */
  async authenticateAndStore(userId: string, password?: string): Promise<UserSession> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    // Perform authentication
    const authResult = await this.authenticate(userId, password);

    // Encrypt session cookie before storage
    const encryptedSession = encryption.encrypt(authResult.sessionCookie);

    // Session expires in 24 hours (Limitless default)
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // Store session and Limitless user ID in database
    await prisma.user.update({
      where: { id: userId },
      data: {
        limitlessSession: encryptedSession,
        sessionExpiry: expiresAt,
        limitlessUserId: authResult.userData.id,
        limitlessFeeRate: authResult.userData.rank?.feeRateBps || 0,
      },
    });

    return {
      sessionCookie: authResult.sessionCookie,
      account: authResult.userData.account,
      userId: authResult.userData.id,
      feeRateBps: authResult.userData.rank?.feeRateBps || 0,
      expiresAt,
    };
  }

  /**
   * Get stored session for a user, re-authenticate if expired
   *
   * @param userId - The user's database ID
   * @param password - Password for imported wallets (optional, needed for re-auth)
   * @returns Session cookie string
   */
  async getSession(userId: string, password?: string): Promise<string> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        limitlessSession: true,
        sessionExpiry: true,
        importedWalletAddress: true,
      },
    });

    // Check if session exists and is still valid
    if (user?.limitlessSession && user?.sessionExpiry) {
      const now = new Date();
      if (user.sessionExpiry > now) {
        // Session still valid, decrypt and return
        return encryption.decrypt(user.limitlessSession);
      }
    }

    // Session expired or doesn't exist - need to re-authenticate
    if (user?.importedWalletAddress && !password) {
      throw new Error('Session expired. Password required for imported wallet to re-authenticate.');
    }

    const session = await this.authenticateAndStore(userId, password);
    return session.sessionCookie;
  }

  /**
   * Verify if a session is still valid
   *
   * @param sessionCookie - The session cookie to verify
   * @returns true if valid, false otherwise
   */
  async verifySession(sessionCookie: string): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE}/auth/verify-auth`, {
        method: 'GET',
        headers: {
          Cookie: `limitless_session=${sessionCookie}`,
        },
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Clear stored session for a user
   *
   * @param userId - The user's database ID
   */
  async clearSession(userId: string): Promise<void> {
    const prisma = getPrismaClient();

    await prisma.user.update({
      where: { id: userId },
      data: {
        limitlessSession: null,
        sessionExpiry: null,
      },
    });
  }

  // ============================================
  // MARKET DATA
  // ============================================

  /**
   * Get active markets from Limitless
   *
   * @param limit - Max number of markets to return (default 20)
   * @param page - Page number for pagination (default 1, 1-indexed)
   * @returns Array of Market objects
   */
  async getActiveMarkets(limit: number = 20, page: number = 1): Promise<Market[]> {
    const response = await withRetry(
      () => fetch(`${API_BASE}/markets/active?limit=${limit}&page=${page}`),
      'Get active markets'
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch active markets: ${response.status}`);
    }

    const json = (await response.json()) as { data?: Market[] } | Market[];
    // API returns {data: Market[], totalMarketsCount: number}
    if ('data' in json && Array.isArray(json.data)) {
      return json.data;
    }
    // Fallback for direct array response
    return json as Market[];
  }

  /**
   * Get a specific market by slug
   * IMPORTANT: This returns the venue data needed for order signing!
   *
   * @param slug - Market slug (identifier)
   * @returns Market object with venue data
   */
  async getMarket(slug: string): Promise<Market> {
    const response = await withRetry(() => fetch(`${API_BASE}/markets/${slug}`), 'Get market');

    if (!response.ok) {
      throw new Error(`Failed to fetch market ${slug}: ${response.status}`);
    }

    const market = (await response.json()) as Market;

    // Cache the venue if present
    if (market.venue?.exchange) {
      this.venueCache.set(slug, {
        venue: market.venue,
        fetchedAt: new Date(),
      });
    }

    return market;
  }

  /**
   * Search markets using semantic search
   *
   * @param query - Search query string
   * @param limit - Max results (default 20)
   * @returns Array of matching markets
   */
  async searchMarkets(query: string, limit: number = 20): Promise<Market[]> {
    const encodedQuery = encodeURIComponent(query);
    const response = await withRetry(
      () => fetch(`${API_BASE}/markets/search?query=${encodedQuery}&limit=${limit}`),
      'Search markets'
    );

    if (!response.ok) {
      throw new Error(`Failed to search markets: ${response.status}`);
    }

    const json = (await response.json()) as { markets?: Market[]; data?: Market[] } | Market[];
    // API returns {markets: Market[], totalMarketsCount: number}
    if ('markets' in json && Array.isArray(json.markets)) {
      return json.markets;
    }
    // Fallback for {data: [...]} format
    if ('data' in json && Array.isArray(json.data)) {
      return json.data;
    }
    return json as Market[];
  }

  /**
   * Get orderbook for a market
   *
   * @param marketSlug - Market slug
   * @returns OrderBook with bids and asks
   */
  async getOrderbook(marketSlug: string): Promise<OrderBook> {
    const response = await withRetry(
      () => fetch(`${API_BASE}/markets/${marketSlug}/orderbook`),
      'Get orderbook'
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch orderbook: ${response.status}`);
    }

    return (await response.json()) as OrderBook;
  }

  /**
   * Get historical price data for a market
   *
   * @param marketSlug - Market slug
   * @param interval - Time interval (default '1h')
   * @param limit - Number of data points (default 100)
   * @returns Array of historical price points
   */
  async getHistoricalPrice(
    marketSlug: string,
    interval: string = '1h',
    limit: number = 100
  ): Promise<HistoricalPrice[]> {
    const response = await withRetry(
      () =>
        fetch(
          `${API_BASE}/markets/${marketSlug}/historical-price?interval=${interval}&limit=${limit}`
        ),
      'Get historical price'
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch historical price: ${response.status}`);
    }

    return (await response.json()) as HistoricalPrice[];
  }

  // ============================================
  // VENUE SYSTEM (CRITICAL!)
  // ============================================

  /**
   * Get venue for a market (REQUIRED for order signing)
   *
   * CRITICAL: Each market has its own venue with unique contract addresses!
   * The venue.exchange must be used as verifyingContract in EIP-712 domain.
   *
   * @param marketSlug - Market slug
   * @returns Venue object with exchange and adapter addresses
   * @throws Error if market is AMM (no CLOB venue) or venue not found
   */
  async getVenue(marketSlug: string): Promise<Venue> {
    // Check cache first
    const cached = this.venueCache.get(marketSlug);
    if (cached && Date.now() - cached.fetchedAt.getTime() < this.venueCacheTtlMs) {
      return cached.venue;
    }

    // Check database cache
    const prisma = getPrismaClient();
    const cachedMarket = await prisma.marketCache.findUnique({
      where: { slug: marketSlug },
      select: {
        venueExchange: true,
        venueAdapter: true,
        lastUpdated: true,
      },
    });

    // If database cache is fresh (less than 1 hour old), use it
    if (cachedMarket?.venueExchange) {
      const cacheAge = Date.now() - cachedMarket.lastUpdated.getTime();
      if (cacheAge < this.venueCacheTtlMs) {
        const venue: Venue = {
          exchange: cachedMarket.venueExchange,
          adapter: cachedMarket.venueAdapter,
        };
        this.venueCache.set(marketSlug, { venue, fetchedAt: new Date() });
        return venue;
      }
    }

    // Fetch fresh market data
    const market = await this.getMarket(marketSlug);

    if (!market.venue?.exchange) {
      throw new Error(
        `Market ${marketSlug} does not have a CLOB venue. ` +
          `Trade type: ${market.tradeType}. Only CLOB markets support order placement.`
      );
    }

    // Update database cache
    await prisma.marketCache.upsert({
      where: { slug: marketSlug },
      update: {
        venueExchange: market.venue.exchange,
        venueAdapter: market.venue.adapter,
        lastUpdated: new Date(),
      },
      create: {
        slug: marketSlug,
        title: market.title,
        description: market.description,
        venueExchange: market.venue.exchange,
        venueAdapter: market.venue.adapter,
        yesTokenId: market.yesTokenId || market.tokens?.[0]?.id,
        noTokenId: market.noTokenId || market.tokens?.[1]?.id,
        marketType: market.marketType || (market.groupAddress ? 'group-negrisk' : 'single-clob'),
        status: market.status,
        lastUpdated: new Date(),
      },
    });

    return market.venue;
  }

  /**
   * Check if a market is a CLOB market (supports order placement)
   *
   * @param marketSlug - Market slug
   * @returns true if CLOB, false if AMM
   */
  async isClobMarket(marketSlug: string): Promise<boolean> {
    const market = await this.getMarket(marketSlug);
    return market.tradeType === 'clob' && !!market.venue?.exchange;
  }

  // ============================================
  // AUTHENTICATED API CALLS (Helpers)
  // ============================================

  /**
   * Make an authenticated GET request
   *
   * @param path - API path (without base URL)
   * @param sessionCookie - Session cookie for authentication
   * @returns Response data
   */
  async authenticatedGet<T>(path: string, sessionCookie: string): Promise<T> {
    const response = await withRetry(
      () =>
        fetch(`${API_BASE}${path}`, {
          method: 'GET',
          headers: {
            Cookie: `limitless_session=${sessionCookie}`,
            'Content-Type': 'application/json',
          },
        }),
      `GET ${path}`
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API request failed: ${response.status} - ${errorText}`);
    }

    return (await response.json()) as T;
  }

  /**
   * Make an authenticated POST request
   *
   * @param path - API path (without base URL)
   * @param sessionCookie - Session cookie for authentication
   * @param body - Request body
   * @returns Response data
   */
  async authenticatedPost<T, B = unknown>(path: string, sessionCookie: string, body: B): Promise<T> {
    const response = await withRetry(
      () =>
        fetch(`${API_BASE}${path}`, {
          method: 'POST',
          headers: {
            Cookie: `limitless_session=${sessionCookie}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        }),
      `POST ${path}`
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API request failed: ${response.status} - ${errorText}`);
    }

    return (await response.json()) as T;
  }

  /**
   * Make an authenticated DELETE request
   *
   * @param path - API path (without base URL)
   * @param sessionCookie - Session cookie for authentication
   */
  async authenticatedDelete(path: string, sessionCookie: string): Promise<void> {
    const response = await withRetry(
      () =>
        fetch(`${API_BASE}${path}`, {
          method: 'DELETE',
          headers: {
            Cookie: `limitless_session=${sessionCookie}`,
          },
        }),
      `DELETE ${path}`
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API request failed: ${response.status} - ${errorText}`);
    }
  }

  // ============================================
  // PORTFOLIO ENDPOINTS
  // Note: Typed versions available in portfolio.service.ts
  // These methods use the PortfolioService for proper typing
  // ============================================

  /**
   * Get user's positions (requires authentication)
   * For typed responses, use PortfolioService.getPositions()
   *
   * @param sessionCookie - Session cookie
   * @returns Raw portfolio positions response
   */
  async getPositionsRaw(sessionCookie: string): Promise<PortfolioPositionsRaw> {
    return this.authenticatedGet<PortfolioPositionsRaw>('/portfolio/positions', sessionCookie);
  }

  /**
   * Get user's trades (requires authentication)
   * For typed responses, use PortfolioService.getTrades()
   *
   * @param sessionCookie - Session cookie
   * @param limit - Max trades to return (default 50)
   * @param offset - Pagination offset (default 0)
   * @returns Array of trade objects
   */
  async getTradesRaw(sessionCookie: string, limit: number = 50, offset: number = 0): Promise<TradeRaw[]> {
    return this.authenticatedGet<TradeRaw[]>(
      `/portfolio/trades?limit=${limit}&offset=${offset}`,
      sessionCookie
    );
  }

  /**
   * Get user's portfolio history (requires authentication)
   * For typed responses, use PortfolioService.getPortfolioHistory()
   *
   * @param sessionCookie - Session cookie
   * @param page - Page number (1-indexed)
   * @param limit - Items per page
   * @returns Portfolio history object
   */
  async getPortfolioHistoryRaw(
    sessionCookie: string,
    page: number = 1,
    limit: number = 50
  ): Promise<PortfolioHistoryRaw> {
    return this.authenticatedGet<PortfolioHistoryRaw>(
      `/portfolio/history?page=${page}&limit=${limit}`,
      sessionCookie
    );
  }

  /**
   * Get user's trading allowance/approval status (requires authentication)
   * For typed responses, use PortfolioService.getTradingAllowance()
   *
   * @param sessionCookie - Session cookie
   * @returns Allowance status object
   */
  async getTradingAllowanceRaw(sessionCookie: string): Promise<TradingAllowanceRaw> {
    return this.authenticatedGet<TradingAllowanceRaw>(
      '/portfolio/trading/allowance',
      sessionCookie
    );
  }

  // ============================================
  // ORDER ENDPOINTS
  // ============================================

  /**
   * Get user's orders for a market (requires authentication)
   *
   * @param sessionCookie - Session cookie
   * @param marketSlug - Market slug
   * @returns Array of order objects
   */
  async getOrders(sessionCookie: string, marketSlug: string): Promise<unknown[]> {
    return this.authenticatedGet<unknown[]>(`/markets/${marketSlug}/user-orders`, sessionCookie);
  }

  /**
   * Cancel a single order (requires authentication)
   *
   * @param sessionCookie - Session cookie
   * @param orderId - Order ID to cancel
   */
  async cancelOrder(sessionCookie: string, orderId: string): Promise<void> {
    await this.authenticatedDelete(`/orders/${orderId}`, sessionCookie);
  }

  /**
   * Cancel multiple orders (requires authentication)
   *
   * @param sessionCookie - Session cookie
   * @param orderIds - Array of order IDs to cancel
   */
  async cancelBatchOrders(sessionCookie: string, orderIds: string[]): Promise<void> {
    await this.authenticatedPost('/orders/cancel-batch', sessionCookie, { orderIds });
  }

  /**
   * Cancel all orders in a market (requires authentication)
   *
   * @param sessionCookie - Session cookie
   * @param marketSlug - Market slug
   */
  async cancelAllOrders(sessionCookie: string, marketSlug: string): Promise<void> {
    await this.authenticatedDelete(`/orders/all/${marketSlug}`, sessionCookie);
  }

  /**
   * Clear the venue cache (useful for testing or cache invalidation)
   */
  clearVenueCache(): void {
    this.venueCache.clear();
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let clientInstance: LimitlessClient | null = null;

/**
 * Get the singleton LimitlessClient instance
 */
export function getLimitlessClient(): LimitlessClient {
  if (!clientInstance) {
    clientInstance = new LimitlessClient();
  }
  return clientInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetLimitlessClient(): void {
  if (clientInstance) {
    clientInstance.clearVenueCache();
  }
  clientInstance = null;
}
