/**
 * Limitless Portfolio Service
 *
 * Handles portfolio position tracking, trade history, and P&L calculations.
 * Syncs positions from the Limitless API to the local database.
 *
 * API Response Types based on official Limitless TypeScript SDK:
 * - https://github.com/limitless-labs-group/limitless-exchange-ts-sdk
 */

import { Decimal } from '@prisma/client/runtime/library';
import { getPrismaClient } from '../db/index.js';
import { getLimitlessClient, type Market } from './client.js';

// ============================================
// TYPE DEFINITIONS (from Limitless API)
// ============================================

/**
 * Market info within a position response
 */
export interface PositionMarket {
  id: number;
  slug: string;
  title: string;
  description?: string;
  status: string;
  expirationTimestamp?: number;
  collateralToken: {
    address: string;
    symbol: string;
    decimals: number;
  };
  tradeType: 'amm' | 'clob';
  category?: string;
  groupAddress?: string;
}

/**
 * Token balance info
 */
export interface TokenBalance {
  yes: string; // Raw balance as string (for precision)
  no: string;
}

/**
 * Position side details (YES or NO)
 */
export interface PositionSide {
  contractsAmount: string; // Number of contracts/shares
  currentValue: string; // Current value in collateral
  avgPrice: string; // Average entry price
  unrealizedPnl: string; // Unrealized P&L
  realizedPnl: string; // Realized P&L
}

/**
 * Latest trade info
 */
export interface LatestTrade {
  price: string;
  timestamp: number;
  side: 'BUY' | 'SELL';
  outcomeIndex?: number;
}

/**
 * Live order info
 */
export interface LiveOrder {
  id: string;
  price: string;
  size: string;
  side: 'BUY' | 'SELL';
  tokenId: string;
  status: string;
  createdAt: number;
}

/**
 * CLOB Position from Limitless API
 */
export interface CLOBPosition {
  market: PositionMarket;
  makerAddress: string;
  positions: {
    yes: PositionSide;
    no: PositionSide;
  };
  tokensBalance: TokenBalance;
  latestTrade?: LatestTrade;
  orders?: {
    liveOrders: LiveOrder[];
    totalCollateralLocked: string;
  };
  rewards?: {
    epochs: unknown[];
    isEarning: boolean;
  };
}

/**
 * AMM Position from Limitless API
 */
export interface AMMPosition {
  market: PositionMarket;
  account: string;
  outcomeIndex: number; // 0 = YES, 1 = NO
  collateralAmount: string;
  outcomeTokenAmount: string;
  averageFillPrice: string;
  totalBuysCost: string;
  totalSellsCost: string;
  realizedPnl: string;
  unrealizedPnl: string;
  latestTrade?: {
    outcomeTokenPrice: string;
  };
}

/**
 * Group/NegRisk Position
 */
export interface GroupPosition {
  market: PositionMarket;
  account: string;
  positions: {
    [outcomeId: string]: {
      contractsAmount: string;
      currentValue: string;
      avgPrice: string;
      unrealizedPnl: string;
      realizedPnl: string;
    };
  };
}

/**
 * Full portfolio positions response from Limitless API
 */
export interface PortfolioPositionsResponse {
  amm: AMMPosition[];
  clob: CLOBPosition[];
  group: GroupPosition[];
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
 * Trade record from Limitless API
 */
export interface Trade {
  id: string;
  marketSlug: string;
  marketTitle?: string;
  side: 'BUY' | 'SELL';
  outcomeIndex: number; // 0 = YES, 1 = NO
  price: string;
  size: string;
  total: string;
  fee: string;
  timestamp: number;
  txHash?: string;
  type?: 'OPEN' | 'CLOSE';
  pnl?: string;
  tradeType: 'amm' | 'clob';
}

/**
 * Trade history response
 */
export interface TradeHistoryResponse {
  trades: Trade[];
  pagination?: {
    total: number;
    page: number;
    limit: number;
    hasMore: boolean;
  };
}

/**
 * Portfolio history item
 */
export interface PortfolioHistoryItem {
  timestamp: number;
  type: 'trade' | 'split' | 'merge' | 'conversion' | 'settlement';
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
}

/**
 * Portfolio history response
 */
export interface PortfolioHistoryResponse {
  history: PortfolioHistoryItem[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasMore: boolean;
  };
}

/**
 * Trading allowance response
 */
export interface TradingAllowanceResponse {
  usdc: {
    allowance: string;
    isApproved: boolean;
  };
  ctf: {
    isApprovedForAll: boolean;
  };
  adapter?: {
    isApprovedForAll: boolean;
  };
}

/**
 * Unified position format for our API
 */
export interface UnifiedPosition {
  id: string;
  marketSlug: string;
  marketTitle: string;
  outcomeSide: 'YES' | 'NO';
  balance: string;
  avgEntryPrice: string;
  currentPrice: string;
  totalInvested: string;
  currentValue: string;
  unrealizedPnl: string;
  realizedPnl: string;
  isSettled: boolean;
  tradeType: 'amm' | 'clob';
  lastUpdated: Date;
}

/**
 * Portfolio summary
 */
export interface PortfolioSummary {
  totalValue: string;
  totalInvested: string;
  totalUnrealizedPnl: string;
  totalRealizedPnl: string;
  positionCount: number;
  activeMarkets: number;
}

// ============================================
// PORTFOLIO SERVICE
// ============================================

export class PortfolioService {
  private client = getLimitlessClient();

  /**
   * Get user's portfolio positions from Limitless API
   *
   * @param sessionCookie - Session cookie for authentication
   * @returns Full portfolio positions response
   */
  async getPositions(sessionCookie: string): Promise<PortfolioPositionsResponse> {
    return this.client.authenticatedGet<PortfolioPositionsResponse>(
      '/portfolio/positions',
      sessionCookie
    );
  }

  /**
   * Get user's trade history from Limitless API
   *
   * @param sessionCookie - Session cookie
   * @param limit - Max trades to return (default 50)
   * @param offset - Pagination offset (default 0)
   * @returns Trade history with pagination
   */
  async getTrades(
    sessionCookie: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<TradeHistoryResponse> {
    const trades = await this.client.authenticatedGet<Trade[]>(
      `/portfolio/trades?limit=${limit}&offset=${offset}`,
      sessionCookie
    );

    return {
      trades,
      pagination: {
        total: trades.length,
        page: Math.floor(offset / limit) + 1,
        limit,
        hasMore: trades.length === limit,
      },
    };
  }

  /**
   * Get user's full portfolio history (trades, splits, merges, conversions)
   *
   * @param sessionCookie - Session cookie
   * @param page - Page number (1-indexed)
   * @param limit - Items per page
   * @param from - Start date (ISO 8601)
   * @param to - End date (ISO 8601)
   * @returns Portfolio history with pagination
   */
  async getPortfolioHistory(
    sessionCookie: string,
    page: number = 1,
    limit: number = 50,
    from?: string,
    to?: string
  ): Promise<PortfolioHistoryResponse> {
    let path = `/portfolio/history?page=${page}&limit=${limit}`;
    if (from) path += `&from=${encodeURIComponent(from)}`;
    if (to) path += `&to=${encodeURIComponent(to)}`;

    return this.client.authenticatedGet<PortfolioHistoryResponse>(path, sessionCookie);
  }

  /**
   * Get user's trading allowance (approval status)
   *
   * @param sessionCookie - Session cookie
   * @returns Trading allowance status
   */
  async getTradingAllowance(sessionCookie: string): Promise<TradingAllowanceResponse> {
    return this.client.authenticatedGet<TradingAllowanceResponse>(
      '/portfolio/trading/allowance',
      sessionCookie
    );
  }

  /**
   * Convert CLOB positions to unified format
   */
  private convertCLOBPositions(clobPositions: CLOBPosition[]): UnifiedPosition[] {
    const unified: UnifiedPosition[] = [];

    for (const pos of clobPositions) {
      // Add YES position if it has balance
      const yesBalance = parseFloat(pos.positions.yes.contractsAmount || '0');
      if (yesBalance > 0) {
        unified.push({
          id: `${pos.market.slug}-YES`,
          marketSlug: pos.market.slug,
          marketTitle: pos.market.title,
          outcomeSide: 'YES',
          balance: pos.positions.yes.contractsAmount,
          avgEntryPrice: pos.positions.yes.avgPrice,
          currentPrice: pos.latestTrade?.price || '0.5',
          totalInvested: this.calculateInvested(
            pos.positions.yes.contractsAmount,
            pos.positions.yes.avgPrice
          ),
          currentValue: pos.positions.yes.currentValue,
          unrealizedPnl: pos.positions.yes.unrealizedPnl,
          realizedPnl: pos.positions.yes.realizedPnl,
          isSettled: pos.market.status === 'resolved',
          tradeType: 'clob',
          lastUpdated: new Date(),
        });
      }

      // Add NO position if it has balance
      const noBalance = parseFloat(pos.positions.no.contractsAmount || '0');
      if (noBalance > 0) {
        unified.push({
          id: `${pos.market.slug}-NO`,
          marketSlug: pos.market.slug,
          marketTitle: pos.market.title,
          outcomeSide: 'NO',
          balance: pos.positions.no.contractsAmount,
          avgEntryPrice: pos.positions.no.avgPrice,
          currentPrice: pos.latestTrade?.price
            ? String(1 - parseFloat(pos.latestTrade.price))
            : '0.5',
          totalInvested: this.calculateInvested(
            pos.positions.no.contractsAmount,
            pos.positions.no.avgPrice
          ),
          currentValue: pos.positions.no.currentValue,
          unrealizedPnl: pos.positions.no.unrealizedPnl,
          realizedPnl: pos.positions.no.realizedPnl,
          isSettled: pos.market.status === 'resolved',
          tradeType: 'clob',
          lastUpdated: new Date(),
        });
      }
    }

    return unified;
  }

  /**
   * Convert AMM positions to unified format
   */
  private convertAMMPositions(ammPositions: AMMPosition[]): UnifiedPosition[] {
    return ammPositions.map((pos) => ({
      id: `${pos.market.slug}-${pos.outcomeIndex === 0 ? 'YES' : 'NO'}`,
      marketSlug: pos.market.slug,
      marketTitle: pos.market.title,
      outcomeSide: pos.outcomeIndex === 0 ? 'YES' : 'NO',
      balance: pos.outcomeTokenAmount,
      avgEntryPrice: pos.averageFillPrice,
      currentPrice: pos.latestTrade?.outcomeTokenPrice || '0.5',
      totalInvested: pos.totalBuysCost,
      currentValue: pos.collateralAmount,
      unrealizedPnl: pos.unrealizedPnl,
      realizedPnl: pos.realizedPnl,
      isSettled: pos.market.status === 'resolved',
      tradeType: 'amm',
      lastUpdated: new Date(),
    }));
  }

  /**
   * Get all positions in unified format
   *
   * @param sessionCookie - Session cookie
   * @returns Unified positions and summary
   */
  async getUnifiedPositions(
    sessionCookie: string
  ): Promise<{ positions: UnifiedPosition[]; summary: PortfolioSummary }> {
    const response = await this.getPositions(sessionCookie);

    // Convert all position types to unified format
    const clobPositions = this.convertCLOBPositions(response.clob);
    const ammPositions = this.convertAMMPositions(response.amm);

    // Note: Group/NegRisk positions not yet supported (focus on CLOB/AMM markets)

    const allPositions = [...clobPositions, ...ammPositions];

    // Calculate summary
    const summary = this.calculateSummary(allPositions);

    return { positions: allPositions, summary };
  }

  /**
   * Calculate portfolio summary from positions
   */
  private calculateSummary(positions: UnifiedPosition[]): PortfolioSummary {
    let totalValue = 0;
    let totalInvested = 0;
    let totalUnrealizedPnl = 0;
    let totalRealizedPnl = 0;
    const marketSlugs = new Set<string>();

    for (const pos of positions) {
      totalValue += parseFloat(pos.currentValue || '0');
      totalInvested += parseFloat(pos.totalInvested || '0');
      totalUnrealizedPnl += parseFloat(pos.unrealizedPnl || '0');
      totalRealizedPnl += parseFloat(pos.realizedPnl || '0');
      if (!pos.isSettled) {
        marketSlugs.add(pos.marketSlug);
      }
    }

    return {
      totalValue: totalValue.toFixed(6),
      totalInvested: totalInvested.toFixed(6),
      totalUnrealizedPnl: totalUnrealizedPnl.toFixed(6),
      totalRealizedPnl: totalRealizedPnl.toFixed(6),
      positionCount: positions.length,
      activeMarkets: marketSlugs.size,
    };
  }

  /**
   * Calculate invested amount from balance and avg price
   */
  private calculateInvested(balance: string, avgPrice: string): string {
    const balanceNum = parseFloat(balance || '0');
    const priceNum = parseFloat(avgPrice || '0');
    return (balanceNum * priceNum).toFixed(6);
  }

  /**
   * Sync positions from Limitless API to local database
   *
   * @param userId - Database user ID
   * @param sessionCookie - Session cookie
   * @returns Number of positions synced
   */
  async syncPositions(userId: string, sessionCookie: string): Promise<number> {
    const prisma = getPrismaClient();

    // Fetch positions from API
    const { positions } = await this.getUnifiedPositions(sessionCookie);

    // Get current market prices for P&L calculation
    const marketPrices = await this.fetchMarketPrices(
      [...new Set(positions.map((p) => p.marketSlug))]
    );

    let syncCount = 0;

    for (const pos of positions) {
      // Get current price from market data
      const currentPrice = marketPrices.get(pos.marketSlug)?.[pos.outcomeSide.toLowerCase() as 'yes' | 'no'];

      // Calculate unrealized P&L
      const balance = parseFloat(pos.balance);
      const avgEntry = parseFloat(pos.avgEntryPrice);
      const current = currentPrice ?? parseFloat(pos.currentPrice);
      const unrealizedPnl = balance * (current - avgEntry);

      // Upsert position in database
      await prisma.position.upsert({
        where: {
          userId_marketSlug_outcomeSide: {
            userId,
            marketSlug: pos.marketSlug,
            outcomeSide: pos.outcomeSide,
          },
        },
        update: {
          balance: new Decimal(pos.balance),
          avgEntryPrice: new Decimal(pos.avgEntryPrice),
          totalInvested: new Decimal(pos.totalInvested),
          currentPrice: currentPrice ? new Decimal(currentPrice) : new Decimal(pos.currentPrice),
          unrealizedPnl: new Decimal(unrealizedPnl),
          realizedPnl: new Decimal(pos.realizedPnl),
          isSettled: pos.isSettled,
          isOpen: !pos.isSettled && balance > 0,
          updatedAt: new Date(),
        },
        create: {
          userId,
          marketSlug: pos.marketSlug,
          tokenId: pos.id, // Position ID serves as unique token identifier
          outcomeSide: pos.outcomeSide,
          balance: new Decimal(pos.balance),
          avgEntryPrice: new Decimal(pos.avgEntryPrice),
          totalInvested: new Decimal(pos.totalInvested),
          currentPrice: currentPrice ? new Decimal(currentPrice) : new Decimal(pos.currentPrice),
          unrealizedPnl: new Decimal(unrealizedPnl),
          realizedPnl: new Decimal(pos.realizedPnl),
          isSettled: pos.isSettled,
          isOpen: !pos.isSettled && balance > 0,
        },
      });

      syncCount++;
    }

    // Mark positions as closed if they no longer exist in the API response
    const currentPositionKeys = positions.map(
      (p) => `${p.marketSlug}-${p.outcomeSide}`
    );

    await prisma.position.updateMany({
      where: {
        userId,
        isOpen: true,
        NOT: {
          OR: positions.map((p) => ({
            marketSlug: p.marketSlug,
            outcomeSide: p.outcomeSide,
          })),
        },
      },
      data: {
        isOpen: false,
        balance: new Decimal(0),
        updatedAt: new Date(),
      },
    });

    return syncCount;
  }

  /**
   * Fetch current market prices for a list of markets
   */
  private async fetchMarketPrices(
    marketSlugs: string[]
  ): Promise<Map<string, { yes: number; no: number }>> {
    const prices = new Map<string, { yes: number; no: number }>();

    // Fetch prices in parallel (with rate limiting consideration)
    const batchSize = 5;
    for (let i = 0; i < marketSlugs.length; i += batchSize) {
      const batch = marketSlugs.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map((slug) => this.client.getMarket(slug))
      );

      for (let j = 0; j < results.length; j++) {
        const result = results[j];
        const slug = batch[j];

        if (result.status === 'fulfilled') {
          const market = result.value;
          // prices array: [yesPrice, noPrice]
          if (market.prices && market.prices.length >= 2) {
            prices.set(slug, {
              yes: market.prices[0],
              no: market.prices[1],
            });
          }
        }
      }
    }

    return prices;
  }

  /**
   * Get positions from local database
   *
   * @param userId - Database user ID
   * @param activeOnly - Only return open positions (default true)
   * @returns Positions from database
   */
  async getStoredPositions(userId: string, activeOnly: boolean = true) {
    const prisma = getPrismaClient();

    return prisma.position.findMany({
      where: {
        userId,
        ...(activeOnly ? { isOpen: true } : {}),
      },
      orderBy: { updatedAt: 'desc' },
    });
  }

  /**
   * Get position for a specific market and outcome
   *
   * @param userId - Database user ID
   * @param marketSlug - Market slug
   * @param outcomeSide - YES or NO
   */
  async getStoredPosition(userId: string, marketSlug: string, outcomeSide: 'YES' | 'NO') {
    const prisma = getPrismaClient();

    return prisma.position.findUnique({
      where: {
        userId_marketSlug_outcomeSide: {
          userId,
          marketSlug,
          outcomeSide,
        },
      },
    });
  }

  /**
   * Calculate total portfolio value
   *
   * @param userId - Database user ID
   * @returns Portfolio value summary
   */
  async calculatePortfolioValue(userId: string): Promise<PortfolioSummary> {
    const positions = await this.getStoredPositions(userId, true);

    let totalValue = 0;
    let totalInvested = 0;
    let totalUnrealizedPnl = 0;
    let totalRealizedPnl = 0;
    const marketSlugs = new Set<string>();

    for (const pos of positions) {
      const balance = pos.balance.toNumber();
      const currentPrice = pos.currentPrice?.toNumber() || 0;
      const value = balance * currentPrice;

      totalValue += value;
      totalInvested += pos.totalInvested.toNumber();
      totalUnrealizedPnl += pos.unrealizedPnl.toNumber();
      totalRealizedPnl += pos.realizedPnl.toNumber();
      marketSlugs.add(pos.marketSlug);
    }

    return {
      totalValue: totalValue.toFixed(6),
      totalInvested: totalInvested.toFixed(6),
      totalUnrealizedPnl: totalUnrealizedPnl.toFixed(6),
      totalRealizedPnl: totalRealizedPnl.toFixed(6),
      positionCount: positions.length,
      activeMarkets: marketSlugs.size,
    };
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let portfolioServiceInstance: PortfolioService | null = null;

/**
 * Get the singleton PortfolioService instance
 */
export function getPortfolioService(): PortfolioService {
  if (!portfolioServiceInstance) {
    portfolioServiceInstance = new PortfolioService();
  }
  return portfolioServiceInstance;
}
