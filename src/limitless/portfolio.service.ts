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
import { ethers, Contract } from 'ethers';
import { getPrismaClient } from '../db/index.js';
import { getLimitlessClient, type Market } from './client.js';
import { getBaseWalletService } from '../wallet/base-wallet.service.js';
import { config } from '../config/index.js';

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

  // ============================================
  // ON-CHAIN POSITION TRACKING
  // ============================================

  private provider: ethers.JsonRpcProvider | null = null;

  private getProvider(): ethers.JsonRpcProvider {
    if (!this.provider) {
      this.provider = new ethers.JsonRpcProvider(config.base.rpcUrl, {
        chainId: config.base.chainId,
        name: 'base',
      });
    }
    return this.provider;
  }

  /**
   * Get on-chain ERC-1155 shares by scanning transfer events on Base.
   * This bypasses the Limitless API and reads directly from the blockchain.
   * Discovers tokens even if the API doesn't track them.
   *
   * @param userId - Database user ID
   * @returns On-chain shares with market mapping
   */
  async getOnChainShares(userId: string): Promise<{
    walletAddress: string;
    shares: Array<{
      tokenId: string;
      balance: string;
      balanceFormatted: number;
      market?: {
        slug: string;
        title: string;
        outcome: 'YES' | 'NO' | 'UNKNOWN';
        currentPrice?: number;
        status?: string;
      };
      inApiPositions: boolean;
    }>;
    totalShares: number;
    note: string;
  }> {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user. Create or import a wallet first.');
    }

    const walletAddress = walletInfo.address;
    const provider = this.getProvider();
    const ctfAddress = config.contracts.CTF;

    const ctfContract = new Contract(ctfAddress, [
      'event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value)',
      'event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values)',
      'function balanceOf(address account, uint256 id) view returns (uint256)',
    ], provider);

    // Base has ~2s block time, 300k blocks ≈ 7 days
    const currentBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, currentBlock - 300000);

    // Collect unique token IDs from transfer events TO this wallet
    const tokenIds = new Set<string>();

    try {
      const singleFilter = ctfContract.filters.TransferSingle(null, null, walletAddress);
      const singleEvents = await ctfContract.queryFilter(singleFilter, fromBlock, currentBlock);
      for (const event of singleEvents) {
        const parsed = event as ethers.EventLog;
        if (parsed.args) {
          tokenIds.add(parsed.args[3].toString()); // id is 4th arg
        }
      }
    } catch (error) {
      console.warn('Error querying TransferSingle events:', error);
    }

    try {
      const batchFilter = ctfContract.filters.TransferBatch(null, null, walletAddress);
      const batchEvents = await ctfContract.queryFilter(batchFilter, fromBlock, currentBlock);
      for (const event of batchEvents) {
        const parsed = event as ethers.EventLog;
        if (parsed.args && parsed.args[3]) {
          for (const id of parsed.args[3]) {
            tokenIds.add(id.toString());
          }
        }
      }
    } catch (error) {
      console.warn('Error querying TransferBatch events:', error);
    }

    // Also check the public API positions for comparison
    let apiTokenIds = new Set<string>();
    try {
      const pubPositions = await this.getPublicPositions(walletAddress);
      if (pubPositions) {
        for (const pos of pubPositions.clob || []) {
          // CLOB positions have tokensBalance with yes/no
          if (pos.market?.slug) {
            const market = await this.client.getMarket(pos.market.slug).catch(() => null);
            if (market?.yesTokenId) apiTokenIds.add(market.yesTokenId);
            if (market?.noTokenId) apiTokenIds.add(market.noTokenId);
          }
        }
      }
    } catch (e) {
      // Ignore API errors - on-chain is the fallback
    }

    // Check current balance for each discovered token ID
    const shares: Array<{
      tokenId: string;
      balance: string;
      balanceFormatted: number;
      market?: {
        slug: string;
        title: string;
        outcome: 'YES' | 'NO' | 'UNKNOWN';
        currentPrice?: number;
        status?: string;
      };
      inApiPositions: boolean;
    }> = [];

    for (const tokenId of tokenIds) {
      try {
        const balance: bigint = await ctfContract.balanceOf(walletAddress, tokenId);
        const balanceFormatted = parseFloat(ethers.formatUnits(balance, 6));

        if (balanceFormatted > 0) {
          // Try to map token ID to a market
          const marketInfo = await this.resolveTokenToMarket(tokenId);

          shares.push({
            tokenId,
            balance: balance.toString(),
            balanceFormatted,
            market: marketInfo || undefined,
            inApiPositions: apiTokenIds.has(tokenId),
          });
        }
      } catch (e) {
        console.warn(`Error checking balance for token ${tokenId}:`, e);
      }
    }

    shares.sort((a, b) => b.balanceFormatted - a.balanceFormatted);

    return {
      walletAddress,
      shares,
      totalShares: shares.length,
      note: shares.length === 0
        ? 'No ERC-1155 outcome tokens found on-chain in the last ~7 days of transfers.'
        : shares.some(s => !s.inApiPositions)
          ? 'Found on-chain shares NOT tracked by the Limitless API! These may be from CLOB fills or transfers.'
          : 'All on-chain shares match API positions.',
    };
  }

  /**
   * Check the on-chain balance of a specific token ID
   *
   * @param userId - Database user ID
   * @param tokenId - The ERC-1155 token ID to check
   * @returns Balance info with market mapping
   */
  async checkTokenBalance(userId: string, tokenId: string): Promise<{
    walletAddress: string;
    tokenId: string;
    balance: string;
    balanceFormatted: number;
    market?: {
      slug: string;
      title: string;
      outcome: 'YES' | 'NO' | 'UNKNOWN';
      currentPrice?: number;
      status?: string;
    };
  }> {
    const walletService = getBaseWalletService();
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user.');
    }

    const provider = this.getProvider();
    const ctfContract = new Contract(config.contracts.CTF, [
      'function balanceOf(address account, uint256 id) view returns (uint256)',
    ], provider);

    const balance: bigint = await ctfContract.balanceOf(walletInfo.address, tokenId);
    const balanceFormatted = parseFloat(ethers.formatUnits(balance, 6));

    const marketInfo = await this.resolveTokenToMarket(tokenId);

    return {
      walletAddress: walletInfo.address,
      tokenId,
      balance: balance.toString(),
      balanceFormatted,
      market: marketInfo || undefined,
    };
  }

  /**
   * Get positions via the PUBLIC API endpoint (no auth required).
   * Fallback for when session cookies fail.
   *
   * @param walletAddress - The wallet address to check
   * @returns Positions response or null on failure
   */
  async getPublicPositions(walletAddress: string): Promise<PortfolioPositionsResponse | null> {
    try {
      const apiUrl = config.limitless.apiUrl;
      const response = await fetch(`${apiUrl}/portfolio/${walletAddress}/positions`);
      if (!response.ok) {
        console.warn(`Public positions API returned ${response.status}`);
        return null;
      }
      return (await response.json()) as PortfolioPositionsResponse;
    } catch (e) {
      console.warn('Failed to fetch public positions:', e);
      return null;
    }
  }

  /**
   * Resolve a token ID to its market information.
   * Searches active markets to find which market this token belongs to.
   */
  private async resolveTokenToMarket(tokenId: string): Promise<{
    slug: string;
    title: string;
    outcome: 'YES' | 'NO' | 'UNKNOWN';
    currentPrice?: number;
    status?: string;
  } | null> {
    try {
      // First check our local cache of known token→market mappings
      const prisma = getPrismaClient();
      const cached = await prisma.position.findFirst({
        where: { tokenId },
        select: { marketSlug: true, outcomeSide: true },
      });

      if (cached) {
        try {
          const market = await this.client.getMarket(cached.marketSlug);
          return {
            slug: cached.marketSlug,
            title: market.title,
            outcome: cached.outcomeSide as 'YES' | 'NO',
            currentPrice: market.prices?.[cached.outcomeSide === 'YES' ? 0 : 1],
            status: market.status,
          };
        } catch {
          // Market might have been removed, fall through
        }
      }

      // Search active markets and check token IDs
      const markets = await this.client.getActiveMarkets(100, 1);
      for (const market of markets) {
        const slug = market.slug || '';
        // Check yesTokenId / noTokenId
        if (market.yesTokenId === tokenId) {
          return {
            slug,
            title: market.title,
            outcome: 'YES',
            currentPrice: market.prices?.[0],
            status: market.status,
          };
        }
        if (market.noTokenId === tokenId) {
          return {
            slug,
            title: market.title,
            outcome: 'NO',
            currentPrice: market.prices?.[1],
            status: market.status,
          };
        }
        // Check tokens array
        if (market.tokens) {
          for (const token of market.tokens) {
            if (token.id === tokenId) {
              const outcome = token.outcome?.toUpperCase() === 'YES' ? 'YES'
                : token.outcome?.toUpperCase() === 'NO' ? 'NO' : 'UNKNOWN';
              return {
                slug,
                title: market.title,
                outcome: outcome as 'YES' | 'NO' | 'UNKNOWN',
                currentPrice: token.price,
                status: market.status,
              };
            }
          }
        }
      }

      // Could not resolve - return null
      return null;
    } catch (e) {
      console.warn(`Failed to resolve token ${tokenId} to market:`, e);
      return null;
    }
  }

  /**
   * Get positions with public API fallback.
   * Tries authenticated endpoint first, falls back to public endpoint.
   *
   * @param sessionCookie - Session cookie (can be empty for fallback)
   * @param walletAddress - Wallet address for public API fallback
   * @returns Positions response
   */
  async getPositionsWithFallback(
    sessionCookie: string | null,
    walletAddress: string
  ): Promise<PortfolioPositionsResponse> {
    // Try authenticated endpoint first
    if (sessionCookie) {
      try {
        return await this.getPositions(sessionCookie);
      } catch (e) {
        console.warn('Authenticated positions failed, trying public endpoint:', e);
      }
    }

    // Fallback to public endpoint
    const pubPositions = await this.getPublicPositions(walletAddress);
    if (pubPositions) {
      return pubPositions;
    }

    // Both failed - return empty
    return { amm: [], clob: [], group: [] };
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
