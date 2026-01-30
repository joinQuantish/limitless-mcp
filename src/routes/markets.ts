/**
 * Market REST API Routes for Limitless MCP
 *
 * Public routes for accessing Limitless market data.
 * No authentication required.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { getLimitlessClient } from '../limitless/client.js';

const router = Router();
const client = getLimitlessClient();

// ============================================
// MARKET LISTING
// ============================================

/**
 * GET /api/markets
 * Get list of active markets
 */
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { limit = '20', page = '1' } = req.query;

    const markets = await client.getActiveMarkets(
      parseInt(limit as string, 10),
      parseInt(page as string, 10)
    );

    res.json({
      success: true,
      count: markets.length,
      data: markets,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/markets/search
 * Search markets by query
 */
router.get('/search', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { q, limit = '20' } = req.query;

    if (!q) {
      res.status(400).json({
        success: false,
        error: 'Query parameter "q" is required',
      });
      return;
    }

    const markets = await client.searchMarkets(
      q as string,
      parseInt(limit as string, 10)
    );

    res.json({
      success: true,
      query: q,
      count: markets.length,
      data: markets,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/markets/categories
 * Get available market categories
 *
 * Note: Limitless API uses /markets/categories/count endpoint
 */
router.get('/categories', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Fetch categories from Limitless API
    const response = await fetch('https://api.limitless.exchange/markets/categories/count');

    if (!response.ok) {
      // Return fallback categories if API fails
      res.json({
        success: true,
        data: {
          note: 'Categories endpoint returned fallback data',
          categories: [
            { name: 'Crypto', count: 0 },
            { name: 'Politics', count: 0 },
            { name: 'Sports', count: 0 },
            { name: 'Entertainment', count: 0 },
            { name: 'Science', count: 0 },
            { name: 'Economics', count: 0 },
          ],
        },
      });
      return;
    }

    const categories = await response.json();

    res.json({
      success: true,
      data: categories,
    });
  } catch (error: unknown) {
    // Return fallback on error
    res.json({
      success: true,
      data: {
        note: 'Categories endpoint not available',
        categories: [
          { name: 'Crypto', count: 0 },
          { name: 'Politics', count: 0 },
          { name: 'Sports', count: 0 },
          { name: 'Entertainment', count: 0 },
          { name: 'Science', count: 0 },
          { name: 'Economics', count: 0 },
        ],
      },
    });
  }
});

// ============================================
// SINGLE MARKET
// ============================================

/**
 * GET /api/markets/:slug
 * Get a specific market by slug
 */
router.get('/:slug', async (req: Request<{ slug: string }>, res: Response, next: NextFunction) => {
  try {
    const { slug } = req.params;

    const market = await client.getMarket(slug);

    if (!market) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    res.json({
      success: true,
      data: market,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    if (message.includes('404') || message.includes('not found')) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    next(error);
  }
});

/**
 * GET /api/markets/:slug/orderbook
 * Get orderbook for a market
 */
router.get('/:slug/orderbook', async (req: Request<{ slug: string }>, res: Response, next: NextFunction) => {
  try {
    const { slug } = req.params;

    const orderbook = await client.getOrderbook(slug);

    // Calculate summary stats
    const bestBid = orderbook.bids[0]?.price || 0;
    const bestAsk = orderbook.asks[0]?.price || 0;
    const spread = bestAsk && bestBid ? bestAsk - bestBid : 0;
    const midPrice = bestAsk && bestBid ? (bestAsk + bestBid) / 2 : bestBid || bestAsk;

    const totalBidSize = orderbook.bids.reduce((sum, b) => sum + b.size, 0);
    const totalAskSize = orderbook.asks.reduce((sum, a) => sum + a.size, 0);

    res.json({
      success: true,
      data: {
        ...orderbook,
        summary: {
          bestBid,
          bestAsk,
          spread,
          spreadPercent: midPrice ? (spread / midPrice) * 100 : 0,
          midPrice,
          totalBidSize,
          totalAskSize,
          bidLevels: orderbook.bids.length,
          askLevels: orderbook.asks.length,
        },
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    if (message.includes('404') || message.includes('not found')) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    next(error);
  }
});

/**
 * GET /api/markets/:slug/price-history
 * Get historical price data for a market
 */
router.get('/:slug/price-history', async (req: Request<{ slug: string }>, res: Response, next: NextFunction) => {
  try {
    const { slug } = req.params;
    const { interval = '1h', limit = '100' } = req.query;

    const history = await client.getHistoricalPrice(
      slug,
      interval as string,
      parseInt(limit as string, 10)
    );

    res.json({
      success: true,
      data: {
        interval,
        count: history.length,
        history,
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    if (message.includes('404') || message.includes('not found')) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    next(error);
  }
});

/**
 * GET /api/markets/:slug/venue
 * Get venue information for a market (for order signing)
 */
router.get('/:slug/venue', async (req: Request<{ slug: string }>, res: Response, next: NextFunction) => {
  try {
    const { slug } = req.params;

    const venue = await client.getVenue(slug);

    res.json({
      success: true,
      data: {
        marketSlug: slug,
        venue,
        note: 'Use venue.exchange as verifyingContract for EIP-712 order signing',
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    if (message.includes('404') || message.includes('not found')) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    if (message.includes('CLOB venue')) {
      res.status(400).json({
        success: false,
        error: 'Not a CLOB market',
        message: 'This market uses AMM trading and does not have a CLOB venue',
      });
      return;
    }

    next(error);
  }
});

/**
 * GET /api/markets/:slug/is-clob
 * Check if a market is a CLOB market (supports order placement)
 */
router.get('/:slug/is-clob', async (req: Request<{ slug: string }>, res: Response, next: NextFunction) => {
  try {
    const { slug } = req.params;

    const isClob = await client.isClobMarket(slug);

    res.json({
      success: true,
      data: {
        marketSlug: slug,
        isClob,
        message: isClob
          ? 'This market supports order placement via CLOB'
          : 'This market uses AMM trading only',
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    if (message.includes('404') || message.includes('not found')) {
      res.status(404).json({
        success: false,
        error: 'Market not found',
      });
      return;
    }

    next(error);
  }
});

export { router as marketsRoutes };
export default router;
