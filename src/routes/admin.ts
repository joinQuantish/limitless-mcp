/**
 * Admin Routes for Limitless MCP
 *
 * Internal Quantish admin routes for managing:
 * - Access codes (create, list, revoke)
 * - System statistics
 *
 * All routes require x-admin-key header authentication.
 */

import { Router, Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { getAccessCodeService } from '../services/accesscode.service.js';
import { config } from '../config/index.js';

const router = Router();

// ============================================
// ADMIN AUTHENTICATION MIDDLEWARE
// ============================================

/**
 * Validate x-admin-key header against ADMIN_API_KEY
 */
const adminAuth = (req: Request, res: Response, next: NextFunction): void => {
  const adminKey = req.headers['x-admin-key'] as string;

  if (!config.admin.apiKey) {
    res.status(500).json({
      error: 'Admin API key not configured',
      message: 'Set ADMIN_API_KEY environment variable',
    });
    return;
  }

  if (!adminKey || adminKey !== config.admin.apiKey) {
    res.status(401).json({ error: 'Invalid admin API key' });
    return;
  }

  next();
};

// Apply admin auth to all routes
router.use(adminAuth);

// Rate limiting for admin routes (more generous than public)
const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Admin rate limit exceeded' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.use(adminLimiter);

// ============================================
// ACCESS CODE MANAGEMENT
// ============================================

/**
 * POST /api/admin/access-codes
 * Create a new access code
 */
router.post('/access-codes', async (req: Request, res: Response) => {
  try {
    const {
      developerName,
      developerEmail,
      notes,
      maxUses,
      expiresInDays,
      forPlatformRegistration,
    } = req.body;

    const accessCodeService = getAccessCodeService();
    const accessCode = await accessCodeService.createAccessCode({
      developerName,
      developerEmail,
      notes,
      maxUses: maxUses || 1,
      expiresInDays,
      createdBy: 'admin',
      forPlatformRegistration: forPlatformRegistration || false,
    });

    res.status(201).json({
      success: true,
      accessCode,
      message: forPlatformRegistration
        ? 'Platform access code created. Share this with the B2B partner.'
        : 'Access code created. Share this with the developer.',
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to create access code', message });
  }
});

/**
 * POST /api/admin/access-codes/bulk
 * Create multiple access codes at once
 */
router.post('/access-codes/bulk', async (req: Request, res: Response) => {
  try {
    const { count = 10, ...options } = req.body;

    if (count < 1 || count > 100) {
      res.status(400).json({
        error: 'Invalid count',
        message: 'Count must be between 1 and 100',
      });
      return;
    }

    const accessCodeService = getAccessCodeService();
    const codes = [];

    for (let i = 0; i < count; i++) {
      const code = await accessCodeService.createAccessCode({
        ...options,
        createdBy: 'admin',
      });
      codes.push(code);
    }

    res.status(201).json({
      success: true,
      count: codes.length,
      accessCodes: codes,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to create access codes', message });
  }
});

/**
 * GET /api/admin/access-codes
 * List all access codes
 */
router.get('/access-codes', async (req: Request, res: Response) => {
  try {
    const {
      includeInactive,
      forPlatformRegistration,
      limit,
      offset,
    } = req.query;

    const accessCodeService = getAccessCodeService();
    const codes = await accessCodeService.listAccessCodes({
      includeInactive: includeInactive === 'true',
      forPlatformRegistration:
        forPlatformRegistration === undefined
          ? undefined
          : forPlatformRegistration === 'true',
      limit: limit ? parseInt(limit as string, 10) : undefined,
      offset: offset ? parseInt(offset as string, 10) : undefined,
    });

    res.json({
      success: true,
      count: codes.length,
      accessCodes: codes,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to list access codes', message });
  }
});

/**
 * GET /api/admin/access-codes/stats
 * Get access code statistics
 */
router.get('/access-codes/stats', async (req: Request, res: Response) => {
  try {
    const accessCodeService = getAccessCodeService();
    const stats = await accessCodeService.getStatistics();

    res.json({
      success: true,
      statistics: stats,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to get statistics', message });
  }
});

/**
 * GET /api/admin/access-codes/:codeOrId
 * Get a specific access code
 */
router.get('/access-codes/:codeOrId', async (req: Request<{ codeOrId: string }>, res: Response) => {
  try {
    const { codeOrId } = req.params;

    const accessCodeService = getAccessCodeService();
    const accessCode = await accessCodeService.getAccessCode(codeOrId);

    if (!accessCode) {
      res.status(404).json({ error: 'Access code not found' });
      return;
    }

    res.json({
      success: true,
      accessCode,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to get access code', message });
  }
});

/**
 * PATCH /api/admin/access-codes/:codeOrId
 * Update an access code
 */
router.patch('/access-codes/:codeOrId', async (req: Request<{ codeOrId: string }>, res: Response) => {
  try {
    const { codeOrId } = req.params;
    const { developerName, developerEmail, notes, maxUses, expiresAt, isActive } =
      req.body;

    const accessCodeService = getAccessCodeService();
    const accessCode = await accessCodeService.updateAccessCode(codeOrId, {
      developerName,
      developerEmail,
      notes,
      maxUses,
      expiresAt: expiresAt ? new Date(expiresAt) : undefined,
      isActive,
    });

    if (!accessCode) {
      res.status(404).json({ error: 'Access code not found' });
      return;
    }

    res.json({
      success: true,
      accessCode,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to update access code', message });
  }
});

/**
 * DELETE /api/admin/access-codes/:codeOrId
 * Revoke an access code
 */
router.delete('/access-codes/:codeOrId', async (req: Request<{ codeOrId: string }>, res: Response) => {
  try {
    const { codeOrId } = req.params;

    const accessCodeService = getAccessCodeService();
    const success = await accessCodeService.revokeAccessCode(codeOrId);

    if (!success) {
      res.status(404).json({ error: 'Access code not found' });
      return;
    }

    res.json({
      success: true,
      message: 'Access code revoked',
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to revoke access code', message });
  }
});

// ============================================
// SYSTEM STATISTICS
// ============================================

/**
 * GET /api/admin/stats
 * Get system-wide statistics
 */
router.get('/stats', async (req: Request, res: Response) => {
  try {
    const { getPrismaClient } = await import('../db/index.js');
    const prisma = getPrismaClient();

    const [
      totalUsers,
      activeUsers,
      suspendedUsers,
      readyUsers,
      totalOrders,
      totalPositions,
      totalPlatforms,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { status: 'READY' } }),
      prisma.user.count({ where: { status: 'SUSPENDED' } }),
      prisma.user.count({ where: { status: 'READY' } }),
      prisma.order.count(),
      prisma.position.count(),
      prisma.platform.count(),
    ]);

    const accessCodeService = getAccessCodeService();
    const accessCodeStats = await accessCodeService.getStatistics();

    res.json({
      success: true,
      statistics: {
        users: {
          total: totalUsers,
          active: activeUsers,
          suspended: suspendedUsers,
          ready: readyUsers,
        },
        orders: {
          total: totalOrders,
        },
        positions: {
          total: totalPositions,
        },
        platforms: {
          total: totalPlatforms,
        },
        accessCodes: accessCodeStats,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to get statistics', message });
  }
});

export { router as adminRoutes };
export default router;
