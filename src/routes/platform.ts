/**
 * Platform Admin REST API Routes for Limitless MCP
 *
 * All routes require x-platform-key header.
 * Platform admins can only access their own users (scoped by platformId).
 *
 * Endpoints:
 * - GET /api/platform/info - Get platform details
 * - GET /api/platform/users - List platform users (paginated, searchable)
 * - GET /api/platform/users/:userId - Get single user details
 * - POST /api/platform/users/:userId/reset-api-key - Reset user's API key
 * - POST /api/platform/users/:userId/revoke-api-keys - Revoke all user's API keys
 * - GET /api/platform/activity - Get activity log
 * - POST /api/platform/regenerate-admin-key - Rotate platform admin key
 * - PATCH /api/platform/contact - Update contact information
 */

import { Router, Request, Response } from 'express';
import {
  platformAuth,
  platformRateLimit,
  platformUserListRateLimit,
} from '../middleware/platformAuth.js';
import { getPlatformService } from '../services/platform.service.js';

const router = Router();

/**
 * Helper to extract user-agent string from request headers
 * Handles the case where user-agent could be string | string[] | undefined
 */
function getUserAgent(req: Request): string | undefined {
  const ua = req.headers['user-agent'];
  if (Array.isArray(ua)) {
    return ua[0];
  }
  return ua;
}

/**
 * Helper to safely extract a param from Express params
 * Express types params as string | string[], but route params are always strings
 */
function getParam(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value[0] || '';
  }
  return value || '';
}

// Apply rate limiting and authentication to all routes
router.use(platformRateLimit);
router.use(platformAuth);

/**
 * GET /api/platform/info
 * Get platform details including user count
 */
router.get('/info', async (req: Request, res: Response) => {
  try {
    const platformService = getPlatformService();
    const platform = await platformService.getPlatformInfo(req.platform!.id);

    // Log activity (fire-and-forget)
    platformService.logActivity(
      req.platform!.id,
      'view_info',
      undefined,
      undefined,
      true,
      undefined,
      req.ip,
      getUserAgent(req)
    ).catch(() => {}); // Ignore logging errors

    res.json({
      success: true,
      platform,
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error getting info:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/platform/users
 * List users (paginated)
 *
 * Query params:
 * - page: Page number (default: 1)
 * - limit: Results per page (default: 20, max: 100)
 * - search: Optional search string for externalId or wallet address
 */
router.get('/users', platformUserListRateLimit, async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const search = req.query.search as string;

    const platformService = getPlatformService();
    const result = await platformService.listPlatformUsers(
      req.platform!.id,
      page,
      limit,
      search
    );

    // Log activity (fire-and-forget)
    platformService.logActivity(
      req.platform!.id,
      'list_users',
      undefined,
      { page, limit, search, resultCount: result.items.length },
      true,
      undefined,
      req.ip,
      getUserAgent(req)
    ).catch(() => {});

    res.json({
      success: true,
      users: result.items,
      pagination: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        totalPages: result.totalPages,
      },
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error listing users:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/platform/users/:userId
 * Get user details
 */
router.get('/users/:userId', async (req: Request, res: Response) => {
  try {
    const userId = getParam(req.params.userId);
    const platformService = getPlatformService();
    const user = await platformService.getPlatformUser(req.platform!.id, userId);

    if (!user) {
      // Log failed attempt
      platformService.logActivity(
        req.platform!.id,
        'view_user',
        userId,
        undefined,
        false,
        'User not found or not owned by platform',
        req.ip,
        getUserAgent(req)
      ).catch(() => {});

      return res.status(404).json({
        success: false,
        error: 'User not found or does not belong to this platform',
      });
    }

    // Log activity
    platformService.logActivity(
      req.platform!.id,
      'view_user',
      userId,
      undefined,
      true,
      undefined,
      req.ip,
      getUserAgent(req)
    ).catch(() => {});

    res.json({
      success: true,
      user,
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error getting user:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/platform/users/:userId/reset-api-key
 * Reset a user's API key (generates new key, invalidates old ones)
 *
 * Body:
 * - keyName: Optional name for the new key
 */
router.post('/users/:userId/reset-api-key', async (req: Request, res: Response) => {
  try {
    const userId = getParam(req.params.userId);
    const { keyName } = req.body;

    const platformService = getPlatformService();
    const result = await platformService.resetUserApiKey(
      req.platform!.id,
      userId,
      keyName,
      req.ip,
      getUserAgent(req)
    );

    res.json({
      success: true,
      credentials: {
        apiKey: result.apiKey,
        apiSecret: result.apiSecret,
        keyPrefix: result.keyPrefix,
      },
      message: 'API key reset successfully. Store these credentials securely - the full key will not be shown again.',
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error resetting API key:', err);

    // Log failed attempt
    const platformService = getPlatformService();
    platformService.logActivity(
      req.platform!.id,
      'reset_api_key',
      getParam(req.params.userId),
      undefined,
      false,
      err.message,
      req.ip,
      getUserAgent(req)
    ).catch(() => {});

    res.status(err.message.includes('not found') ? 404 : 500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/platform/users/:userId/revoke-api-keys
 * Revoke all of a user's API keys
 */
router.post('/users/:userId/revoke-api-keys', async (req: Request, res: Response) => {
  try {
    const userId = getParam(req.params.userId);

    const platformService = getPlatformService();
    const revokedCount = await platformService.revokeUserApiKeys(
      req.platform!.id,
      userId,
      req.ip,
      getUserAgent(req)
    );

    res.json({
      success: true,
      revokedCount,
      message: `Revoked ${revokedCount} API key(s)`,
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error revoking API keys:', err);

    // Log failed attempt
    const platformService = getPlatformService();
    platformService.logActivity(
      req.platform!.id,
      'revoke_api_keys',
      getParam(req.params.userId),
      undefined,
      false,
      err.message,
      req.ip,
      getUserAgent(req)
    ).catch(() => {});

    res.status(err.message.includes('not found') ? 404 : 500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/platform/activity
 * Get activity log
 *
 * Query params:
 * - page: Page number (default: 1)
 * - limit: Results per page (default: 50, max: 200)
 */
router.get('/activity', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);

    const platformService = getPlatformService();
    const result = await platformService.getActivityLog(
      req.platform!.id,
      page,
      limit
    );

    res.json({
      success: true,
      activities: result.items,
      pagination: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        totalPages: result.totalPages,
      },
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error getting activity log:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/platform/regenerate-admin-key
 * Rotate the platform admin key
 * WARNING: This invalidates the current key immediately!
 */
router.post('/regenerate-admin-key', async (req: Request, res: Response) => {
  try {
    const platformService = getPlatformService();
    const credentials = await platformService.regenerateAdminKey(
      req.platform!.id,
      req.ip,
      getUserAgent(req)
    );

    res.json({
      success: true,
      credentials: {
        adminKey: credentials.adminKey,
        adminSecret: credentials.adminSecret,
        keyPrefix: credentials.keyPrefix,
      },
      message:
        'Admin key regenerated. Your old key is now invalid. Store these credentials securely - they will not be shown again.',
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error regenerating admin key:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * PATCH /api/platform/contact
 * Update platform contact information
 *
 * Body:
 * - contactEmail: New contact email (optional)
 * - contactName: New contact name (optional)
 */
router.patch('/contact', async (req: Request, res: Response) => {
  try {
    const { contactEmail, contactName } = req.body;

    // Validate email format if provided
    if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
        message: 'Provide a valid email address',
      });
    }

    // Validate that at least one field is provided
    if (contactEmail === undefined && contactName === undefined) {
      return res.status(400).json({
        success: false,
        error: 'No fields to update',
        message: 'Provide contactEmail and/or contactName to update',
      });
    }

    const platformService = getPlatformService();
    const platform = await platformService.updateContactInfo(
      req.platform!.id,
      contactEmail,
      contactName,
      req.ip,
      getUserAgent(req)
    );

    res.json({
      success: true,
      platform,
      message: 'Contact information updated successfully',
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platform] Error updating contact info:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

export { router as platformRoutes };
export default router;
