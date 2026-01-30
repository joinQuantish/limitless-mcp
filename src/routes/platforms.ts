/**
 * Public Platform Registration Routes for Limitless MCP
 *
 * Registration endpoint that requires an access code (no auth required).
 * This is intentionally separate from platform.ts to avoid auth middleware.
 *
 * Endpoints:
 * - POST /api/platforms/register - Register a new platform with access code
 */

import { Router, Request, Response } from 'express';
import { platformRegistrationRateLimit } from '../middleware/platformAuth.js';
import { getPlatformService } from '../services/platform.service.js';

const router = Router();

/**
 * POST /api/platforms/register
 * Register a new platform using an access code
 *
 * Body:
 * - accessCode: Platform registration access code (LMT-XXXX-XXXX-XXXX format) [required]
 * - name: Platform display name [required]
 * - slug: Optional URL-friendly slug (auto-generated from name if not provided)
 * - contactEmail: Optional contact email
 * - contactName: Optional contact name
 *
 * Returns:
 * - Platform info
 * - Admin credentials (ONLY shown once - store securely!)
 * - Usage examples and endpoint list
 */
router.post('/register', platformRegistrationRateLimit, async (req: Request, res: Response) => {
  try {
    const { accessCode, name, slug, contactEmail, contactName } = req.body;

    // Validate access code
    if (!accessCode) {
      return res.status(400).json({
        success: false,
        error: 'Access code required',
        message: 'Provide an access code to register a platform',
      });
    }

    // Validate platform name
    if (!name || name.length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Platform name required',
        message: 'Provide a platform name (minimum 2 characters)',
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        success: false,
        error: 'Name too long',
        message: 'Platform name must be 100 characters or less',
      });
    }

    // Validate slug format if provided
    if (slug && (slug.length < 2 || slug.length > 50)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid slug',
        message: 'Slug must be between 2 and 50 characters',
      });
    }

    if (slug && !/^[a-z0-9-]+$/.test(slug)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid slug format',
        message: 'Slug must contain only lowercase letters, numbers, and hyphens',
      });
    }

    // Validate email format if provided
    if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email',
        message: 'Provide a valid email address',
      });
    }

    const platformService = getPlatformService();
    const result = await platformService.registerPlatform(
      accessCode,
      name,
      slug,
      contactEmail,
      contactName
    );

    console.log(`[Platforms] New platform registered: ${result.platform.name} (${result.platform.slug})`);

    res.status(201).json({
      success: true,
      platform: result.platform,
      credentials: result.credentials,
      usage: {
        header: 'x-platform-key',
        example: `x-platform-key: ${result.credentials.adminKey}`,
        endpoints: {
          info: 'GET /api/platform/info',
          users: 'GET /api/platform/users',
          userDetails: 'GET /api/platform/users/:userId',
          resetApiKey: 'POST /api/platform/users/:userId/reset-api-key',
          revokeApiKeys: 'POST /api/platform/users/:userId/revoke-api-keys',
          activity: 'GET /api/platform/activity',
          regenerateKey: 'POST /api/platform/regenerate-admin-key',
          updateContact: 'PATCH /api/platform/contact',
        },
      },
      message:
        'Platform registered successfully! Store your credentials securely - the admin key will not be shown again.',
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[Platforms] Registration error:', err);

    // Determine appropriate status code based on error message
    let status = 500;
    if (
      err.message.includes('Invalid access code') ||
      err.message.includes('not active') ||
      err.message.includes('expired') ||
      err.message.includes('maximum uses')
    ) {
      status = 400;
    } else if (err.message.includes('not for platform registration')) {
      status = 400;
    } else if (err.message.includes('already taken')) {
      status = 409; // Conflict
    }

    res.status(status).json({
      success: false,
      error: err.message,
    });
  }
});

export { router as platformsRoutes };
export default router;
