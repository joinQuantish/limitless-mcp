/**
 * Platform Admin Authentication Middleware for Limitless MCP
 *
 * Validates x-platform-key header for B2B partner admin access.
 * Platform admins can only access their own users via the /api/platform/* endpoints.
 *
 * Security:
 * - Keys are SHA-256 hashed before lookup (never stored in plaintext)
 * - Platform status is validated (only ACTIVE platforms can authenticate)
 * - Rate limiting prevents brute force attacks
 */

import { Request, Response, NextFunction } from 'express';
import { createHash } from 'crypto';
import rateLimit from 'express-rate-limit';
import { getPrismaClient } from '../db/index.js';

// Platform key prefix for Limitless
const PLATFORM_KEY_PREFIX = 'plt_limitless_';
const KEY_PREFIX_LENGTH = 19; // "plt_limitless_" + 5 chars for identification

// Extend Express Request to include platform info
declare global {
  namespace Express {
    interface Request {
      platform?: {
        id: string;
        name: string;
        slug: string;
        status: string;
        maxUsers: number;
      };
      platformKeyPrefix?: string;
    }
  }
}

/**
 * Hash a platform admin key using SHA-256
 * Used for secure lookup - we NEVER store plaintext keys
 */
function hashPlatformKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/**
 * Middleware to authenticate platform admin requests
 * Requires x-platform-key header matching a valid platform's admin key
 */
export async function platformAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const platformKey = req.headers['x-platform-key'] as string;

    if (!platformKey) {
      res.status(401).json({
        success: false,
        error: 'Platform key required',
        message: 'Provide x-platform-key header with your platform admin key',
      });
      return;
    }

    // Validate key format (plt_limitless_<base64url chars>)
    if (!platformKey.startsWith(PLATFORM_KEY_PREFIX) || platformKey.length < 25) {
      res.status(401).json({
        success: false,
        error: 'Invalid platform key format',
        message: 'Platform key must be in format: plt_limitless_<key>',
      });
      return;
    }

    const keyPrefix = platformKey.slice(0, KEY_PREFIX_LENGTH);
    const keyHash = hashPlatformKey(platformKey);

    const prisma = getPrismaClient();

    // Look up platform by key hash
    const platform = await prisma.platform.findUnique({
      where: { adminKeyHash: keyHash },
    });

    if (!platform) {
      res.status(401).json({
        success: false,
        error: 'Invalid platform key',
        message: 'The provided platform key is not valid',
      });
      return;
    }

    // Check platform status
    if (platform.status === 'SUSPENDED') {
      res.status(403).json({
        success: false,
        error: 'Platform suspended',
        message: 'Your platform access has been temporarily suspended. Contact support.',
      });
      return;
    }

    if (platform.status === 'DEACTIVATED') {
      res.status(403).json({
        success: false,
        error: 'Platform deactivated',
        message: 'Your platform access has been permanently deactivated.',
      });
      return;
    }

    // Attach platform info to request
    req.platform = {
      id: platform.id,
      name: platform.name,
      slug: platform.slug,
      status: platform.status,
      maxUsers: platform.maxUsers,
    };
    req.platformKeyPrefix = keyPrefix;

    next();
  } catch (error) {
    console.error('[PlatformAuth] Error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication error',
      message: 'An error occurred while authenticating your platform key',
    });
  }
}

/**
 * Rate limiting for platform admin endpoints
 * 100 requests per minute for general admin endpoints
 */
export const platformRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: {
    success: false,
    error: 'Rate limit exceeded',
    message: 'Too many requests. Please slow down.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Rate limit by platform ID if authenticated, otherwise by IP
    return req.platform?.id || req.ip || 'unknown';
  },
});

/**
 * Stricter rate limit for user listing (30 req/min)
 * Prevents mass scraping of user data
 */
export const platformUserListRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: {
    success: false,
    error: 'Rate limit exceeded',
    message: 'Too many user list requests. Please slow down.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.platform?.id || req.ip || 'unknown';
  },
});

/**
 * Very strict rate limit for platform registration (5 per hour per IP)
 * Prevents abuse of registration endpoint
 */
export const platformRegistrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: {
    success: false,
    error: 'Too many registration attempts',
    message: 'Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
