/**
 * Authentication Middleware for Limitless MCP
 * Handles API key validation and user context attachment
 *
 * Security features:
 * - Extracts x-api-key header
 * - Validates key against SHA-256 hash in database
 * - Verifies key is active and not expired
 * - Checks user account status (not suspended)
 * - Attaches userId and keyId to request context
 *
 * Two modes:
 * - apiKeyAuth: Required authentication - rejects requests without valid key
 * - optionalAuth: Optional authentication - allows unauthenticated but attaches user if valid
 */

import { Request, Response, NextFunction } from 'express';
import { getApiKeyService, ApiKeyValidation } from '../services/apikey.service.js';

/**
 * Extended Request type with authentication context
 */
export interface AuthenticatedRequest extends Request {
  userId?: string;
  keyId?: string;
  keyRecord?: ApiKeyValidation['keyRecord'];
}

/**
 * API Key Authentication Middleware
 * Validates x-api-key header and sets userId on request
 *
 * Required for protected endpoints - rejects requests without valid API key
 *
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function
 */
export async function apiKeyAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const apiKey = req.headers['x-api-key'] as string | undefined;

    if (!apiKey) {
      res.status(401).json({
        success: false,
        error: 'API key required. Provide x-api-key header.',
      });
      return;
    }

    const apiKeyService = getApiKeyService();
    const validation = await apiKeyService.validateApiKey(apiKey);

    if (!validation.isValid) {
      res.status(401).json({
        success: false,
        error: validation.message || 'Invalid API key',
      });
      return;
    }

    // Attach authentication context to request for downstream use
    (req as AuthenticatedRequest).userId = validation.userId;
    (req as AuthenticatedRequest).keyId = validation.keyId;
    (req as AuthenticatedRequest).keyRecord = validation.keyRecord;

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication error',
    });
  }
}

/**
 * Optional Authentication Middleware
 * Allows unauthenticated requests but attaches userId if valid key provided
 *
 * Useful for endpoints that work differently for authenticated vs anonymous users
 *
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const apiKey = req.headers['x-api-key'] as string | undefined;

    if (apiKey) {
      const apiKeyService = getApiKeyService();
      const validation = await apiKeyService.validateApiKey(apiKey);

      if (validation.isValid) {
        (req as AuthenticatedRequest).userId = validation.userId;
        (req as AuthenticatedRequest).keyId = validation.keyId;
        (req as AuthenticatedRequest).keyRecord = validation.keyRecord;
      }
      // Don't fail on invalid key for optional auth - just don't attach context
    }

    next();
  } catch (error) {
    // Don't fail on optional auth errors - just continue without user context
    console.warn('Optional auth error (non-fatal):', error);
    next();
  }
}

/**
 * Extract user ID from request
 * Helper function for route handlers
 *
 * @param req - Express request object
 * @returns User ID if authenticated, undefined otherwise
 */
export function getUserId(req: Request): string | undefined {
  return (req as AuthenticatedRequest).userId;
}

/**
 * Extract key ID from request
 * Helper function for route handlers
 *
 * @param req - Express request object
 * @returns Key ID if authenticated, undefined otherwise
 */
export function getKeyId(req: Request): string | undefined {
  return (req as AuthenticatedRequest).keyId;
}

/**
 * Check if request is authenticated
 * Helper function for route handlers
 *
 * @param req - Express request object
 * @returns true if request has valid authentication
 */
export function isAuthenticated(req: Request): boolean {
  return !!(req as AuthenticatedRequest).userId;
}

/**
 * Require authentication or throw
 * Helper function that throws if not authenticated
 *
 * @param req - Express request object
 * @returns User ID (throws if not authenticated)
 * @throws Error if request is not authenticated
 */
export function requireUserId(req: Request): string {
  const userId = (req as AuthenticatedRequest).userId;
  if (!userId) {
    throw new Error('Authentication required');
  }
  return userId;
}

export default {
  apiKeyAuth,
  optionalAuth,
  getUserId,
  getKeyId,
  isAuthenticated,
  requireUserId,
};
