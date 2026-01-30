/**
 * Platform Service for Limitless MCP
 *
 * Handles B2B platform registration, management, and user administration.
 * Platform admins can manage their own users without accessing private keys.
 *
 * Key Format:
 * - Platform Admin Key: plt_limitless_<24 base64url chars>
 * - Platform Admin Secret: psk_limitless_<32 base64url chars>
 *
 * Security:
 * - Admin keys are NEVER stored in plaintext - only SHA-256 hashes
 * - Admin secrets are encrypted with AES-256-GCM before storage
 * - Platform data is isolated - platforms cannot access other platforms' users
 */

import crypto from 'crypto';
import { Prisma } from '@prisma/client';
import { getPrismaClient } from '../db/index.js';
import { getEncryptionService } from '../crypto/encryption.js';
import { getApiKeyService } from './apikey.service.js';

// Constants for platform admin keys
const PLATFORM_KEY_PREFIX = 'plt_limitless_';
const PLATFORM_SECRET_PREFIX = 'psk_limitless_';
const PLATFORM_KEY_RANDOM_BYTES = 24; // 24 bytes = 32 base64url chars
const PLATFORM_SECRET_RANDOM_BYTES = 32; // 32 bytes = 43 base64url chars
const KEY_PREFIX_LENGTH = 19; // "plt_limitless_" + 6 chars for identification

/**
 * Platform credentials returned at registration (ONLY shown once)
 */
export interface PlatformCredentials {
  adminKey: string;
  adminSecret: string;
  keyPrefix: string;
}

/**
 * Platform information (safe to return to admins)
 */
export interface PlatformInfo {
  id: string;
  name: string;
  slug: string;
  contactEmail: string | null;
  contactName: string | null;
  status: string;
  maxUsers: number;
  userCount: number;
  createdAt: Date;
}

/**
 * Platform user summary (does NOT expose wallet private keys)
 */
export interface PlatformUser {
  id: string;
  externalId: string;
  walletAddress: string | null;
  importedWalletAddress: string | null;
  status: string;
  createdAt: Date;
  updatedAt: Date;
  apiKeyCount: number;
}

/**
 * Paginated result type
 */
export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/**
 * Activity log entry
 */
export interface PlatformActivityEntry {
  id: string;
  action: string;
  targetUserId: string | null;
  details: unknown;
  success: boolean;
  errorMessage: string | null;
  createdAt: Date;
}

export class PlatformService {
  private encryption = getEncryptionService();
  private apiKeyService = getApiKeyService();

  /**
   * Generate platform admin key
   * Format: plt_limitless_<24 base64url chars>
   */
  private generatePlatformAdminKey(): string {
    const randomBytes = crypto.randomBytes(PLATFORM_KEY_RANDOM_BYTES);
    return `${PLATFORM_KEY_PREFIX}${randomBytes.toString('base64url')}`;
  }

  /**
   * Generate platform admin secret
   * Format: psk_limitless_<32 base64url chars>
   */
  private generatePlatformSecret(): string {
    const randomBytes = crypto.randomBytes(PLATFORM_SECRET_RANDOM_BYTES);
    return `${PLATFORM_SECRET_PREFIX}${randomBytes.toString('base64url')}`;
  }

  /**
   * Hash a platform admin key using SHA-256
   * Used for secure storage - we NEVER store plaintext keys
   */
  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }

  /**
   * Generate URL-friendly slug from platform name
   */
  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 50);
  }

  /**
   * Register a new platform using an access code
   *
   * @param accessCode - Platform registration access code (LMT-XXXX-XXXX-XXXX format)
   * @param name - Platform display name
   * @param slug - Optional URL-friendly slug (auto-generated from name if not provided)
   * @param contactEmail - Optional contact email
   * @param contactName - Optional contact name
   * @returns Platform info and admin credentials (credentials ONLY shown once)
   */
  async registerPlatform(
    accessCode: string,
    name: string,
    slug?: string,
    contactEmail?: string,
    contactName?: string
  ): Promise<{
    platform: PlatformInfo;
    credentials: PlatformCredentials;
  }> {
    const prisma = getPrismaClient();

    // Validate access code
    const code = await prisma.accessCode.findUnique({
      where: { code: accessCode },
    });

    if (!code) {
      throw new Error('Invalid access code');
    }

    if (!code.isActive) {
      throw new Error('Access code is no longer active');
    }

    if (!code.forPlatformRegistration) {
      throw new Error('This access code is not for platform registration');
    }

    if (code.expiresAt && code.expiresAt < new Date()) {
      throw new Error('Access code has expired');
    }

    if (code.maxUses > 0 && code.currentUses >= code.maxUses) {
      throw new Error('Access code has reached maximum uses');
    }

    // Generate or validate slug
    const platformSlug = slug || this.generateSlug(name);

    // Check slug uniqueness
    const existingSlug = await prisma.platform.findUnique({
      where: { slug: platformSlug },
    });
    if (existingSlug) {
      throw new Error(`Platform slug "${platformSlug}" is already taken`);
    }

    // Generate admin credentials
    const adminKey = this.generatePlatformAdminKey();
    const adminSecret = this.generatePlatformSecret();
    const adminKeyHash = this.hashKey(adminKey);
    const adminKeyPrefix = adminKey.slice(0, KEY_PREFIX_LENGTH);
    const encryptedAdminSecret = this.encryption.encrypt(adminSecret);

    // Create platform in a transaction
    const platform = await prisma.$transaction(async (tx) => {
      // Increment access code usage
      await tx.accessCode.update({
        where: { id: code.id },
        data: {
          currentUses: { increment: 1 },
        },
      });

      // Create the platform
      const newPlatform = await tx.platform.create({
        data: {
          name,
          slug: platformSlug,
          adminKeyHash,
          adminKeyPrefix,
          encryptedAdminSecret,
          contactEmail,
          contactName,
          status: 'ACTIVE',
          maxUsers: -1, // Unlimited by default
        },
      });

      // Log the registration activity
      await tx.platformActivityLog.create({
        data: {
          platformId: newPlatform.id,
          action: 'platform_registered',
          details: {
            name,
            slug: platformSlug,
            accessCodeId: code.id,
          },
          success: true,
        },
      });

      return newPlatform;
    });

    return {
      platform: {
        id: platform.id,
        name: platform.name,
        slug: platform.slug,
        contactEmail: platform.contactEmail,
        contactName: platform.contactName,
        status: platform.status,
        maxUsers: platform.maxUsers,
        userCount: 0,
        createdAt: platform.createdAt,
      },
      credentials: {
        adminKey,
        adminSecret,
        keyPrefix: adminKeyPrefix,
      },
    };
  }

  /**
   * Validate a platform admin key
   *
   * @param adminKey - The full platform admin key to validate
   * @returns Platform ID if valid, null otherwise
   */
  async validateAdminKey(adminKey: string): Promise<{
    isValid: boolean;
    platformId?: string;
    platform?: {
      id: string;
      name: string;
      slug: string;
      status: string;
    };
    message?: string;
  }> {
    const prisma = getPrismaClient();

    // Check key format
    if (!adminKey || !adminKey.startsWith(PLATFORM_KEY_PREFIX)) {
      return {
        isValid: false,
        message: 'Invalid platform admin key format',
      };
    }

    // Hash the key for lookup
    const keyHash = this.hashKey(adminKey);

    // Find the platform
    const platform = await prisma.platform.findUnique({
      where: { adminKeyHash: keyHash },
      select: {
        id: true,
        name: true,
        slug: true,
        status: true,
      },
    });

    if (!platform) {
      return {
        isValid: false,
        message: 'Platform admin key not found',
      };
    }

    // Check if platform is active
    if (platform.status !== 'ACTIVE') {
      return {
        isValid: false,
        message: `Platform is ${platform.status.toLowerCase()}`,
      };
    }

    return {
      isValid: true,
      platformId: platform.id,
      platform,
    };
  }

  /**
   * Get platform information
   *
   * @param platformId - Platform database ID
   * @returns Platform info with user count
   */
  async getPlatformInfo(platformId: string): Promise<PlatformInfo> {
    const prisma = getPrismaClient();

    const platform = await prisma.platform.findUnique({
      where: { id: platformId },
      include: {
        _count: {
          select: { users: true },
        },
      },
    });

    if (!platform) {
      throw new Error('Platform not found');
    }

    return {
      id: platform.id,
      name: platform.name,
      slug: platform.slug,
      contactEmail: platform.contactEmail,
      contactName: platform.contactName,
      status: platform.status,
      maxUsers: platform.maxUsers,
      userCount: platform._count.users,
      createdAt: platform.createdAt,
    };
  }

  /**
   * List users for a platform (paginated)
   *
   * @param platformId - Platform database ID
   * @param page - Page number (1-indexed)
   * @param limit - Results per page
   * @param search - Optional search string for externalId or wallet address
   * @returns Paginated list of platform users
   */
  async listPlatformUsers(
    platformId: string,
    page: number = 1,
    limit: number = 20,
    search?: string
  ): Promise<PaginatedResult<PlatformUser>> {
    const prisma = getPrismaClient();
    const skip = (page - 1) * limit;

    // Build where clause - always scoped to platform
    const where: {
      platformId: string;
      OR?: Array<{
        externalId?: { contains: string; mode: 'insensitive' };
        walletAddress?: { contains: string; mode: 'insensitive' };
      }>;
    } = { platformId };

    if (search) {
      where.OR = [
        { externalId: { contains: search, mode: 'insensitive' } },
        { walletAddress: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        select: {
          id: true,
          externalId: true,
          walletAddress: true,
          importedWalletAddress: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          _count: {
            select: { apiKeys: { where: { isActive: true } } },
          },
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.user.count({ where }),
    ]);

    return {
      items: users.map((u) => ({
        id: u.id,
        externalId: u.externalId,
        walletAddress: u.walletAddress,
        importedWalletAddress: u.importedWalletAddress,
        status: u.status,
        createdAt: u.createdAt,
        updatedAt: u.updatedAt,
        apiKeyCount: u._count.apiKeys,
      })),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a specific user's details (platform-scoped)
   *
   * @param platformId - Platform database ID
   * @param userId - User database ID
   * @returns User details or null if not found/not in platform
   */
  async getPlatformUser(
    platformId: string,
    userId: string
  ): Promise<PlatformUser | null> {
    const prisma = getPrismaClient();

    const user = await prisma.user.findFirst({
      where: { id: userId, platformId },
      select: {
        id: true,
        externalId: true,
        walletAddress: true,
        importedWalletAddress: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: { apiKeys: { where: { isActive: true } } },
        },
      },
    });

    if (!user) {
      return null;
    }

    return {
      id: user.id,
      externalId: user.externalId,
      walletAddress: user.walletAddress,
      importedWalletAddress: user.importedWalletAddress,
      status: user.status,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      apiKeyCount: user._count.apiKeys,
    };
  }

  /**
   * Reset a user's API key (generates new key, invalidates all old ones)
   *
   * @param platformId - Platform database ID
   * @param userId - User database ID
   * @param keyName - Optional name for the new key
   * @param ipAddress - Optional IP address for logging
   * @param userAgent - Optional user agent for logging
   * @returns New API key credentials (ONLY shown once)
   */
  async resetUserApiKey(
    platformId: string,
    userId: string,
    keyName?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{
    apiKey: string;
    apiSecret: string;
    keyPrefix: string;
  }> {
    const prisma = getPrismaClient();

    // Verify user belongs to this platform (critical security check)
    const user = await prisma.user.findFirst({
      where: { id: userId, platformId },
    });

    if (!user) {
      throw new Error('User not found or does not belong to this platform');
    }

    // Revoke all existing active keys
    await prisma.userApiKey.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });

    // Create a new API key
    const result = await this.apiKeyService.createApiKey(
      userId,
      keyName || 'Platform Reset Key'
    );

    // Log the activity
    await prisma.platformActivityLog.create({
      data: {
        platformId,
        action: 'reset_api_key',
        targetUserId: userId,
        details: {
          newKeyPrefix: result.keyPrefix,
        },
        ipAddress,
        userAgent,
        success: true,
      },
    });

    return {
      apiKey: result.apiKey,
      apiSecret: result.apiSecret,
      keyPrefix: result.keyPrefix,
    };
  }

  /**
   * Revoke all of a user's API keys
   *
   * @param platformId - Platform database ID
   * @param userId - User database ID
   * @param ipAddress - Optional IP address for logging
   * @param userAgent - Optional user agent for logging
   * @returns Number of keys revoked
   */
  async revokeUserApiKeys(
    platformId: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<number> {
    const prisma = getPrismaClient();

    // Verify user belongs to this platform (critical security check)
    const user = await prisma.user.findFirst({
      where: { id: userId, platformId },
    });

    if (!user) {
      throw new Error('User not found or does not belong to this platform');
    }

    // Revoke all active keys
    const result = await prisma.userApiKey.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });

    // Log the activity
    await prisma.platformActivityLog.create({
      data: {
        platformId,
        action: 'revoke_api_keys',
        targetUserId: userId,
        details: {
          revokedCount: result.count,
        },
        ipAddress,
        userAgent,
        success: true,
      },
    });

    return result.count;
  }

  /**
   * Get platform activity log (paginated)
   *
   * @param platformId - Platform database ID
   * @param page - Page number (1-indexed)
   * @param limit - Results per page
   * @returns Paginated activity log
   */
  async getActivityLog(
    platformId: string,
    page: number = 1,
    limit: number = 50
  ): Promise<PaginatedResult<PlatformActivityEntry>> {
    const prisma = getPrismaClient();
    const skip = (page - 1) * limit;

    const [activities, total] = await Promise.all([
      prisma.platformActivityLog.findMany({
        where: { platformId },
        skip,
        take: limit,
        select: {
          id: true,
          action: true,
          targetUserId: true,
          details: true,
          success: true,
          errorMessage: true,
          createdAt: true,
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.platformActivityLog.count({ where: { platformId } }),
    ]);

    return {
      items: activities,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Regenerate platform admin key
   * Invalidates the old key immediately
   *
   * @param platformId - Platform database ID
   * @param ipAddress - Optional IP address for logging
   * @param userAgent - Optional user agent for logging
   * @returns New admin credentials (ONLY shown once)
   */
  async regenerateAdminKey(
    platformId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<PlatformCredentials> {
    const prisma = getPrismaClient();

    // Generate new credentials
    const adminKey = this.generatePlatformAdminKey();
    const adminSecret = this.generatePlatformSecret();
    const adminKeyHash = this.hashKey(adminKey);
    const adminKeyPrefix = adminKey.slice(0, KEY_PREFIX_LENGTH);
    const encryptedAdminSecret = this.encryption.encrypt(adminSecret);

    // Update platform with new credentials
    await prisma.platform.update({
      where: { id: platformId },
      data: {
        adminKeyHash,
        adminKeyPrefix,
        encryptedAdminSecret,
      },
    });

    // Log the activity
    await prisma.platformActivityLog.create({
      data: {
        platformId,
        action: 'regenerate_admin_key',
        details: {
          newKeyPrefix: adminKeyPrefix,
        },
        ipAddress,
        userAgent,
        success: true,
      },
    });

    return {
      adminKey,
      adminSecret,
      keyPrefix: adminKeyPrefix,
    };
  }

  /**
   * Log a platform activity
   * Used by other services and middleware to record platform-related actions
   *
   * @param platformId - Platform database ID
   * @param action - Action name (e.g., "user_list", "reset_api_key")
   * @param targetUserId - Optional user ID affected by the action
   * @param details - Optional additional details
   * @param success - Whether the action succeeded
   * @param errorMessage - Optional error message if action failed
   * @param ipAddress - Optional IP address
   * @param userAgent - Optional user agent
   */
  async logActivity(
    platformId: string,
    action: string,
    targetUserId?: string,
    details?: Record<string, unknown>,
    success: boolean = true,
    errorMessage?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const prisma = getPrismaClient();

    await prisma.platformActivityLog.create({
      data: {
        platformId,
        action,
        targetUserId,
        details: details ? (details as Prisma.InputJsonValue) : Prisma.JsonNull,
        success,
        errorMessage,
        ipAddress,
        userAgent,
      },
    });
  }

  /**
   * Check if a platform can add more users
   * Respects maxUsers limit (-1 = unlimited)
   *
   * @param platformId - Platform database ID
   * @returns true if platform can add more users
   */
  async canAddUser(platformId: string): Promise<boolean> {
    const prisma = getPrismaClient();

    const platform = await prisma.platform.findUnique({
      where: { id: platformId },
      include: {
        _count: {
          select: { users: true },
        },
      },
    });

    if (!platform) {
      return false;
    }

    // -1 means unlimited users
    if (platform.maxUsers < 0) {
      return true;
    }

    return platform._count.users < platform.maxUsers;
  }

  /**
   * Check if platform is active
   *
   * @param platformId - Platform database ID
   * @returns true if platform status is ACTIVE
   */
  async isActive(platformId: string): Promise<boolean> {
    const prisma = getPrismaClient();

    const platform = await prisma.platform.findUnique({
      where: { id: platformId },
      select: { status: true },
    });

    return platform?.status === 'ACTIVE';
  }

  /**
   * Update platform contact information
   *
   * @param platformId - Platform database ID
   * @param contactEmail - New contact email
   * @param contactName - New contact name
   * @param ipAddress - Optional IP address for logging
   * @param userAgent - Optional user agent for logging
   */
  async updateContactInfo(
    platformId: string,
    contactEmail?: string,
    contactName?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<PlatformInfo> {
    const prisma = getPrismaClient();

    const platform = await prisma.platform.update({
      where: { id: platformId },
      data: {
        ...(contactEmail !== undefined && { contactEmail }),
        ...(contactName !== undefined && { contactName }),
      },
      include: {
        _count: {
          select: { users: true },
        },
      },
    });

    // Log the activity
    await prisma.platformActivityLog.create({
      data: {
        platformId,
        action: 'update_contact_info',
        details: {
          contactEmail: contactEmail ?? 'unchanged',
          contactName: contactName ?? 'unchanged',
        },
        ipAddress,
        userAgent,
        success: true,
      },
    });

    return {
      id: platform.id,
      name: platform.name,
      slug: platform.slug,
      contactEmail: platform.contactEmail,
      contactName: platform.contactName,
      status: platform.status,
      maxUsers: platform.maxUsers,
      userCount: platform._count.users,
      createdAt: platform.createdAt,
    };
  }
}

// Singleton instance
let platformServiceInstance: PlatformService | null = null;

/**
 * Get the singleton PlatformService instance
 */
export function getPlatformService(): PlatformService {
  if (!platformServiceInstance) {
    platformServiceInstance = new PlatformService();
  }
  return platformServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetPlatformService(): void {
  platformServiceInstance = null;
}
