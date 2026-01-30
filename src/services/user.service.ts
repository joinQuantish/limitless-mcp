/**
 * User Service for Limitless MCP
 * Handles user creation, management, and wallet association
 *
 * Features:
 * - Create users with externalId (developer's user identifier)
 * - Generate or import Base wallets
 * - Platform linking for B2B partners
 * - User status tracking (CREATED -> READY)
 * - Session management for Limitless API
 *
 * Security:
 * - ExternalIds are scoped per platform (same externalId can exist across platforms)
 * - Wallets are encrypted at rest
 * - Returning user API key generation requires HMAC signature
 */

import { User, UserStatus, Prisma } from '@prisma/client';
import { getPrismaClient } from '../db/index.js';
import { getBaseWalletService, WalletInfo, WalletImportBundle } from '../wallet/base-wallet.service.js';
import { getApiKeyService, ApiKeyResult } from './apikey.service.js';
import { getEncryptionService } from '../crypto/encryption.js';

/**
 * User creation options
 */
export interface CreateUserOptions {
  externalId: string;
  platformId?: string | null;
  email?: string | null;
  generateWallet?: boolean; // If true, automatically generate wallet on creation
}

/**
 * User signup result (returned to API consumers)
 */
export interface SignupResult {
  userId: string;
  externalId: string;
  platformId: string | null;
  wallet: {
    address: string;
    type: 'generated' | 'imported';
    network: string;
    chainId: number;
  } | null;
  apiKey: string;      // pk_limitless_xxx - ONLY shown once
  apiSecret: string;   // sk_limitless_xxx - ONLY shown once
  status: UserStatus;
}

/**
 * User info (safe to return, no secrets)
 */
export interface UserInfo {
  id: string;
  externalId: string;
  platformId: string | null;
  status: UserStatus;
  wallet: {
    address: string;
    type: 'generated' | 'imported';
    network: string;
    chainId: number;
  } | null;
  hasApiKey: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Full user status including balances
 */
export interface UserStatusInfo extends UserInfo {
  balances?: {
    eth: string;
    usdc: string;
  };
  hasLimitlessSession: boolean;
  sessionExpiry: Date | null;
}

/**
 * User Service
 * Handles user lifecycle from creation through wallet setup
 */
export class UserService {
  /**
   * Create a new user
   * Optionally generates wallet immediately
   *
   * @param options - User creation options
   * @returns User database record
   */
  async createUser(options: CreateUserOptions): Promise<User> {
    const prisma = getPrismaClient();

    // Validate externalId
    if (!options.externalId || typeof options.externalId !== 'string') {
      throw new Error('externalId is required and must be a string');
    }

    // Check if user already exists for this platform + externalId combination
    const existingUser = await prisma.user.findFirst({
      where: {
        externalId: options.externalId,
        platformId: options.platformId || null,
      },
    });

    if (existingUser) {
      throw new Error('User with this externalId already exists');
    }

    // If platformId is provided, validate the platform exists and is active
    if (options.platformId) {
      const platform = await prisma.platform.findUnique({
        where: { id: options.platformId },
      });

      if (!platform) {
        throw new Error('Platform not found');
      }

      if (platform.status !== 'ACTIVE') {
        throw new Error('Platform is not active');
      }

      // Check if platform has hit user limit
      if (platform.maxUsers !== -1) {
        const userCount = await prisma.user.count({
          where: { platformId: options.platformId },
        });
        if (userCount >= platform.maxUsers) {
          throw new Error('Platform has reached maximum user limit');
        }
      }
    }

    // Create the user
    const user = await prisma.user.create({
      data: {
        externalId: options.externalId,
        platformId: options.platformId || null,
        status: 'CREATED',
      },
    });

    // Generate wallet if requested
    if (options.generateWallet) {
      const walletService = getBaseWalletService();
      await walletService.generateWallet(user.id);

      // Fetch updated user with wallet
      const updatedUser = await prisma.user.findUnique({
        where: { id: user.id },
      });

      return updatedUser || user;
    }

    return user;
  }

  /**
   * Full signup flow - create user, generate wallet, create API key
   * This is the primary entry point for new users
   *
   * @param externalId - Developer's user identifier
   * @param platformId - Optional platform ID for B2B partners
   * @param keyName - Optional friendly name for the API key
   * @returns SignupResult with credentials (shown only once)
   */
  async signup(
    externalId: string,
    platformId?: string | null,
    keyName?: string
  ): Promise<SignupResult> {
    const walletService = getBaseWalletService();
    const apiKeyService = getApiKeyService();

    // Create user with wallet
    const user = await this.createUser({
      externalId,
      platformId: platformId || null,
      generateWallet: true,
    });

    // Get wallet info
    const walletInfo = await walletService.getWalletInfo(user.id);

    // Create API key
    const apiKeyResult = await apiKeyService.createApiKey(
      user.id,
      keyName || 'default'
    );

    return {
      userId: user.id,
      externalId: user.externalId,
      platformId: user.platformId,
      wallet: walletInfo
        ? {
            address: walletInfo.address,
            type: walletInfo.type,
            network: 'base',
            chainId: 8453,
          }
        : null,
      apiKey: apiKeyResult.apiKey,
      apiSecret: apiKeyResult.apiSecret,
      status: user.status,
    };
  }

  /**
   * Get user by database ID
   *
   * @param id - User's database ID
   * @returns User or null
   */
  async getUserById(id: string): Promise<User | null> {
    const prisma = getPrismaClient();
    return prisma.user.findUnique({
      where: { id },
    });
  }

  /**
   * Get user by externalId (within a platform scope)
   *
   * @param externalId - Developer's user identifier
   * @param platformId - Platform ID (null for direct Quantish users)
   * @returns User or null
   */
  async getUserByExternalId(
    externalId: string,
    platformId?: string | null
  ): Promise<User | null> {
    const prisma = getPrismaClient();
    return prisma.user.findFirst({
      where: {
        externalId,
        platformId: platformId || null,
      },
    });
  }

  /**
   * Get user info (safe to return to API consumers)
   *
   * @param userId - User's database ID
   * @returns UserInfo or null
   */
  async getUserInfo(userId: string): Promise<UserInfo | null> {
    const prisma = getPrismaClient();
    const walletService = getBaseWalletService();
    const apiKeyService = getApiKeyService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return null;
    }

    const walletInfo = await walletService.getWalletInfo(userId);
    const hasApiKey = await apiKeyService.hasActiveApiKey(userId);

    return {
      id: user.id,
      externalId: user.externalId,
      platformId: user.platformId,
      status: user.status,
      wallet: walletInfo
        ? {
            address: walletInfo.address,
            type: walletInfo.type,
            network: 'base',
            chainId: 8453,
          }
        : null,
      hasApiKey,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  /**
   * Get full user status including balances and session info
   *
   * @param userId - User's database ID
   * @returns UserStatusInfo or null
   */
  async getUserStatus(userId: string): Promise<UserStatusInfo | null> {
    const prisma = getPrismaClient();
    const walletService = getBaseWalletService();
    const apiKeyService = getApiKeyService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return null;
    }

    const walletInfo = await walletService.getWalletInfo(userId);
    const hasApiKey = await apiKeyService.hasActiveApiKey(userId);

    // Get balances if wallet exists
    let balances: { eth: string; usdc: string } | undefined;
    if (walletInfo) {
      try {
        const rawBalances = await walletService.getBalances(walletInfo.address);
        balances = {
          eth: rawBalances.eth,
          usdc: rawBalances.usdc,
        };
      } catch {
        // Ignore balance fetch errors
      }
    }

    // Check session status
    const hasLimitlessSession = Boolean(user.limitlessSession);
    const sessionValid = user.sessionExpiry ? user.sessionExpiry > new Date() : false;

    return {
      id: user.id,
      externalId: user.externalId,
      platformId: user.platformId,
      status: user.status,
      wallet: walletInfo
        ? {
            address: walletInfo.address,
            type: walletInfo.type,
            network: 'base',
            chainId: 8453,
          }
        : null,
      hasApiKey,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      balances,
      hasLimitlessSession: hasLimitlessSession && sessionValid,
      sessionExpiry: user.sessionExpiry,
    };
  }

  /**
   * Setup wallet for an existing user (generates new Base wallet)
   *
   * @param userId - User's database ID
   * @returns WalletInfo with address and type
   */
  async setupWallet(userId: string): Promise<WalletInfo> {
    const walletService = getBaseWalletService();

    // Check if user exists
    const user = await this.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Check if wallet already exists
    const existingWallet = await walletService.getWalletInfo(userId);
    if (existingWallet) {
      throw new Error('User already has a wallet');
    }

    // Generate new wallet
    return walletService.generateWallet(userId);
  }

  /**
   * Import wallet from encrypted bundle
   *
   * @param userId - User's database ID
   * @param bundle - Encrypted wallet bundle from client
   * @returns WalletInfo with address and type
   */
  async importWallet(userId: string, bundle: WalletImportBundle): Promise<WalletInfo> {
    const walletService = getBaseWalletService();

    // Check if user exists
    const user = await this.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Import wallet
    return walletService.importWallet(userId, bundle);
  }

  /**
   * Import wallet from raw private key
   *
   * @param userId - User's database ID
   * @param privateKey - Raw private key (with or without 0x prefix)
   * @returns WalletInfo with address and type
   */
  async importPrivateKey(userId: string, privateKey: string): Promise<WalletInfo> {
    const walletService = getBaseWalletService();

    // Check if user exists
    const user = await this.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Import private key
    return walletService.importPrivateKey(userId, privateKey);
  }

  /**
   * Update user status
   *
   * @param userId - User's database ID
   * @param status - New status
   * @returns Updated user
   */
  async updateStatus(userId: string, status: UserStatus): Promise<User> {
    const prisma = getPrismaClient();

    return prisma.user.update({
      where: { id: userId },
      data: { status },
    });
  }

  /**
   * Suspend a user
   *
   * @param userId - User's database ID
   * @returns Updated user
   */
  async suspendUser(userId: string): Promise<User> {
    return this.updateStatus(userId, 'SUSPENDED');
  }

  /**
   * Reactivate a suspended user
   *
   * @param userId - User's database ID
   * @returns Updated user
   */
  async reactivateUser(userId: string): Promise<User> {
    const prisma = getPrismaClient();
    const walletService = getBaseWalletService();

    // Check if user has wallet to determine correct status
    const walletInfo = await walletService.getWalletInfo(userId);
    const newStatus = walletInfo ? 'READY' : 'CREATED';

    return prisma.user.update({
      where: { id: userId },
      data: { status: newStatus },
    });
  }

  /**
   * Store Limitless API session for a user
   *
   * @param userId - User's database ID
   * @param sessionCookie - Limitless session cookie value
   * @param expiryHours - Session expiry time in hours (default: 24)
   */
  async storeSession(
    userId: string,
    sessionCookie: string,
    expiryHours: number = 24
  ): Promise<void> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const expiry = new Date();
    expiry.setHours(expiry.getHours() + expiryHours);

    // Encrypt session cookie before storage
    const encryptedSession = encryption.encrypt(sessionCookie);

    await prisma.user.update({
      where: { id: userId },
      data: {
        limitlessSession: encryptedSession,
        sessionExpiry: expiry,
      },
    });
  }

  /**
   * Get stored Limitless session for a user
   * Returns null if session doesn't exist or is expired
   *
   * @param userId - User's database ID
   * @returns Session cookie string or null
   */
  async getSession(userId: string): Promise<string | null> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        limitlessSession: true,
        sessionExpiry: true,
      },
    });

    if (!user?.limitlessSession) {
      return null;
    }

    // Check if session is expired
    if (user.sessionExpiry && user.sessionExpiry < new Date()) {
      return null;
    }

    try {
      return encryption.decrypt(user.limitlessSession);
    } catch {
      return null;
    }
  }

  /**
   * Clear stored Limitless session
   *
   * @param userId - User's database ID
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

  /**
   * Check if a user exists
   *
   * @param externalId - Developer's user identifier
   * @param platformId - Platform ID (null for direct Quantish users)
   * @returns true if user exists
   */
  async userExists(
    externalId: string,
    platformId?: string | null
  ): Promise<boolean> {
    const prisma = getPrismaClient();

    const count = await prisma.user.count({
      where: {
        externalId,
        platformId: platformId || null,
      },
    });

    return count > 0;
  }

  /**
   * Request new API key for a returning user
   * Requires HMAC signature for security
   *
   * @param externalId - Developer's user identifier
   * @param platformId - Platform ID (null for direct Quantish users)
   * @param signature - HMAC signature (externalId:timestamp, signed with existing API secret)
   * @param timestamp - Unix timestamp in milliseconds
   * @param keyName - Optional friendly name for the new key
   * @returns New API key result
   */
  async requestApiKeyForReturningUser(
    externalId: string,
    platformId: string | null,
    signature: string,
    timestamp: string,
    keyName?: string
  ): Promise<ApiKeyResult> {
    const prisma = getPrismaClient();
    const apiKeyService = getApiKeyService();

    // Find the user
    const user = await this.getUserByExternalId(externalId, platformId);
    if (!user) {
      throw new Error('User not found');
    }

    // Check if user has any active API keys
    const activeKeys = await prisma.userApiKey.findMany({
      where: {
        userId: user.id,
        isActive: true,
      },
      orderBy: { createdAt: 'desc' },
      take: 1,
    });

    if (activeKeys.length === 0) {
      throw new Error('No active API keys found. Contact support.');
    }

    // Get the API secret for signature verification
    const apiSecret = await apiKeyService.getApiSecret(activeKeys[0].id);
    if (!apiSecret) {
      throw new Error('Could not verify signature. Contact support.');
    }

    // Verify the signature
    const signatureData = `${externalId}:${timestamp}`;
    const isValid = apiKeyService.validateHmacSignature(
      apiSecret,
      signatureData,
      signature
    );

    if (!isValid) {
      throw new Error('Invalid signature or signature expired');
    }

    // Create new API key
    return apiKeyService.createApiKey(user.id, keyName || 'additional-key');
  }

  /**
   * List users for a platform (B2B partner function)
   *
   * @param platformId - Platform ID
   * @param limit - Maximum number of users to return
   * @param offset - Number of users to skip
   * @returns Array of UserInfo
   */
  async listPlatformUsers(
    platformId: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<UserInfo[]> {
    const prisma = getPrismaClient();
    const walletService = getBaseWalletService();
    const apiKeyService = getApiKeyService();

    const users = await prisma.user.findMany({
      where: { platformId },
      take: limit,
      skip: offset,
      orderBy: { createdAt: 'desc' },
    });

    // Map to UserInfo (in parallel for efficiency)
    const userInfos = await Promise.all(
      users.map(async (user) => {
        const walletInfo = await walletService.getWalletInfo(user.id);
        const hasApiKey = await apiKeyService.hasActiveApiKey(user.id);

        return {
          id: user.id,
          externalId: user.externalId,
          platformId: user.platformId,
          status: user.status,
          wallet: walletInfo
            ? {
                address: walletInfo.address,
                type: walletInfo.type,
                network: 'base' as const,
                chainId: 8453,
              }
            : null,
          hasApiKey,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        };
      })
    );

    return userInfos;
  }

  /**
   * Count users for a platform
   *
   * @param platformId - Platform ID
   * @returns User count
   */
  async countPlatformUsers(platformId: string): Promise<number> {
    const prisma = getPrismaClient();

    return prisma.user.count({
      where: { platformId },
    });
  }

  /**
   * Log user activity
   *
   * @param userId - User's database ID
   * @param action - Action type (e.g., "order_placed", "wallet_imported")
   * @param resource - Resource type (e.g., "order", "wallet")
   * @param resourceId - Optional resource ID
   * @param details - Optional additional context
   * @param ipAddress - Optional IP address
   * @param userAgent - Optional user agent string
   */
  async logActivity(
    userId: string,
    action: string,
    resource: string,
    resourceId?: string | null,
    details?: Record<string, unknown> | null,
    ipAddress?: string | null,
    userAgent?: string | null
  ): Promise<void> {
    const prisma = getPrismaClient();

    await prisma.activityLog.create({
      data: {
        userId,
        action,
        resource,
        resourceId: resourceId || null,
        details: details ? (details as Prisma.InputJsonValue) : Prisma.JsonNull,
        ipAddress: ipAddress || null,
        userAgent: userAgent || null,
      },
    });
  }
}

// Singleton instance
let userServiceInstance: UserService | null = null;

/**
 * Get the singleton UserService instance
 */
export function getUserService(): UserService {
  if (!userServiceInstance) {
    userServiceInstance = new UserService();
  }
  return userServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetUserService(): void {
  userServiceInstance = null;
}
