/**
 * API Key Service for Limitless MCP
 * Handles API key generation, validation, and management
 *
 * Security:
 * - API keys are NEVER stored in plaintext - only SHA-256 hashes
 * - API secrets are encrypted with AES-256-GCM before storage
 * - Timing-safe comparison used for all key/secret validation
 * - Keys can be revoked and have optional expiration
 *
 * Key Format:
 * - API Key: pk_limitless_<24 base64url chars>
 * - API Secret: sk_limitless_<32 base64url chars>
 *
 * The secret is used for optional HMAC request signing by returning users.
 */

import crypto from 'crypto';
import { getPrismaClient } from '../db/index.js';
import { getEncryptionService } from '../crypto/encryption.js';

/**
 * Result of creating a new API key
 * Note: apiKey and apiSecret are ONLY returned once at creation time
 */
export interface ApiKeyResult {
  apiKey: string;        // Full API key (pk_limitless_...) - ONLY shown once
  apiSecret: string;     // Full API secret (sk_limitless_...) - ONLY shown once
  keyPrefix: string;     // First 16 chars for display/identification
  keyId: string;         // Database ID for the key record
}

/**
 * Result of validating an API key
 */
export interface ApiKeyValidation {
  isValid: boolean;
  userId?: string;
  keyId?: string;
  keyRecord?: {
    id: string;
    userId: string;
    keyPrefix: string;
    name: string | null;
    lastUsedAt: Date | null;
    expiresAt: Date | null;
    isActive: boolean;
    createdAt: Date;
  };
  message?: string;
}

/**
 * Summary of an API key (safe to return to users)
 */
export interface ApiKeySummary {
  id: string;
  keyPrefix: string;
  name: string | null;
  isActive: boolean;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
}

/**
 * API Key constants
 */
const API_KEY_PREFIX = 'pk_limitless_';
const API_SECRET_PREFIX = 'sk_limitless_';
const API_KEY_RANDOM_BYTES = 24;  // 24 bytes = 32 base64url chars
const API_SECRET_RANDOM_BYTES = 32;  // 32 bytes = 43 base64url chars
const KEY_PREFIX_LENGTH = 16;  // How much of the key to store for identification

export class ApiKeyService {
  /**
   * Create a new API key for a user
   *
   * @param userId - The user's database ID
   * @param name - Optional friendly name for the key
   * @returns API key result with the full key and secret (ONLY shown once)
   */
  async createApiKey(userId: string, name?: string): Promise<ApiKeyResult> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    // Generate the API key: pk_limitless_<random base64url>
    const keyRandom = crypto.randomBytes(API_KEY_RANDOM_BYTES).toString('base64url');
    const apiKey = `${API_KEY_PREFIX}${keyRandom}`;
    const keyPrefix = apiKey.substring(0, KEY_PREFIX_LENGTH);

    // Generate the API secret: sk_limitless_<random base64url>
    const secretRandom = crypto.randomBytes(API_SECRET_RANDOM_BYTES).toString('base64url');
    const apiSecret = `${API_SECRET_PREFIX}${secretRandom}`;

    // Hash the API key for storage (NEVER store plaintext key)
    const keyHash = this.hashKey(apiKey);

    // Encrypt the secret for storage
    const encryptedSecret = encryption.encrypt(apiSecret);

    // Create the key record
    const keyRecord = await prisma.userApiKey.create({
      data: {
        userId,
        keyHash,
        keyPrefix,
        encryptedSecret,
        name,
        isActive: true,
      },
    });

    return {
      apiKey,
      apiSecret,
      keyPrefix,
      keyId: keyRecord.id,
    };
  }

  /**
   * Validate an API key
   * Used by authentication middleware to verify requests
   *
   * @param apiKey - The full API key to validate
   * @returns Validation result with user ID if valid
   */
  async validateApiKey(apiKey: string): Promise<ApiKeyValidation> {
    const prisma = getPrismaClient();

    // Check key format
    if (!apiKey || !apiKey.startsWith(API_KEY_PREFIX)) {
      return {
        isValid: false,
        message: 'Invalid API key format',
      };
    }

    // Hash the key for lookup
    const keyHash = this.hashKey(apiKey);

    // Find the key record
    const keyRecord = await prisma.userApiKey.findUnique({
      where: { keyHash },
      include: {
        user: {
          select: {
            id: true,
            status: true,
          },
        },
      },
    });

    if (!keyRecord) {
      return {
        isValid: false,
        message: 'API key not found',
      };
    }

    // Check if key is active
    if (!keyRecord.isActive) {
      return {
        isValid: false,
        message: 'API key is inactive',
      };
    }

    // Check if key has expired
    if (keyRecord.expiresAt && keyRecord.expiresAt < new Date()) {
      return {
        isValid: false,
        message: 'API key has expired',
      };
    }

    // Check if user is suspended
    if (keyRecord.user.status === 'SUSPENDED') {
      return {
        isValid: false,
        message: 'User account is suspended',
      };
    }

    // Update last used timestamp (don't await - fire and forget)
    prisma.userApiKey.update({
      where: { id: keyRecord.id },
      data: { lastUsedAt: new Date() },
    }).catch(() => {
      // Ignore errors updating last used - not critical
    });

    return {
      isValid: true,
      userId: keyRecord.userId,
      keyId: keyRecord.id,
      keyRecord: {
        id: keyRecord.id,
        userId: keyRecord.userId,
        keyPrefix: keyRecord.keyPrefix,
        name: keyRecord.name,
        lastUsedAt: keyRecord.lastUsedAt,
        expiresAt: keyRecord.expiresAt,
        isActive: keyRecord.isActive,
        createdAt: keyRecord.createdAt,
      },
    };
  }

  /**
   * Get the decrypted API secret for a key
   * Used for HMAC signature verification
   *
   * @param keyId - The key's database ID
   * @returns The decrypted API secret, or null if not found
   */
  async getApiSecret(keyId: string): Promise<string | null> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const keyRecord = await prisma.userApiKey.findUnique({
      where: { id: keyId },
      select: { encryptedSecret: true },
    });

    if (!keyRecord || !keyRecord.encryptedSecret) {
      return null;
    }

    try {
      return encryption.decrypt(keyRecord.encryptedSecret);
    } catch {
      return null;
    }
  }

  /**
   * Validate an HMAC signature for a request
   * Used for returning user authentication and secure operations
   *
   * Format: HMAC-SHA256(externalId:timestamp, apiSecret)
   *
   * @param apiSecret - The API secret to use for verification
   * @param data - The data that was signed (e.g., "externalId:timestamp")
   * @param signature - The provided signature to verify
   * @param maxAgeMs - Maximum age of the signature in milliseconds (default: 5 minutes)
   * @returns true if signature is valid and within time window
   */
  validateHmacSignature(
    apiSecret: string,
    data: string,
    signature: string,
    maxAgeMs: number = 5 * 60 * 1000
  ): boolean {
    const encryption = getEncryptionService();

    // Parse timestamp from data (expected format: "externalId:timestamp")
    const parts = data.split(':');
    if (parts.length < 2) {
      return false;
    }

    const timestamp = parseInt(parts[parts.length - 1], 10);
    if (isNaN(timestamp)) {
      return false;
    }

    // Check if timestamp is within allowed window
    const now = Date.now();
    if (Math.abs(now - timestamp) > maxAgeMs) {
      return false;
    }

    // Verify the signature
    return encryption.hmacVerify(data, signature, apiSecret);
  }

  /**
   * Create an HMAC signature (for client reference/testing)
   *
   * @param apiSecret - The API secret to use for signing
   * @param data - The data to sign
   * @returns The HMAC-SHA256 signature (hex encoded)
   */
  createHmacSignature(apiSecret: string, data: string): string {
    const encryption = getEncryptionService();
    return encryption.hmacSign(data, apiSecret);
  }

  /**
   * List all API keys for a user
   * Does NOT expose actual keys or secrets
   *
   * @param userId - The user's database ID
   * @returns Array of key summaries
   */
  async listApiKeys(userId: string): Promise<ApiKeySummary[]> {
    const prisma = getPrismaClient();

    const keys = await prisma.userApiKey.findMany({
      where: { userId },
      select: {
        id: true,
        keyPrefix: true,
        name: true,
        isActive: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return keys;
  }

  /**
   * Revoke an API key
   *
   * @param userId - The user's database ID (for authorization)
   * @param keyId - The key's database ID
   * @returns true if key was revoked, false if not found or unauthorized
   */
  async revokeApiKey(userId: string, keyId: string): Promise<boolean> {
    const prisma = getPrismaClient();

    // Verify ownership
    const key = await prisma.userApiKey.findFirst({
      where: {
        id: keyId,
        userId,
      },
    });

    if (!key) {
      return false;
    }

    await prisma.userApiKey.update({
      where: { id: keyId },
      data: { isActive: false },
    });

    return true;
  }

  /**
   * Revoke all API keys for a user
   *
   * @param userId - The user's database ID
   * @returns Number of keys revoked
   */
  async revokeAllApiKeys(userId: string): Promise<number> {
    const prisma = getPrismaClient();

    const result = await prisma.userApiKey.updateMany({
      where: {
        userId,
        isActive: true,
      },
      data: { isActive: false },
    });

    return result.count;
  }

  /**
   * Check if a user has any active API keys
   *
   * @param userId - The user's database ID
   * @returns true if user has at least one active key
   */
  async hasActiveApiKey(userId: string): Promise<boolean> {
    const prisma = getPrismaClient();

    const count = await prisma.userApiKey.count({
      where: {
        userId,
        isActive: true,
      },
    });

    return count > 0;
  }

  /**
   * Get the count of active API keys for a user
   *
   * @param userId - The user's database ID
   * @returns Number of active keys
   */
  async getActiveKeyCount(userId: string): Promise<number> {
    const prisma = getPrismaClient();

    return await prisma.userApiKey.count({
      where: {
        userId,
        isActive: true,
      },
    });
  }

  /**
   * Hash an API key using SHA-256
   * Used for secure storage - we NEVER store plaintext keys
   *
   * @param key - The API key to hash
   * @returns SHA-256 hash (hex encoded)
   */
  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }
}

// Singleton instance
let apiKeyServiceInstance: ApiKeyService | null = null;

/**
 * Get the singleton ApiKeyService instance
 */
export function getApiKeyService(): ApiKeyService {
  if (!apiKeyServiceInstance) {
    apiKeyServiceInstance = new ApiKeyService();
  }
  return apiKeyServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetApiKeyService(): void {
  apiKeyServiceInstance = null;
}
