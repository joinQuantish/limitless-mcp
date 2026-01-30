/**
 * Encryption Service for Limitless MCP
 * Uses AES-256-GCM with random IVs for all encryption
 *
 * Security: All private keys and secrets are encrypted at rest using
 * server-side AES-256-GCM encryption with unique random IVs.
 */

import crypto from 'crypto';
import { config } from '../config/index.js';

export class EncryptionService {
  private readonly key: Buffer;
  private readonly algorithm = 'aes-256-gcm';
  private readonly ivLength = 16;
  private readonly authTagLength = 16;

  constructor() {
    if (!config.encryption.key || config.encryption.key.length !== 64) {
      throw new Error('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
    }
    // Validate the key is valid hex
    if (!/^[0-9a-fA-F]{64}$/.test(config.encryption.key)) {
      throw new Error('ENCRYPTION_KEY must contain only hexadecimal characters');
    }
    this.key = Buffer.from(config.encryption.key, 'hex');
  }

  /**
   * Encrypt plaintext using AES-256-GCM with random IV
   * Format: iv:authTag:ciphertext (all hex encoded)
   *
   * @param plaintext - The string to encrypt
   * @returns Encrypted string in format iv:authTag:ciphertext
   */
  encrypt(plaintext: string): string {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv) as crypto.CipherGCM;

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  /**
   * Decrypt ciphertext encrypted with encrypt()
   *
   * @param ciphertext - Encrypted string in format iv:authTag:ciphertext
   * @returns Decrypted plaintext string
   * @throws Error if ciphertext format is invalid or decryption fails
   */
  decrypt(ciphertext: string): string {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid ciphertext format: expected iv:authTag:ciphertext');
    }

    const [ivHex, authTagHex, encryptedHex] = parts;

    // Validate hex strings
    if (ivHex.length !== 32 || !/^[0-9a-fA-F]+$/.test(ivHex)) {
      throw new Error('Invalid IV in ciphertext');
    }
    if (authTagHex.length !== 32 || !/^[0-9a-fA-F]+$/.test(authTagHex)) {
      throw new Error('Invalid auth tag in ciphertext');
    }
    if (!/^[0-9a-fA-F]*$/.test(encryptedHex)) {
      throw new Error('Invalid encrypted data in ciphertext');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Hash a value using SHA-256
   * Used for storing API key hashes (we never store plaintext keys)
   *
   * @param value - The string to hash
   * @returns Hex-encoded SHA-256 hash
   */
  hash(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

  /**
   * Generate a secure random string (hex encoded)
   *
   * @param bytes - Number of random bytes (default 32 = 64 hex chars)
   * @returns Hex-encoded random string
   */
  generateSecureRandom(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Generate a secure random string (base64url encoded)
   * Used for API keys and secrets
   *
   * @param bytes - Number of random bytes
   * @returns Base64url-encoded random string
   */
  generateSecureRandomBase64(bytes: number = 24): string {
    return crypto.randomBytes(bytes).toString('base64url');
  }

  /**
   * Compare two strings in constant time to prevent timing attacks
   *
   * @param a - First string
   * @param b - Second string
   * @returns true if strings are equal
   */
  constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  /**
   * Generate HMAC-SHA256 signature
   * Used for returning user authentication
   *
   * @param data - Data to sign
   * @param secret - HMAC secret key
   * @returns Hex-encoded HMAC signature
   */
  hmacSign(data: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
  }

  /**
   * Verify HMAC-SHA256 signature in constant time
   *
   * @param data - Original data
   * @param signature - Signature to verify
   * @param secret - HMAC secret key
   * @returns true if signature is valid
   */
  hmacVerify(data: string, signature: string, secret: string): boolean {
    const expected = this.hmacSign(data, secret);
    return this.constantTimeCompare(expected, signature);
  }
}

// Singleton instance
let encryptionServiceInstance: EncryptionService | null = null;

/**
 * Get the singleton EncryptionService instance
 * Lazy initialization - only creates instance when first called
 */
export function getEncryptionService(): EncryptionService {
  if (!encryptionServiceInstance) {
    encryptionServiceInstance = new EncryptionService();
  }
  return encryptionServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetEncryptionService(): void {
  encryptionServiceInstance = null;
}
