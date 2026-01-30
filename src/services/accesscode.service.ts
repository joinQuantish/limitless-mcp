/**
 * Access Code Service for Limitless MCP
 *
 * Manages access codes for:
 * - SDK registration (new user accounts)
 * - Platform registration (B2B partners)
 *
 * Access codes are single/limited use and can expire.
 * Format: LMT-XXXX-XXXX-XXXX
 */

import { v4 as uuidv4 } from 'uuid';
import { getPrismaClient } from '../db/index.js';

// ============================================
// ACCESS CODE SERVICE
// ============================================

export class AccessCodeService {
  /**
   * Create a new access code
   *
   * @param data - Access code creation options
   * @returns The created access code record
   */
  async createAccessCode(data: {
    developerName?: string;
    developerEmail?: string;
    notes?: string;
    maxUses?: number;
    expiresInDays?: number;
    createdBy: string;
    forPlatformRegistration?: boolean;
  }) {
    const prisma = getPrismaClient();

    // Generate code: LMT-XXXX-XXXX-XXXX
    const randomPart = uuidv4()
      .toUpperCase()
      .replace(/-/g, '')
      .substring(0, 12)
      .match(/.{1,4}/g)
      ?.join('-');

    const code = `LMT-${randomPart}`;

    const expiresAt = data.expiresInDays
      ? new Date(Date.now() + data.expiresInDays * 24 * 60 * 60 * 1000)
      : null;

    const accessCode = await prisma.accessCode.create({
      data: {
        code,
        developerName: data.developerName,
        developerEmail: data.developerEmail,
        notes: data.notes,
        maxUses: data.maxUses || 1,
        expiresAt,
        createdBy: data.createdBy,
        forPlatformRegistration: data.forPlatformRegistration || false,
      },
    });

    return accessCode;
  }

  /**
   * Validate and use an access code
   *
   * Validates that the code:
   * - Exists
   * - Is active
   * - Has not expired
   * - Has not reached max uses
   *
   * If valid, increments the usage count.
   *
   * @param code - The access code to validate
   * @param externalId - The externalId of the user using the code (for logging)
   * @returns Validation result with isValid flag and message
   */
  async validateAndUseAccessCode(
    code: string,
    externalId: string
  ): Promise<{ isValid: boolean; message: string; forPlatformRegistration?: boolean }> {
    const prisma = getPrismaClient();

    const accessCode = await prisma.accessCode.findUnique({
      where: { code },
    });

    if (!accessCode) {
      return { isValid: false, message: 'Invalid access code' };
    }

    if (!accessCode.isActive) {
      return { isValid: false, message: 'Access code is inactive' };
    }

    if (accessCode.expiresAt && accessCode.expiresAt < new Date()) {
      return { isValid: false, message: 'Access code has expired' };
    }

    if (accessCode.maxUses !== -1 && accessCode.currentUses >= accessCode.maxUses) {
      return { isValid: false, message: 'Access code has reached maximum uses' };
    }

    // Increment usage count
    await prisma.accessCode.update({
      where: { id: accessCode.id },
      data: { currentUses: { increment: 1 } },
    });

    return {
      isValid: true,
      message: 'Access code valid',
      forPlatformRegistration: accessCode.forPlatformRegistration,
    };
  }

  /**
   * List all access codes
   *
   * @param options - Filter options
   * @returns Array of access codes
   */
  async listAccessCodes(options?: {
    includeInactive?: boolean;
    forPlatformRegistration?: boolean;
    limit?: number;
    offset?: number;
  }) {
    const prisma = getPrismaClient();

    const where: Record<string, unknown> = {};

    // Filter by active status
    if (!options?.includeInactive) {
      where.isActive = true;
    }

    // Filter by type
    if (options?.forPlatformRegistration !== undefined) {
      where.forPlatformRegistration = options.forPlatformRegistration;
    }

    return prisma.accessCode.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: options?.limit || 100,
      skip: options?.offset || 0,
    });
  }

  /**
   * Get a specific access code by code or ID
   *
   * @param codeOrId - The access code string or database ID
   * @returns The access code record or null
   */
  async getAccessCode(codeOrId: string) {
    const prisma = getPrismaClient();

    return prisma.accessCode.findFirst({
      where: {
        OR: [{ id: codeOrId }, { code: codeOrId }],
      },
    });
  }

  /**
   * Revoke an access code
   *
   * @param codeOrId - The access code string or database ID
   * @returns true if revoked, false if not found
   */
  async revokeAccessCode(codeOrId: string): Promise<boolean> {
    const prisma = getPrismaClient();

    try {
      const accessCode = await prisma.accessCode.findFirst({
        where: {
          OR: [{ id: codeOrId }, { code: codeOrId }],
        },
      });

      if (!accessCode) return false;

      await prisma.accessCode.update({
        where: { id: accessCode.id },
        data: { isActive: false },
      });

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Update an access code
   *
   * @param codeOrId - The access code string or database ID
   * @param data - Fields to update
   * @returns The updated access code or null if not found
   */
  async updateAccessCode(
    codeOrId: string,
    data: {
      developerName?: string;
      developerEmail?: string;
      notes?: string;
      maxUses?: number;
      expiresAt?: Date | null;
      isActive?: boolean;
    }
  ) {
    const prisma = getPrismaClient();

    const accessCode = await this.getAccessCode(codeOrId);
    if (!accessCode) return null;

    return prisma.accessCode.update({
      where: { id: accessCode.id },
      data,
    });
  }

  /**
   * Get usage statistics for access codes
   *
   * @returns Statistics object
   */
  async getStatistics() {
    const prisma = getPrismaClient();

    const [total, active, expired, fullyUsed, platformCodes, userCodes] = await Promise.all([
      prisma.accessCode.count(),
      prisma.accessCode.count({ where: { isActive: true } }),
      prisma.accessCode.count({
        where: {
          expiresAt: { lt: new Date() },
        },
      }),
      prisma.accessCode.count({
        where: {
          maxUses: { not: -1 },
          currentUses: { gte: prisma.accessCode.fields.maxUses },
        },
      }),
      prisma.accessCode.count({ where: { forPlatformRegistration: true } }),
      prisma.accessCode.count({ where: { forPlatformRegistration: false } }),
    ]);

    // For fully used, we need a raw query or separate approach
    const fullyUsedResult = await prisma.$queryRaw<{ count: bigint }[]>`
      SELECT COUNT(*) as count
      FROM "AccessCode"
      WHERE "maxUses" != -1 AND "currentUses" >= "maxUses"
    `;

    return {
      total,
      active,
      expired,
      fullyUsed: Number(fullyUsedResult[0]?.count || 0),
      platformCodes,
      userCodes,
    };
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let accessCodeServiceInstance: AccessCodeService | null = null;

/**
 * Get the singleton AccessCodeService instance
 */
export function getAccessCodeService(): AccessCodeService {
  if (!accessCodeServiceInstance) {
    accessCodeServiceInstance = new AccessCodeService();
  }
  return accessCodeServiceInstance;
}
