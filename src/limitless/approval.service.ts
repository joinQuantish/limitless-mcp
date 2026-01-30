/**
 * Limitless Approval Service
 *
 * Handles token approval checking and setting for trading on Limitless Exchange.
 *
 * Approvals Required for Trading:
 * 1. USDC allowance for venue.exchange (ERC-20 approve)
 * 2. CTF token approval for venue.exchange (ERC-1155 setApprovalForAll)
 * 3. For NegRisk markets: CTF token approval for venue.adapter
 *
 * CRITICAL: Approvals are per-venue! Each market may have a different venue.exchange.
 * Always fetch the venue dynamically from the market before checking/setting approvals.
 *
 * Note: Users pay gas (ETH on Base) for approval transactions.
 */

import { ethers, Contract } from 'ethers';
import { config } from '../config/index.js';
import { getPrismaClient } from '../db/index.js';
import { getBaseWalletService } from '../wallet/base-wallet.service.js';
import { getLimitlessClient, Venue, Market } from './client.js';

// ============================================
// ABI DEFINITIONS
// ============================================

/**
 * ERC-20 ABI for USDC allowance and approval
 */
const ERC20_ABI = [
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
];

/**
 * ERC-1155 ABI for CTF (Conditional Tokens Framework) approval
 * CTF tokens are ERC-1155 representing YES/NO outcomes
 */
const ERC1155_ABI = [
  'function isApprovedForAll(address account, address operator) view returns (bool)',
  'function setApprovalForAll(address operator, bool approved)',
  'function balanceOf(address account, uint256 id) view returns (uint256)',
];

// ============================================
// TYPE DEFINITIONS
// ============================================

/**
 * Approval status for a specific venue
 */
export interface ApprovalStatus {
  /** Is USDC approved for spending by venue.exchange? */
  usdcApproved: boolean;
  /** Current USDC allowance (raw, in 6 decimals) */
  usdcAllowance: string;
  /** Is CTF (ERC-1155) approved for venue.exchange? */
  ctfApproved: boolean;
  /** Is CTF approved for venue.adapter? (only relevant for NegRisk markets) */
  ctfAdapterApproved: boolean;
  /** Are all necessary approvals in place? */
  allApproved: boolean;
  /** The venue these approvals are for */
  venue: Venue;
  /** The market slug (for reference) */
  marketSlug: string;
  /** Is this a NegRisk market? */
  isNegRisk: boolean;
}

/**
 * Result of an approval transaction
 */
export interface ApprovalResult {
  success: boolean;
  txHash?: string;
  gasUsed?: string;
  error?: string;
}

/**
 * All approvals set result
 */
export interface SetApprovalsResult {
  usdcApproval?: ApprovalResult;
  ctfApproval?: ApprovalResult;
  ctfAdapterApproval?: ApprovalResult;
  allSuccessful: boolean;
}

// ============================================
// CONSTANTS
// ============================================

/** Maximum uint256 value for unlimited approval */
export const MAX_UINT256 = ethers.MaxUint256;

/** Minimum USDC allowance to consider "approved" (1M USDC as fallback check) */
const MIN_USDC_ALLOWANCE = BigInt('1000000000000'); // 1M USDC in 6 decimals

/** Retry configuration for RPC calls */
const RETRY_CONFIG = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
};

// ============================================
// RETRY HELPER
// ============================================

async function withRetry<T>(
  fn: () => Promise<T>,
  operation: string,
  maxRetries: number = RETRY_CONFIG.maxRetries
): Promise<T> {
  let lastError: Error | unknown;
  let delay = RETRY_CONFIG.initialDelayMs;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      lastError = error;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check if this is a retryable error
      const isRetryable =
        errorMessage.includes('rate limit') ||
        errorMessage.includes('429') ||
        errorMessage.includes('503') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('ETIMEDOUT') ||
        errorMessage.includes('ECONNRESET') ||
        errorMessage.includes('network') ||
        errorMessage.includes('SERVER_ERROR');

      if (!isRetryable || attempt === maxRetries) {
        throw error;
      }

      console.warn(
        `${operation} failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms: ${errorMessage}`
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
    }
  }

  throw lastError;
}

// ============================================
// APPROVAL SERVICE CLASS
// ============================================

export class LimitlessApprovalService {
  private provider: ethers.JsonRpcProvider | null = null;

  constructor() {}

  /**
   * Get the JSON-RPC provider for Base chain
   */
  private getProvider(): ethers.JsonRpcProvider {
    if (!this.provider) {
      this.provider = new ethers.JsonRpcProvider(config.base.rpcUrl, {
        chainId: config.base.chainId,
        name: 'base',
      });
    }
    return this.provider;
  }

  // ============================================
  // CHECK APPROVALS
  // ============================================

  /**
   * Check USDC allowance for a specific spender (venue.exchange).
   *
   * @param ownerAddress - The wallet address that owns the USDC
   * @param spenderAddress - The venue.exchange address that needs approval
   * @returns Object with approval status and current allowance
   */
  async checkUsdcAllowance(
    ownerAddress: string,
    spenderAddress: string
  ): Promise<{ approved: boolean; allowance: bigint }> {
    const provider = this.getProvider();

    const usdcContract = new Contract(config.tokens.USDC, ERC20_ABI, provider);

    const allowance: bigint = await withRetry(
      () => usdcContract.allowance(ownerAddress, spenderAddress),
      'Check USDC allowance'
    );

    // Approved if unlimited (MaxUint256) or above minimum threshold
    const approved = allowance === MAX_UINT256 || allowance >= MIN_USDC_ALLOWANCE;

    return { approved, allowance };
  }

  /**
   * Check CTF (ERC-1155) approval for a specific operator.
   *
   * @param ownerAddress - The wallet address that owns the CTF tokens
   * @param operatorAddress - The venue.exchange or venue.adapter that needs approval
   * @param ctfContractAddress - The CTF contract address (from market's collateralToken or venue)
   * @returns true if approved
   */
  async checkCtfApproval(
    ownerAddress: string,
    operatorAddress: string,
    ctfContractAddress: string
  ): Promise<boolean> {
    const provider = this.getProvider();

    const ctfContract = new Contract(ctfContractAddress, ERC1155_ABI, provider);

    const isApproved: boolean = await withRetry(
      () => ctfContract.isApprovedForAll(ownerAddress, operatorAddress),
      'Check CTF approval'
    );

    return isApproved;
  }

  /**
   * Check all approvals for a specific market.
   * Fetches the venue dynamically and checks all required approvals.
   *
   * @param userId - User's database ID
   * @param marketSlug - Market slug to check approvals for
   * @returns ApprovalStatus with detailed approval info
   */
  async checkApprovals(userId: string, marketSlug: string): Promise<ApprovalStatus> {
    const walletService = getBaseWalletService();
    const client = getLimitlessClient();

    // Get user's wallet address
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user. Create or import a wallet first.');
    }

    const ownerAddress = walletInfo.address;

    // Get market data with venue (CRITICAL: dynamic per market!)
    const market = await client.getMarket(marketSlug);

    if (!market.venue?.exchange) {
      throw new Error(
        `Market ${marketSlug} does not have a CLOB venue. ` +
          `Trade type: ${market.tradeType}. Only CLOB markets support order placement.`
      );
    }

    const venue = market.venue;
    const isNegRisk = !!(market.groupAddress || market.marketType === 'group-negrisk');

    // Get CTF contract address from market
    // For AMM markets: market.address is the CTF contract
    // For CLOB markets: market.address is null - CTF approval not needed for BUY orders
    const ctfContractAddress = market.address || null;

    // Check USDC allowance for venue.exchange
    const { approved: usdcApproved, allowance } = await this.checkUsdcAllowance(
      ownerAddress,
      venue.exchange
    );

    // Check CTF approval for venue.exchange
    // For CLOB markets without market.address, CTF approval is only needed for SELL orders
    // We'll mark it as approved (true) since we can't check it without the contract address
    let ctfApproved = true;
    if (ctfContractAddress) {
      ctfApproved = await this.checkCtfApproval(ownerAddress, venue.exchange, ctfContractAddress);
    }

    // Check CTF approval for venue.adapter (only for NegRisk markets)
    let ctfAdapterApproved = true; // Default true if no adapter needed
    if (isNegRisk && venue.adapter && ctfContractAddress) {
      ctfAdapterApproved = await this.checkCtfApproval(ownerAddress, venue.adapter, ctfContractAddress);
    }

    // All approved if USDC and CTF are approved (and adapter if NegRisk)
    const allApproved = usdcApproved && ctfApproved && ctfAdapterApproved;

    return {
      usdcApproved,
      usdcAllowance: allowance.toString(),
      ctfApproved,
      ctfAdapterApproved,
      allApproved,
      venue,
      marketSlug,
      isNegRisk,
    };
  }

  /**
   * Check approvals for multiple venues at once.
   * Useful when user might trade on multiple markets.
   *
   * @param userId - User's database ID
   * @param marketSlugs - Array of market slugs to check
   * @returns Map of market slug to ApprovalStatus
   */
  async checkApprovalsForMarkets(
    userId: string,
    marketSlugs: string[]
  ): Promise<Map<string, ApprovalStatus>> {
    const results = new Map<string, ApprovalStatus>();

    // Process in parallel for efficiency
    await Promise.all(
      marketSlugs.map(async (slug) => {
        try {
          const status = await this.checkApprovals(userId, slug);
          results.set(slug, status);
        } catch (error) {
          // Log but don't fail entire batch
          console.warn(`Failed to check approvals for market ${slug}:`, error);
        }
      })
    );

    return results;
  }

  // ============================================
  // SET APPROVALS
  // ============================================

  /**
   * Set USDC approval for a specific spender.
   * User pays gas in ETH.
   *
   * @param userId - User's database ID
   * @param spenderAddress - The venue.exchange address to approve
   * @param amount - Amount to approve (default: MaxUint256 for unlimited)
   * @param password - Password for imported wallets
   * @returns ApprovalResult with transaction details
   */
  async setUsdcApproval(
    userId: string,
    spenderAddress: string,
    amount: bigint = MAX_UINT256,
    password?: string
  ): Promise<ApprovalResult> {
    const walletService = getBaseWalletService();
    const provider = this.getProvider();

    // Get signer
    let signer: ethers.Wallet;
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    if (walletInfo.type === 'imported') {
      if (!password) {
        throw new Error('Password required for imported wallet');
      }
      // Use the private method via the service - we need to get a connected signer
      const baseService = walletService as { getSignerForImportedWallet: (userId: string, password: string) => Promise<ethers.Wallet> };
      signer = await baseService.getSignerForImportedWallet(userId, password);
    } else {
      const baseService = walletService as { getSignerForGeneratedWallet: (userId: string) => Promise<ethers.Wallet> };
      signer = await baseService.getSignerForGeneratedWallet(userId);
    }

    try {
      const usdcContract = new Contract(config.tokens.USDC, ERC20_ABI, signer);

      // Send approval transaction
      const tx = await withRetry(
        () => usdcContract.approve(spenderAddress, amount),
        'Set USDC approval'
      );

      // Wait for confirmation
      const receipt = await tx.wait();

      return {
        success: true,
        txHash: receipt.hash,
        gasUsed: receipt.gasUsed.toString(),
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Set CTF (ERC-1155) approval for a specific operator.
   * User pays gas in ETH.
   *
   * @param userId - User's database ID
   * @param operatorAddress - The venue.exchange or venue.adapter to approve
   * @param ctfContractAddress - The CTF contract address
   * @param approved - Whether to approve (true) or revoke (false)
   * @param password - Password for imported wallets
   * @returns ApprovalResult with transaction details
   */
  async setCtfApproval(
    userId: string,
    operatorAddress: string,
    ctfContractAddress: string,
    approved: boolean = true,
    password?: string
  ): Promise<ApprovalResult> {
    const walletService = getBaseWalletService();

    // Get signer
    let signer: ethers.Wallet;
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    if (walletInfo.type === 'imported') {
      if (!password) {
        throw new Error('Password required for imported wallet');
      }
      const baseService = walletService as { getSignerForImportedWallet: (userId: string, password: string) => Promise<ethers.Wallet> };
      signer = await baseService.getSignerForImportedWallet(userId, password);
    } else {
      const baseService = walletService as { getSignerForGeneratedWallet: (userId: string) => Promise<ethers.Wallet> };
      signer = await baseService.getSignerForGeneratedWallet(userId);
    }

    try {
      const ctfContract = new Contract(ctfContractAddress, ERC1155_ABI, signer);

      // Send setApprovalForAll transaction
      const tx = await withRetry(
        () => ctfContract.setApprovalForAll(operatorAddress, approved),
        'Set CTF approval'
      );

      // Wait for confirmation
      const receipt = await tx.wait();

      return {
        success: true,
        txHash: receipt.hash,
        gasUsed: receipt.gasUsed.toString(),
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Set all required approvals for a specific market.
   * This sets USDC approval and CTF approvals for both venue.exchange and venue.adapter (if NegRisk).
   *
   * @param userId - User's database ID
   * @param marketSlug - Market slug to set approvals for
   * @param force - If true, set approvals even if already approved
   * @param password - Password for imported wallets
   * @returns SetApprovalsResult with all approval transaction results
   */
  async setApprovals(
    userId: string,
    marketSlug: string,
    force: boolean = false,
    password?: string
  ): Promise<SetApprovalsResult> {
    // First check current approval status
    const status = await this.checkApprovals(userId, marketSlug);

    // Get market for CTF contract address
    const client = getLimitlessClient();
    const market = await client.getMarket(marketSlug);
    const ctfContractAddress = market.address || null;

    const result: SetApprovalsResult = {
      allSuccessful: true,
    };

    // Set USDC approval if needed
    if (force || !status.usdcApproved) {
      result.usdcApproval = await this.setUsdcApproval(
        userId,
        status.venue.exchange,
        MAX_UINT256,
        password
      );
      if (!result.usdcApproval.success) {
        result.allSuccessful = false;
      }
    }

    // Set CTF approval for venue.exchange if needed
    // Skip for CLOB markets without a market.address (CTF contract)
    if (ctfContractAddress && (force || !status.ctfApproved)) {
      result.ctfApproval = await this.setCtfApproval(
        userId,
        status.venue.exchange,
        ctfContractAddress,
        true,
        password
      );
      if (!result.ctfApproval.success) {
        result.allSuccessful = false;
      }
    }

    // Set CTF approval for venue.adapter if NegRisk and needed
    if (status.isNegRisk && status.venue.adapter && ctfContractAddress && (force || !status.ctfAdapterApproved)) {
      result.ctfAdapterApproval = await this.setCtfApproval(
        userId,
        status.venue.adapter,
        ctfContractAddress,
        true,
        password
      );
      if (!result.ctfAdapterApproval.success) {
        result.allSuccessful = false;
      }
    }

    return result;
  }

  /**
   * Estimate gas cost for setting approvals.
   * Useful for showing users the expected cost before approving.
   *
   * @param userId - User's database ID
   * @param marketSlug - Market slug to estimate for
   * @returns Estimated gas in ETH as string
   */
  async estimateApprovalGas(userId: string, marketSlug: string): Promise<string> {
    const walletService = getBaseWalletService();
    const provider = this.getProvider();
    const client = getLimitlessClient();

    // Get wallet address
    const walletInfo = await walletService.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    // Get market venue
    const market = await client.getMarket(marketSlug);
    if (!market.venue?.exchange) {
      throw new Error('Market does not support CLOB trading');
    }

    // Check what approvals are needed
    const status = await this.checkApprovals(userId, marketSlug);

    let totalGas = BigInt(0);

    // Estimate USDC approval (~50k gas)
    if (!status.usdcApproved) {
      totalGas += BigInt(50000);
    }

    // Estimate CTF approval (~60k gas)
    if (!status.ctfApproved) {
      totalGas += BigInt(60000);
    }

    // Estimate adapter approval (~60k gas)
    if (status.isNegRisk && status.venue.adapter && !status.ctfAdapterApproved) {
      totalGas += BigInt(60000);
    }

    // Get current gas price
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice || BigInt(1000000000); // 1 gwei fallback

    const totalCost = totalGas * gasPrice;

    return ethers.formatEther(totalCost);
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let approvalServiceInstance: LimitlessApprovalService | null = null;

/**
 * Get the singleton LimitlessApprovalService instance
 */
export function getLimitlessApprovalService(): LimitlessApprovalService {
  if (!approvalServiceInstance) {
    approvalServiceInstance = new LimitlessApprovalService();
  }
  return approvalServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetLimitlessApprovalService(): void {
  approvalServiceInstance = null;
}
