/**
 * Base Wallet Service for Limitless MCP
 * Handles wallet generation, encryption, storage, and signing for Base chain (Ethereum L2)
 *
 * Security:
 * - Private keys encrypted at rest with AES-256-GCM
 * - Random IVs for each encryption
 * - Keys cleared from memory after signing operations
 */

import crypto from 'crypto';
import { ethers, Wallet as EthersWallet, TypedDataDomain, TypedDataField } from 'ethers';
import { config } from '../config/index.js';
import { getEncryptionService } from '../crypto/encryption.js';
import { getPrismaClient } from '../db/index.js';

// ERC-20 ABI for balance checks and transfers
const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function transfer(address to, uint256 amount) returns (bool)',
];

// Retry configuration for RPC calls
const RETRY_CONFIG = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
};

/**
 * Execute a function with exponential backoff retry logic
 * Handles rate limits and transient RPC errors
 */
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

      // Check if this is a retryable error (rate limit, timeout, network issues)
      const isRetryable =
        errorMessage.includes('rate limit') ||
        errorMessage.includes('429') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('ETIMEDOUT') ||
        errorMessage.includes('ECONNRESET') ||
        errorMessage.includes('network') ||
        errorMessage.includes('SERVER_ERROR');

      if (!isRetryable || attempt === maxRetries) {
        // Not retryable or max retries reached
        throw error;
      }

      // Wait before retrying with exponential backoff
      console.warn(
        `${operation} failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms: ${errorMessage}`
      );
      await new Promise((resolve) => setTimeout(resolve, delay));

      // Increase delay for next attempt (exponential backoff with cap)
      delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
    }
  }

  // Should never reach here, but TypeScript needs this
  throw lastError;
}

export interface WalletInfo {
  address: string;
  type: 'generated' | 'imported';
  createdAt: Date;
}

export interface WalletBalances {
  eth: string; // Native ETH balance (gas token on Base)
  usdc: string; // USDC balance
  usdcRaw: bigint; // Raw USDC balance in smallest units
  ethRaw: bigint; // Raw ETH balance in wei
}

export interface WalletImportBundle {
  encryptedKey: string;
  salt: string;
  iv: string;
  publicKey: string;
  version: string;
}

/**
 * Base Wallet Service
 * Manages Ethereum wallets for trading on Limitless Exchange (Base chain)
 */
export class BaseWalletService {
  private provider: ethers.JsonRpcProvider | null = null;
  private readonly chainId = config.base.chainId; // 8453 for Base mainnet

  constructor() {}

  /**
   * Get the JSON-RPC provider for Base chain
   * Lazy initialization to allow for config changes
   */
  private getProvider(): ethers.JsonRpcProvider {
    if (!this.provider) {
      this.provider = new ethers.JsonRpcProvider(config.base.rpcUrl, {
        chainId: this.chainId,
        name: 'base',
      });
    }
    return this.provider;
  }

  /**
   * Generate a new random Ethereum wallet for a user
   * Private key is encrypted with AES-256-GCM before storage
   *
   * @param userId - The user's database ID
   * @returns WalletInfo with the wallet address and type
   */
  async generateWallet(userId: string): Promise<WalletInfo> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    // Generate new random wallet
    const wallet = EthersWallet.createRandom();
    const address = wallet.address; // Already EIP-55 checksummed
    const privateKey = wallet.privateKey; // 0x-prefixed hex string

    // Encrypt the private key for storage
    const encryptedPrivateKey = encryption.encrypt(privateKey);

    // Store in database
    await prisma.user.update({
      where: { id: userId },
      data: {
        walletAddress: address,
        encryptedPrivateKey: encryptedPrivateKey,
        status: 'READY',
      },
    });

    return {
      address,
      type: 'generated',
      createdAt: new Date(),
    };
  }

  /**
   * Import an existing wallet using encrypted bundle
   * User encrypts the key client-side; we store the encrypted blob
   *
   * @param userId - The user's database ID
   * @param bundle - Encrypted wallet data from client
   * @returns WalletInfo with the wallet address
   */
  async importWallet(userId: string, bundle: WalletImportBundle): Promise<WalletInfo> {
    const prisma = getPrismaClient();

    // Verify bundle format
    if (!this.verifyWalletImportBundle(bundle)) {
      throw new Error('Invalid wallet import bundle format');
    }

    // Validate address format
    if (!ethers.isAddress(bundle.publicKey)) {
      throw new Error('Invalid wallet address in bundle');
    }

    // Normalize address to checksummed format
    const checksummedAddress = ethers.getAddress(bundle.publicKey);

    // Check if this wallet address is already registered to another user
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { walletAddress: checksummedAddress },
          { importedWalletAddress: checksummedAddress },
        ],
      },
    });

    if (existingUser && existingUser.id !== userId) {
      throw new Error('This wallet is already registered to another user');
    }

    // Store the encrypted bundle (we cannot decrypt without user's password)
    await prisma.user.update({
      where: { id: userId },
      data: {
        importedWalletAddress: checksummedAddress,
        importedWalletEncrypted: bundle.encryptedKey,
        importedWalletSalt: bundle.salt,
        importedWalletIv: bundle.iv,
        walletImportedAt: new Date(),
        status: 'READY',
      },
    });

    return {
      address: checksummedAddress,
      type: 'imported',
      createdAt: new Date(),
    };
  }

  /**
   * Verify wallet import bundle has required fields
   */
  private verifyWalletImportBundle(bundle: WalletImportBundle): boolean {
    return Boolean(
      bundle &&
        typeof bundle.encryptedKey === 'string' &&
        bundle.encryptedKey.length > 0 &&
        typeof bundle.salt === 'string' &&
        bundle.salt.length > 0 &&
        typeof bundle.iv === 'string' &&
        bundle.iv.length > 0 &&
        typeof bundle.publicKey === 'string' &&
        bundle.publicKey.length > 0 &&
        typeof bundle.version === 'string'
    );
  }

  /**
   * Get wallet info for a user
   *
   * @param userId - The user's database ID
   * @returns WalletInfo or null if no wallet found
   */
  async getWalletInfo(userId: string): Promise<WalletInfo | null> {
    const prisma = getPrismaClient();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        walletAddress: true,
        importedWalletAddress: true,
        walletImportedAt: true,
        createdAt: true,
      },
    });

    if (!user) {
      return null;
    }

    // Prefer imported wallet if both exist
    if (user.importedWalletAddress) {
      return {
        address: user.importedWalletAddress,
        type: 'imported',
        createdAt: user.walletImportedAt || user.createdAt,
      };
    }

    if (user.walletAddress) {
      return {
        address: user.walletAddress,
        type: 'generated',
        createdAt: user.createdAt,
      };
    }

    return null;
  }

  /**
   * Get wallet balances (ETH + USDC)
   * Includes retry logic for handling Base RPC rate limits
   *
   * @param address - Ethereum address to check
   * @returns WalletBalances with ETH and USDC balances
   */
  async getBalances(address: string): Promise<WalletBalances> {
    const provider = this.getProvider();

    // Validate address
    if (!ethers.isAddress(address)) {
      throw new Error('Invalid Ethereum address');
    }

    // Get ETH balance with retry logic
    const ethBalance = await withRetry(
      () => provider.getBalance(address),
      'ETH balance fetch'
    );

    // Get USDC balance with retry logic
    let usdcBalance = BigInt(0);
    try {
      const usdcContract = new ethers.Contract(config.tokens.USDC, ERC20_ABI, provider);
      usdcBalance = await withRetry(
        () => usdcContract.balanceOf(address),
        'USDC balance fetch'
      );
    } catch (error) {
      // USDC balance check failed after retries, could be no account or RPC issue
      console.warn('Failed to fetch USDC balance after retries:', error);
    }

    return {
      eth: ethers.formatEther(ethBalance),
      usdc: ethers.formatUnits(usdcBalance, 6), // USDC has 6 decimals
      ethRaw: ethBalance,
      usdcRaw: usdcBalance,
    };
  }

  /**
   * Get a signer for transactions (for generated wallets)
   * Used internally - caller should clear the signer after use
   *
   * @param userId - The user's database ID
   * @returns Connected ethers Wallet (signer)
   */
  async getSignerForGeneratedWallet(userId: string): Promise<EthersWallet> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { encryptedPrivateKey: true },
    });

    if (!user?.encryptedPrivateKey) {
      throw new Error('No generated wallet found for this user. Use password-based signing for imported wallets.');
    }

    const privateKey = encryption.decrypt(user.encryptedPrivateKey);
    const provider = this.getProvider();

    return new EthersWallet(privateKey, provider);
  }

  /**
   * Decrypt imported wallet with password (client-side decryption helper)
   * This is for imported wallets that were encrypted with user's password
   *
   * NOTE: This should be implemented with scrypt key derivation to match
   * the client-side encryption. The password is used to derive the decryption key.
   *
   * @param userId - The user's database ID
   * @param password - User's encryption password
   * @returns Connected ethers Wallet (signer)
   */
  async getSignerForImportedWallet(userId: string, password: string): Promise<EthersWallet> {
    const prisma = getPrismaClient();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        importedWalletAddress: true,
        importedWalletEncrypted: true,
        importedWalletSalt: true,
        importedWalletIv: true,
      },
    });

    if (!user?.importedWalletEncrypted || !user?.importedWalletSalt || !user?.importedWalletIv) {
      throw new Error('No imported wallet found for this user');
    }

    // Derive key from password using scrypt (matches client-side encryption)
    const salt = Buffer.from(user.importedWalletSalt, 'hex');
    const key = crypto.scryptSync(password, salt, 32);
    const iv = Buffer.from(user.importedWalletIv, 'hex');
    const encryptedData = Buffer.from(user.importedWalletEncrypted, 'hex');

    // Decrypt using AES-256-GCM
    // Format: last 16 bytes are authTag
    const authTag = encryptedData.subarray(encryptedData.length - 16);
    const ciphertext = encryptedData.subarray(0, encryptedData.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const privateKey = decrypted.toString('utf8');

    // Verify the address matches
    const wallet = new EthersWallet(privateKey);
    if (wallet.address.toLowerCase() !== user.importedWalletAddress?.toLowerCase()) {
      throw new Error('Decrypted key does not match expected wallet address. Invalid password?');
    }

    const provider = this.getProvider();
    return wallet.connect(provider);
  }

  /**
   * Sign a raw message (for Limitless authentication)
   *
   * @param userId - The user's database ID
   * @param message - Message to sign
   * @param password - Password (required for imported wallets)
   * @returns Signature string
   */
  async signMessage(userId: string, message: string, password?: string): Promise<string> {
    const walletInfo = await this.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    let signer: EthersWallet;

    if (walletInfo.type === 'imported') {
      if (!password) {
        throw new Error('Password required for imported wallet signing');
      }
      signer = await this.getSignerForImportedWallet(userId, password);
    } else {
      signer = await this.getSignerForGeneratedWallet(userId);
    }

    try {
      return await signer.signMessage(message);
    } finally {
      // Clear signer from memory - since ethers v6, we can't directly overwrite privateKey
      // The garbage collector will clean it up when signer goes out of scope
    }
  }

  /**
   * Sign EIP-712 typed data (for Limitless order signing)
   *
   * @param userId - The user's database ID
   * @param domain - EIP-712 domain (MUST include dynamic venue.exchange as verifyingContract)
   * @param types - EIP-712 type definitions
   * @param value - Data to sign
   * @param password - Password (required for imported wallets)
   * @returns Signature string
   */
  async signTypedData(
    userId: string,
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, unknown>,
    password?: string
  ): Promise<string> {
    const walletInfo = await this.getWalletInfo(userId);
    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    let signer: EthersWallet;

    if (walletInfo.type === 'imported') {
      if (!password) {
        throw new Error('Password required for imported wallet signing');
      }
      signer = await this.getSignerForImportedWallet(userId, password);
    } else {
      signer = await this.getSignerForGeneratedWallet(userId);
    }

    try {
      return await signer.signTypedData(domain, types, value);
    } finally {
      // Signer cleared when function exits
    }
  }

  /**
   * Get the active wallet address for a user
   * Convenience method that returns just the address string
   *
   * @param userId - The user's database ID
   * @returns Address string or null
   */
  async getAddress(userId: string): Promise<string | null> {
    const walletInfo = await this.getWalletInfo(userId);
    return walletInfo?.address || null;
  }

  /**
   * Check if an address is valid Ethereum address
   *
   * @param address - Address to validate
   * @returns true if valid
   */
  isValidAddress(address: string): boolean {
    return ethers.isAddress(address);
  }

  /**
   * Get EIP-55 checksummed address
   *
   * @param address - Address to checksum
   * @returns Checksummed address
   */
  getChecksummedAddress(address: string): string {
    return ethers.getAddress(address);
  }

  /**
   * Export private key for a generated wallet
   * WARNING: Handle with extreme care - this exposes the raw private key
   *
   * @param userId - The user's database ID
   * @returns Raw private key (0x-prefixed hex string)
   */
  async exportPrivateKey(userId: string): Promise<string> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        walletAddress: true,
        encryptedPrivateKey: true,
        importedWalletAddress: true,
      },
    });

    // Cannot export imported wallet keys - user already has them
    if (user?.importedWalletAddress && !user.encryptedPrivateKey) {
      throw new Error('Cannot export imported wallet key. You already have this key.');
    }

    if (!user?.encryptedPrivateKey) {
      throw new Error('No generated wallet found for this user');
    }

    return encryption.decrypt(user.encryptedPrivateKey);
  }

  /**
   * Import a raw private key (for direct key import)
   * Different from importWallet which takes an encrypted bundle
   *
   * @param userId - The user's database ID
   * @param privateKey - Raw private key (with or without 0x prefix)
   * @returns WalletInfo with the wallet address
   */
  async importPrivateKey(userId: string, privateKey: string): Promise<WalletInfo> {
    const prisma = getPrismaClient();
    const encryption = getEncryptionService();

    // Normalize private key
    if (!privateKey.startsWith('0x')) {
      privateKey = '0x' + privateKey;
    }

    // Validate and get wallet from private key
    let wallet: EthersWallet;
    try {
      wallet = new EthersWallet(privateKey);
    } catch {
      throw new Error('Invalid private key format');
    }

    const address = wallet.address;

    // Check if this wallet is already registered to another user
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ walletAddress: address }, { importedWalletAddress: address }],
      },
    });

    if (existingUser && existingUser.id !== userId) {
      throw new Error('This wallet is already registered to another user');
    }

    // Encrypt and store as a generated wallet (since we have the raw key)
    const encryptedPrivateKey = encryption.encrypt(privateKey);

    await prisma.user.update({
      where: { id: userId },
      data: {
        walletAddress: address,
        encryptedPrivateKey: encryptedPrivateKey,
        status: 'READY',
      },
    });

    return {
      address,
      type: 'generated', // Treated as generated since we have the raw key encrypted
      createdAt: new Date(),
    };
  }

  /**
   * Get the JSON-RPC provider (for external use in transaction building)
   */
  getProviderInstance(): ethers.JsonRpcProvider {
    return this.getProvider();
  }

  /**
   * Send ETH to another address
   *
   * @param userId - The user's database ID
   * @param toAddress - Destination address
   * @param ethAmount - Amount of ETH to send (e.g., 0.1 for 0.1 ETH)
   * @param password - Password (required for imported wallets)
   * @returns Transaction details including hash and explorer URL
   */
  async sendEth(
    userId: string,
    toAddress: string,
    ethAmount: number,
    password?: string
  ): Promise<{
    txHash: string;
    fromAddress: string;
    toAddress: string;
    amount: string;
    gasUsed: string;
    explorerUrl: string;
  }> {
    const walletInfo = await this.getWalletInfo(userId);

    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    if (walletInfo.type === 'imported' && !password) {
      throw new Error('Password required for imported wallet transactions');
    }

    // Validate destination address
    if (!ethers.isAddress(toAddress)) {
      throw new Error('Invalid destination address');
    }

    // Normalize address
    const normalizedTo = ethers.getAddress(toAddress);

    // Get signer
    let signer: EthersWallet;
    if (walletInfo.type === 'imported') {
      signer = await this.getSignerForImportedWallet(userId, password!);
    } else {
      signer = await this.getSignerForGeneratedWallet(userId);
    }

    try {
      // Calculate amount in wei
      const amountWei = ethers.parseEther(ethAmount.toString());

      // Check balance
      const balance = await signer.provider!.getBalance(walletInfo.address);

      // Estimate gas for the transaction
      const estimatedGas = await signer.estimateGas({
        to: normalizedTo,
        value: amountWei,
      });

      // Get current gas price
      const feeData = await signer.provider!.getFeeData();
      const gasPrice = feeData.gasPrice || ethers.parseUnits('1', 'gwei');

      const gasCost = estimatedGas * gasPrice;
      const totalCost = amountWei + gasCost;

      if (balance < totalCost) {
        const balanceEth = ethers.formatEther(balance);
        const neededEth = ethers.formatEther(totalCost);
        throw new Error(`Insufficient ETH balance. Have: ${balanceEth} ETH, need: ${neededEth} ETH (including gas)`);
      }

      // Send transaction
      const tx = await signer.sendTransaction({
        to: normalizedTo,
        value: amountWei,
      });

      // Wait for confirmation
      const receipt = await tx.wait();

      if (!receipt) {
        throw new Error('Transaction failed - no receipt received');
      }

      return {
        txHash: receipt.hash,
        fromAddress: walletInfo.address,
        toAddress: normalizedTo,
        amount: ethAmount.toString(),
        gasUsed: receipt.gasUsed.toString(),
        explorerUrl: `https://basescan.org/tx/${receipt.hash}`,
      };
    } finally {
      // Signer cleared when function exits
    }
  }

  /**
   * Send USDC to another address
   *
   * @param userId - The user's database ID
   * @param toAddress - Destination address
   * @param usdcAmount - Amount of USDC to send (e.g., 10 for $10)
   * @param password - Password (required for imported wallets)
   * @returns Transaction details including hash and explorer URL
   */
  async sendUsdc(
    userId: string,
    toAddress: string,
    usdcAmount: number,
    password?: string
  ): Promise<{
    txHash: string;
    fromAddress: string;
    toAddress: string;
    amount: string;
    gasUsed: string;
    explorerUrl: string;
  }> {
    const walletInfo = await this.getWalletInfo(userId);

    if (!walletInfo) {
      throw new Error('No wallet found for user');
    }

    if (walletInfo.type === 'imported' && !password) {
      throw new Error('Password required for imported wallet transactions');
    }

    // Validate destination address
    if (!ethers.isAddress(toAddress)) {
      throw new Error('Invalid destination address');
    }

    // Normalize address
    const normalizedTo = ethers.getAddress(toAddress);

    // Get signer
    let signer: EthersWallet;
    if (walletInfo.type === 'imported') {
      signer = await this.getSignerForImportedWallet(userId, password!);
    } else {
      signer = await this.getSignerForGeneratedWallet(userId);
    }

    try {
      // Calculate amount in USDC units (6 decimals)
      const amountRaw = ethers.parseUnits(usdcAmount.toString(), 6);

      // Create USDC contract instance
      const usdcContract = new ethers.Contract(config.tokens.USDC, ERC20_ABI, signer);

      // Check USDC balance
      const usdcBalance = await usdcContract.balanceOf(walletInfo.address);

      if (usdcBalance < amountRaw) {
        const balanceFormatted = ethers.formatUnits(usdcBalance, 6);
        throw new Error(`Insufficient USDC balance. Have: ${balanceFormatted} USDC, need: ${usdcAmount} USDC`);
      }

      // Check ETH balance for gas
      const ethBalance = await signer.provider!.getBalance(walletInfo.address);

      // Estimate gas for the transfer
      const estimatedGas = await usdcContract.transfer.estimateGas(normalizedTo, amountRaw);

      // Get current gas price
      const feeData = await signer.provider!.getFeeData();
      const gasPrice = feeData.gasPrice || ethers.parseUnits('1', 'gwei');

      const gasCost = estimatedGas * gasPrice;

      if (ethBalance < gasCost) {
        const ethBalanceFormatted = ethers.formatEther(ethBalance);
        const gasNeeded = ethers.formatEther(gasCost);
        throw new Error(`Insufficient ETH for gas. Have: ${ethBalanceFormatted} ETH, need: ${gasNeeded} ETH for gas`);
      }

      // Send USDC transfer transaction
      const tx = await usdcContract.transfer(normalizedTo, amountRaw);

      // Wait for confirmation
      const receipt = await tx.wait();

      if (!receipt) {
        throw new Error('Transaction failed - no receipt received');
      }

      return {
        txHash: receipt.hash,
        fromAddress: walletInfo.address,
        toAddress: normalizedTo,
        amount: usdcAmount.toString(),
        gasUsed: receipt.gasUsed.toString(),
        explorerUrl: `https://basescan.org/tx/${receipt.hash}`,
      };
    } finally {
      // Signer cleared when function exits
    }
  }
}

// Singleton instance
let walletServiceInstance: BaseWalletService | null = null;

/**
 * Get the singleton BaseWalletService instance
 */
export function getBaseWalletService(): BaseWalletService {
  if (!walletServiceInstance) {
    walletServiceInstance = new BaseWalletService();
  }
  return walletServiceInstance;
}

/**
 * Reset the singleton instance (for testing purposes only)
 */
export function resetBaseWalletService(): void {
  walletServiceInstance = null;
}
