import dotenv from 'dotenv';
dotenv.config();

export const config = {
  server: {
    port: parseInt(process.env.PORT || '3003', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
  },

  database: {
    url: process.env.DATABASE_URL || '',
  },

  encryption: {
    key: process.env.ENCRYPTION_KEY || '',
  },

  base: {
    rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
    chainId: 8453,
  },

  limitless: {
    apiUrl: process.env.LIMITLESS_API_URL || 'https://api.limitless.exchange',
  },

  admin: {
    apiKey: process.env.ADMIN_API_KEY || '',
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '60', 10),
  },

  // Known token addresses on Base
  tokens: {
    USDC: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
    WETH: '0x4200000000000000000000000000000000000006', // Wrapped ETH on Base
  },

  // Known contract addresses on Base for Limitless
  contracts: {
    CTF: '0xC9c98965297Bc527861c898329Ee280632B76e18', // Conditional Tokens Framework (ERC-1155)
  },
};

// Validate required config
export function validateConfig(): void {
  const required = [
    { key: 'DATABASE_URL', value: config.database.url },
    { key: 'ENCRYPTION_KEY', value: config.encryption.key },
  ];

  const missing = required.filter(({ value }) => !value);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.map(m => m.key).join(', ')}`
    );
  }

  // Validate encryption key format
  if (config.encryption.key.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
}
