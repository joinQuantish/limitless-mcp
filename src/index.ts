/**
 * Limitless MCP Server
 *
 * MCP server for Limitless Exchange prediction markets on Base
 *
 * Features:
 * - MCP JSON-RPC interface (34+ tools)
 * - REST API for markets, admin, and platform management
 * - Base chain wallet generation and import
 * - EIP-712 order signing with dynamic venues
 * - B2B platform partner support
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { config, validateConfig } from './config/index.js';
import { getPrismaClient, disconnectPrisma } from './db/index.js';
import { getMCPHttpHandler } from './mcp/http-handler.js';
import { platformRoutes } from './routes/platform.js';
import { platformsRoutes } from './routes/platforms.js';
import { adminRoutes } from './routes/admin.js';
import { marketsRoutes } from './routes/markets.js';
import { requestLogger, errorLogger } from './middleware/logging.js';

// Validate configuration on startup
validateConfig();

const app = express();

// ============================================
// SECURITY MIDDLEWARE
// ============================================

app.use(helmet());
app.use(
  cors({
    origin: '*', // Configure based on deployment needs
    methods: ['GET', 'POST', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'x-api-key',
      'x-admin-key',
      'x-platform-key',
      'x-hmac-signature',
      'x-hmac-timestamp',
    ],
  })
);

// Body parsing with size limits
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Trust proxy for Railway deployment
app.set('trust proxy', 1);

// ============================================
// REQUEST LOGGING
// ============================================

app.use(requestLogger);

// ============================================
// RATE LIMITING
// ============================================

const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: { error: 'Rate limit exceeded. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use API key if present, otherwise IP
    return (req.headers['x-api-key'] as string) || req.ip || 'unknown';
  },
});
app.use(limiter);

// ============================================
// ROOT & HEALTH ENDPOINTS
// ============================================

/**
 * GET /
 * Root info endpoint with API overview
 */
app.get('/', (_req, res) => {
  res.json({
    name: 'Limitless MCP Server',
    version: '1.0.0',
    description: 'MCP server for Limitless Exchange prediction markets on Base',
    endpoints: {
      health: '/health',
      mcp: '/mcp',
      markets: '/api/markets (public)',
      platform: '/api/platform (requires x-platform-key)',
      platforms: '/api/platforms (registration with access code)',
      admin: '/api/admin (requires x-admin-key)',
    },
    documentation: 'https://github.com/quantish/limitless-mcp',
    features: [
      'Base chain wallet generation',
      'Bring Your Own Wallet (encrypted import)',
      'Limitless market discovery',
      'EIP-712 order signing with dynamic venues',
      'Position tracking',
      'B2B platform partner support',
      'MCP JSON-RPC interface (34+ tools)',
    ],
    chain: {
      name: 'Base',
      chainId: config.base.chainId,
      rpcUrl: config.base.rpcUrl,
    },
  });
});

/**
 * GET /health
 * Health check endpoint for monitoring
 */
app.get('/health', async (_req, res) => {
  try {
    // Quick database connection check
    const prisma = getPrismaClient();
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      service: 'limitless-mcp',
      database: 'connected',
      environment: config.server.nodeEnv,
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      service: 'limitless-mcp',
      database: 'disconnected',
      environment: config.server.nodeEnv,
    });
  }
});

// ============================================
// ROUTES
// ============================================

// MCP endpoint - handles all MCP JSON-RPC requests
const mcpHandler = getMCPHttpHandler();
app.post('/mcp', (req, res) => {
  mcpHandler.handleRequest(req, res);
});

// Admin routes (Quantish internal - requires x-admin-key)
app.use('/api/admin', adminRoutes);

// Platform admin routes (B2B partners - requires x-platform-key)
app.use('/api/platform', platformRoutes);

// Platform registration route (public, requires access code)
app.use('/api/platforms', platformsRoutes);

// Market data routes (public)
app.use('/api/markets', marketsRoutes);

// ============================================
// ERROR HANDLING
// ============================================

// Error logging middleware
app.use(errorLogger);

// Global error handler
app.use(
  (
    err: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error('Unhandled error:', err.message);

    res.status(500).json({
      error: 'Internal server error',
      message: config.server.nodeEnv === 'development' ? err.message : undefined,
    });
  }
);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    method: req.method,
  });
});

// ============================================
// SERVER STARTUP
// ============================================

const PORT = config.server.port;

const server = app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🚀 Limitless MCP Server                                     ║
║                                                               ║
║   Version:     1.0.0                                          ║
║   Environment: ${config.server.nodeEnv.padEnd(20)}             ║
║   Port:        ${PORT.toString().padEnd(20)}                   ║
║                                                               ║
║   Endpoints:                                                  ║
║   • MCP:     http://localhost:${PORT}/mcp                       ║
║   • Health:  http://localhost:${PORT}/health                    ║
║   • Markets: http://localhost:${PORT}/api/markets               ║
║   • Admin:   http://localhost:${PORT}/api/admin                 ║
║                                                               ║
║   Features:                                                   ║
║   • Limitless Exchange prediction markets                     ║
║   • Base chain wallet generation                              ║
║   • Bring Your Own Wallet (encrypted import)                  ║
║   • EIP-712 order signing with dynamic venues                 ║
║   • B2B platform partner support                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);

  // Initialize database connection
  getPrismaClient();
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

async function shutdown(signal: string): Promise<void> {
  console.log(`\n${signal} received, shutting down gracefully...`);

  server.close(() => {
    console.log('HTTP server closed');
  });

  await disconnectPrisma();
  console.log('Database connection closed');

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export default app;
