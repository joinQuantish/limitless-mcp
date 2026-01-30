/**
 * Request Logging Middleware for Limitless MCP
 *
 * Logs all incoming requests with:
 * - Method and path
 * - Response status and time
 * - Request ID for tracing
 * - Client IP (anonymized in production)
 *
 * SECURITY: Does NOT log sensitive data (API keys, signatures, etc.)
 */

import { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';

// ============================================
// TYPES
// ============================================

interface RequestLogData {
  requestId: string;
  method: string;
  path: string;
  query: Record<string, unknown>;
  ip: string;
  userAgent?: string;
  timestamp: string;
}

interface ResponseLogData extends RequestLogData {
  statusCode: number;
  duration: number;
  contentLength?: string;
}

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Generate a unique request ID
 */
function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Anonymize IP address in production
 * Keeps first two octets for debugging, masks last two
 */
function anonymizeIp(ip: string): string {
  if (config.server.nodeEnv === 'development') {
    return ip;
  }

  // Handle IPv4
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
  }

  // Handle IPv6 - just show first segment
  if (ip.includes(':')) {
    const parts = ip.split(':');
    if (parts.length > 2) {
      return `${parts[0]}:${parts[1]}:xxxx:xxxx:xxxx:xxxx`;
    }
  }

  return 'unknown';
}

/**
 * Sanitize query parameters (remove sensitive data)
 */
function sanitizeQuery(query: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = ['key', 'secret', 'password', 'token', 'signature', 'apiKey'];
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(query)) {
    if (sensitiveKeys.some((sk) => key.toLowerCase().includes(sk.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Format duration for logging
 */
function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  return `${(ms / 1000).toFixed(2)}s`;
}

/**
 * Get color code for status (for terminal output)
 */
function getStatusColor(status: number): string {
  if (status >= 500) return '\x1b[31m'; // Red
  if (status >= 400) return '\x1b[33m'; // Yellow
  if (status >= 300) return '\x1b[36m'; // Cyan
  if (status >= 200) return '\x1b[32m'; // Green
  return '\x1b[0m'; // Reset
}

// ============================================
// LOGGING MIDDLEWARE
// ============================================

/**
 * Request logging middleware
 *
 * Adds requestId to request object and logs request/response details
 */
export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const requestId = generateRequestId();
  const startTime = Date.now();

  // Attach requestId to request for downstream use
  (req as Request & { requestId: string }).requestId = requestId;

  // Build request log data
  const requestData: RequestLogData = {
    requestId,
    method: req.method,
    path: req.path,
    query: sanitizeQuery(req.query as Record<string, unknown>),
    ip: anonymizeIp(req.ip || 'unknown'),
    userAgent: req.get('user-agent')?.substring(0, 100), // Truncate long user agents
    timestamp: new Date().toISOString(),
  };

  // Log request (only in development for verbosity)
  if (config.server.nodeEnv === 'development') {
    console.log(`→ ${requestData.method} ${requestData.path} [${requestData.requestId}]`);
  }

  // Listen for response finish
  res.on('finish', () => {
    const duration = Date.now() - startTime;

    const responseData: ResponseLogData = {
      ...requestData,
      statusCode: res.statusCode,
      duration,
      contentLength: res.get('content-length'),
    };

    // Format log message
    const color = getStatusColor(res.statusCode);
    const reset = '\x1b[0m';

    if (config.server.nodeEnv === 'development') {
      console.log(
        `← ${color}${res.statusCode}${reset} ${req.method} ${req.path} ` +
          `${formatDuration(duration)} [${requestId}]`
      );
    } else {
      // Production: JSON format for log aggregation
      console.log(
        JSON.stringify({
          type: 'request',
          ...responseData,
          duration: formatDuration(duration),
        })
      );
    }
  });

  next();
}

/**
 * Error logging middleware (to be used with global error handler)
 */
export function errorLogger(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const requestId = (req as Request & { requestId?: string }).requestId || 'unknown';

  // Log error details (never log stack traces in production)
  const errorData = {
    type: 'error',
    requestId,
    method: req.method,
    path: req.path,
    error: err.message,
    stack: config.server.nodeEnv === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
  };

  console.error(JSON.stringify(errorData));

  next(err);
}
