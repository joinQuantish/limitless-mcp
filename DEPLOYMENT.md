# Limitless MCP Server - Deployment Guide

This guide covers deploying the Limitless MCP server to Railway and troubleshooting common issues.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Railway Deployment](#railway-deployment)
3. [Environment Variables](#environment-variables)
4. [Database Setup](#database-setup)
5. [Health Verification](#health-verification)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance Operations](#maintenance-operations)

---

## Prerequisites

Before deploying, ensure you have:

- [Railway CLI](https://docs.railway.app/develop/cli) installed: `npm install -g @railway/cli`
- Railway account with billing enabled (for PostgreSQL)
- All environment secrets ready (see [Environment Variables](#environment-variables))

---

## Railway Deployment

### Step 1: Initialize Railway Project

```bash
cd /Users/joshberns/quantish-platform-private/limitless-mcp

# Login to Railway
railway login

# Create a NEW project (don't reuse existing)
railway init
# Enter project name: limitless-mcp
```

### Step 2: Add PostgreSQL Database

1. Open the Railway Dashboard: https://railway.app
2. Navigate to your `limitless-mcp` project
3. Click **"+ New"** → **"Database"** → **"PostgreSQL"**
4. Wait for database provisioning (usually 30-60 seconds)
5. Copy the `DATABASE_URL` from the Variables tab

### Step 3: Set Environment Variables

```bash
# Generate encryption key (64-char hex = 32 bytes)
ENCRYPTION_KEY=$(openssl rand -hex 32)

# Generate admin API key
ADMIN_API_KEY=$(openssl rand -hex 32)

# Set all required variables
railway variables set \
  DATABASE_URL="postgresql://..." \
  ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  ADMIN_API_KEY="$ADMIN_API_KEY" \
  BASE_RPC_URL="https://mainnet.base.org" \
  LIMITLESS_API_URL="https://api.limitless.exchange" \
  NODE_ENV="production" \
  PORT="3000"
```

**Important**: Save your `ENCRYPTION_KEY` and `ADMIN_API_KEY` securely. If lost, encrypted data cannot be recovered.

### Step 4: Deploy

```bash
# Deploy to Railway
railway up
```

The deployment uses a multi-stage Dockerfile:
1. **Builder stage**: Installs all deps, compiles TypeScript, generates Prisma client
2. **Production stage**: Only production deps + compiled code

### Step 5: Get Production URL

```bash
# View deployment URL
railway open
```

Or find it in the Railway dashboard under **Settings** → **Domains**.

Default format: `https://limitless-mcp-server-production.up.railway.app`

---

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `ENCRYPTION_KEY` | Yes | 64-char hex for AES-256-GCM | `openssl rand -hex 32` |
| `ADMIN_API_KEY` | Yes | Admin authentication key | `openssl rand -hex 32` |
| `BASE_RPC_URL` | Yes | Base chain RPC endpoint | `https://mainnet.base.org` |
| `LIMITLESS_API_URL` | Yes | Limitless Exchange API | `https://api.limitless.exchange` |
| `NODE_ENV` | Yes | Environment mode | `production` |
| `PORT` | Yes | Server port (Railway uses 3000) | `3000` |
| `BOT_SIGNING_SECRET` | No | HMAC secret for returning users | `openssl rand -hex 32` |

### Generating Secrets

```bash
# Generate 32-byte hex key
openssl rand -hex 32

# Generate 24-byte base64 key
openssl rand -base64 24
```

---

## Database Setup

### Initial Schema Push

The Dockerfile automatically runs `prisma db push` on container start:

```dockerfile
CMD ["sh", "-c", "npx prisma db push --skip-generate --accept-data-loss && node dist/index.js"]
```

### Manual Schema Updates

For manual database operations:

```bash
# Connect to Railway service shell
railway shell

# Run Prisma commands
npx prisma db push          # Push schema changes
npx prisma studio           # Open database GUI
npx prisma migrate status   # Check migration status
```

### Schema Overview

The database includes these main tables:

| Table | Purpose |
|-------|---------|
| `User` | User accounts with encrypted wallet data |
| `UserApiKey` | API keys (SHA-256 hashed) |
| `Order` | Trading orders with EIP-712 signatures |
| `Position` | User positions with P&L tracking |
| `MarketCache` | Cached market data with venue addresses |
| `AccessCode` | Platform registration codes |
| `Platform` | B2B partner platforms |
| `ActivityLog` | User activity audit trail |
| `PlatformActivityLog` | Platform admin audit trail |

### Database Backup

Railway PostgreSQL includes automatic daily backups. For manual backup:

```bash
# Export via pg_dump (requires DATABASE_URL)
pg_dump $DATABASE_URL > backup.sql
```

---

## Health Verification

After deployment, verify all services are healthy:

### 1. Health Endpoint

```bash
curl https://YOUR-DOMAIN.up.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-17T12:00:00.000Z",
  "version": "1.0.0",
  "service": "limitless-mcp",
  "database": "connected",
  "environment": "production"
}
```

### 2. MCP Tools List

```bash
curl -X POST https://YOUR-DOMAIN.up.railway.app/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Should return 35 tools.

### 3. Market Data

```bash
curl "https://YOUR-DOMAIN.up.railway.app/api/markets?limit=3"
```

Should return live market data from Limitless Exchange.

### 4. Signup Flow

```bash
curl -X POST https://YOUR-DOMAIN.up.railway.app/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"limitless_signup",
      "arguments":{"externalId":"health-check-user"}
    }
  }'
```

Should return API key and wallet address.

---

## Troubleshooting

### Common Issues

#### 1. "Cannot find module '@prisma/client'"

**Cause**: Prisma client not generated during build.

**Fix**: The Dockerfile should include `npx prisma generate`. If missing:

```dockerfile
# In builder stage
RUN npx prisma generate
```

#### 2. "PrismaClientInitializationError: Unable to establish connection"

**Cause**: Database connection failed.

**Fix**:
```bash
# Verify DATABASE_URL is set
railway variables

# Check database is running in Railway dashboard
# Connection string format:
# postgresql://user:password@host:port/database
```

#### 3. "error: no matching host key type found"

**Cause**: OpenSSL not installed (needed by Prisma on Alpine).

**Fix**: The Dockerfile includes:
```dockerfile
RUN apk add --no-cache openssl
```

#### 4. Health Check Timeout

**Cause**: Server takes too long to start (Prisma migration).

**Fix**: Increase timeout in `railway.toml`:
```toml
[deploy]
healthcheckTimeout = 120  # 2 minutes
```

#### 5. "401 Unauthorized" from Limitless API

**Cause**: Session expired or invalid signature.

**Fix**:
- Sessions auto-refresh on API calls
- Check `x-account` header is checksummed address
- Verify signature format matches Limitless SDK

#### 6. "feeRateBps out of user's band"

**Cause**: Using wrong fee rate for order placement.

**Fix**: The order service must fetch `limitlessFeeRate` from the user record after authentication with Limitless API.

### View Logs

```bash
# Real-time logs
railway logs

# Or via Railway dashboard → Deployments → View Logs
```

### Rollback Deployment

```bash
# Rollback to previous deployment
railway rollback
```

### Environment Debug

```bash
# List all environment variables (redacted)
railway variables

# Check specific variable
railway variables get DATABASE_URL
```

---

## Maintenance Operations

### Redeploying

```bash
# Manual redeploy
railway up

# Or trigger via GitHub push (if connected)
git push origin master
```

### Scaling

Railway auto-scales based on load. For manual scaling:

1. Railway Dashboard → Service → Settings
2. Adjust **"Replicas"** or **"Memory/CPU"** limits

### Monitoring

- **Railway Metrics**: Built-in CPU, memory, and network charts
- **Health Endpoint**: Integrate with external monitors (UptimeRobot, etc.)

### Database Maintenance

```bash
# Connect to database
railway connect postgres

# Or use Prisma Studio
railway run npx prisma studio
```

### Updating Dependencies

```bash
# Update locally
npm update

# Test
npm run build
npx tsc --noEmit

# Deploy
railway up
```

---

## Configuration Files

### Dockerfile

Multi-stage build for optimized production image:
- Stage 1 (builder): Full dependencies + TypeScript compilation
- Stage 2 (production): Only runtime dependencies + compiled code

### railway.toml

```toml
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/health"
healthcheckTimeout = 120
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

---

## Security Notes

1. **ENCRYPTION_KEY**: Never share or expose. Required to decrypt wallet private keys.
2. **ADMIN_API_KEY**: Required for access code management and admin operations.
3. **Database**: Use Railway's private networking when possible.
4. **Logs**: Sensitive data is redacted in request logging.

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `railway login` | Authenticate CLI |
| `railway up` | Deploy current directory |
| `railway logs` | View deployment logs |
| `railway shell` | Open shell in container |
| `railway variables` | List environment variables |
| `railway rollback` | Revert to previous deployment |
| `railway open` | Open project in browser |

---

## Related Resources

| Resource | URL |
|----------|-----|
| Railway Documentation | https://docs.railway.app |
| Limitless API Docs | https://api.limitless.exchange/api-v1 |
| Base Chain Explorer | https://basescan.org |
| Prisma Documentation | https://www.prisma.io/docs |

---

*Last Updated: January 2026*
