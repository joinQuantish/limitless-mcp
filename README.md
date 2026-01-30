# Limitless MCP Server

<div align="center">
  <h3>Prediction Market Trading on Base via Limitless Exchange</h3>
  <p>Build AI-powered trading agents for Limitless prediction markets using the Model Context Protocol (MCP)</p>

  [![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue.svg)](LICENSE)
  [![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)
  [![Base Chain](https://img.shields.io/badge/Base-L2-blue.svg)](https://base.org/)
</div>

---

## Features

- **Secure Wallet Management**
  - Generate new Base wallets with encrypted private key storage
  - **Bring Your Own Wallet (BYOW)** - Import existing wallets with client-side encryption
  - Private keys are encrypted with AES-256-GCM before storage

- **Full Limitless Market Access**
  - Real-time market discovery via Limitless Exchange API
  - Access to all prediction markets: Politics, Sports, Crypto, and more
  - Live orderbook data and price history
  - Semantic search for market discovery

- **Trading Operations**
  - Place limit orders with EIP-712 signed authentication
  - Cancel orders (single, batch, or all)
  - Check and set token approvals (USDC, CTF)
  - Position tracking with P&L calculations

- **AI Agent Integration**
  - Full MCP (Model Context Protocol) support
  - Works with Claude, Cursor IDE, and other MCP-compatible AI tools
  - 34 pre-built trading tools organized by category

- **Enterprise Security**
  - AES-256-GCM encryption for all sensitive data
  - API key authentication with SHA-256 hashing
  - Platform partner system for B2B integrations
  - Rate limiting and request logging

---

## Quick Start

### 1. Configure MCP (Cursor IDE)

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "limitless": {
      "url": "https://limitless-mcp-server-production.up.railway.app/mcp",
      "headers": {
        "x-api-key": "YOUR_API_KEY"
      }
    }
  }
}
```

### 2. Get Your API Key

Via MCP tool:
```json
{
  "tool": "limitless_signup",
  "args": {
    "externalId": "your-unique-id"
  }
}
```

### 3. Start Trading

```
"Search for bitcoin prediction markets"
"Buy 10 YES shares at $0.60 on the BTC market"
"Show my current positions"
"Cancel my open orders"
```

---

## Available MCP Tools (34 Total)

> **Note:** All tool names are prefixed with `limitless_` to avoid collisions with other MCPs.

### Authentication & Setup (6 tools)

| Tool | Description |
|------|-------------|
| `limitless_signup` | Create a new account with a fresh Base wallet |
| `limitless_request_api_key` | Get new API key (requires HMAC signature) |
| `limitless_setup_wallet` | Generate a new Base wallet |
| `limitless_import_wallet` | Import existing wallet (encrypted) |
| `limitless_get_wallet_import_instructions` | Instructions for secure wallet export |
| `limitless_import_private_key` | Direct private key import |

### Wallet Information (4 tools)

| Tool | Description |
|------|-------------|
| `limitless_get_wallet_info` | Get wallet address and type |
| `limitless_get_wallet_status` | Full wallet status with balances |
| `limitless_get_balances` | Check ETH and USDC balances |
| `limitless_get_deposit_address` | Get address for funding |

### Market Discovery (6 tools)

| Tool | Description |
|------|-------------|
| `limitless_get_markets` | List active markets with pagination |
| `limitless_search_markets` | Semantic search for markets |
| `limitless_get_market` | Get market details including venue |
| `limitless_get_orderbook` | Get order book with bids/asks |
| `limitless_get_price_history` | Historical price data |
| `limitless_get_categories` | List market categories |

### Trading (8 tools)

| Tool | Description |
|------|-------------|
| `limitless_place_order` | Place a limit order |
| `limitless_cancel_order` | Cancel a single order |
| `limitless_cancel_all_orders` | Cancel all orders in a market |
| `limitless_get_orders` | List your orders |
| `limitless_check_approvals` | Check token approvals |
| `limitless_set_approvals` | Set token approvals |
| `limitless_get_locked_balance` | Get USDC locked in orders |
| `limitless_get_quote` | Estimate fill price |

### Positions (4 tools)

| Tool | Description |
|------|-------------|
| `limitless_get_positions` | Get active positions with P&L |
| `limitless_get_trades` | Get trade history |
| `limitless_get_portfolio_history` | Full portfolio history |
| `limitless_sync_positions` | Sync positions from API |

### Transfers (3 tools)

| Tool | Description |
|------|-------------|
| `limitless_send_eth` | Send ETH to another address |
| `limitless_send_usdc` | Send USDC to another address |
| `limitless_export_private_key` | Export wallet private key |

### API Key Management (3 tools)

| Tool | Description |
|------|-------------|
| `limitless_list_api_keys` | List your API keys |
| `limitless_create_api_key` | Create a new API key |
| `limitless_revoke_api_key` | Revoke an API key |

---

## Self-Hosting

### Prerequisites

- Node.js 20+
- PostgreSQL 15+
- Base RPC access (mainnet.base.org)

### Installation

```bash
# Clone the repository
git clone https://github.com/joinQuantish/limitless-mcp.git
cd limitless-mcp

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit .env with your values (see Environment Variables below)

# Generate Prisma client
npx prisma generate

# Push database schema
npx prisma db push

# Build and start
npm run build
npm start
```

### Environment Variables

Create a `.env` file with:

```bash
# Database (PostgreSQL)
DATABASE_URL="postgresql://user:password@host:5432/limitless_mcp?schema=public"

# Encryption (generate with: openssl rand -hex 32)
ENCRYPTION_KEY="your-64-character-hex-encryption-key-here"

# Blockchain - Base L2
BASE_RPC_URL="https://mainnet.base.org"

# Limitless Exchange API
LIMITLESS_API_URL="https://api.limitless.exchange"

# Server
PORT=3003
NODE_ENV=production

# Admin API Key (generate with: openssl rand -hex 32)
ADMIN_API_KEY="your-admin-api-key-here"

# Optional: Bot signing secret for returning user verification
BOT_SIGNING_SECRET=""
```

### Docker Deployment

```bash
# Build the image
docker build -t limitless-mcp .

# Run the container
docker run -d \
  -p 3003:3003 \
  -e DATABASE_URL="postgresql://..." \
  -e ENCRYPTION_KEY="..." \
  -e ADMIN_API_KEY="..." \
  -e BASE_RPC_URL="https://mainnet.base.org" \
  -e LIMITLESS_API_URL="https://api.limitless.exchange" \
  -e NODE_ENV=production \
  limitless-mcp
```

### Railway Deployment

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and initialize
railway login
railway init

# Add PostgreSQL via Railway dashboard

# Set environment variables
railway variables set DATABASE_URL="postgresql://..."
railway variables set ENCRYPTION_KEY="$(openssl rand -hex 32)"
railway variables set ADMIN_API_KEY="$(openssl rand -hex 32)"
railway variables set BASE_RPC_URL="https://mainnet.base.org"
railway variables set LIMITLESS_API_URL="https://api.limitless.exchange"
railway variables set NODE_ENV="production"

# Deploy
railway up
```

---

## API Reference

### Health Check

```bash
curl https://your-server/health
```

Response:
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

### MCP Endpoint

```bash
# List available tools
curl -X POST https://your-server/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Call a tool (authenticated)
curl -X POST https://your-server/mcp \
  -H "Content-Type: application/json" \
  -H "x-api-key: pk_limitless_..." \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"limitless_get_balances",
      "arguments":{}
    }
  }'
```

### Market Data API

```bash
# Get active markets
curl "https://your-server/api/markets?limit=10&page=1"

# Search markets
curl "https://your-server/api/markets/search?query=bitcoin&limit=5"

# Get market details
curl "https://your-server/api/markets/your-market-slug"

# Get orderbook
curl "https://your-server/api/markets/your-market-slug/orderbook"
```

---

## Security Architecture

<details>
<summary>Click to expand security details</summary>

### Encryption at Rest

All sensitive data is encrypted using AES-256-GCM:
- Private keys encrypted before database storage
- Session tokens encrypted with unique IVs
- API secrets encrypted (only SHA-256 hash stored for lookup)

### API Key Security

```
API Key Format: pk_limitless_<32 base64url chars>
API Secret Format: sk_limitless_<43 base64url chars>
```

- Keys are hashed with SHA-256 before storage (never stored in plaintext)
- Secrets are encrypted with AES-256-GCM
- Timing-safe comparison using `crypto.timingSafeEqual`

### Platform Isolation (B2B)

For platform partners:
- Platform admin keys: `plt_limitless_*` / `psk_limitless_*`
- All queries scoped by platformId at database level
- Activity logging for audit trail
- User limits enforced per platform

### Rate Limiting

- 60 requests/minute per API key (general)
- 30 requests/minute for user listing (platform admin)
- 5 requests/hour for platform registration

</details>

---

## Secure Wallet Import (BYOW)

Import your existing MetaMask/hardware wallet securely:

### Step 1: Export Your Private Key

In MetaMask: Settings > Security > Export Private Key

### Step 2: Encrypt Locally

```javascript
const crypto = require('crypto');

const privateKey = 'YOUR_PRIVATE_KEY_WITHOUT_0x_PREFIX';
const password = 'YourSecurePassword123!'; // min 12 chars

const salt = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const derivedKey = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });

const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
let encrypted = cipher.update(privateKey, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag().toString('hex');

console.log({
  encryptedKey: `${encrypted}:${authTag}`,
  salt: salt.toString('hex'),
  iv: iv.toString('hex'),
  publicKey: 'YOUR_WALLET_ADDRESS'
});
```

### Step 3: Import to SDK

```json
{
  "tool": "limitless_import_wallet",
  "args": {
    "encryptedKey": "...",
    "salt": "...",
    "iv": "...",
    "publicKey": "0x...",
    "password": "YourSecurePassword123!"
  }
}
```

> **Security Note**: Your raw private key NEVER leaves your machine. Only the encrypted bundle is sent to our servers, and we cannot decrypt it without your password.

---

## Related Resources

| Resource | URL |
|----------|-----|
| Limitless Exchange | https://limitless.exchange |
| Limitless API Docs | https://api.limitless.exchange/api-v1 |
| Base Chain Explorer | https://basescan.org |
| Base USDC Contract | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) © [Quantish](https://quantish.live)

---

## Support

- Issues: [GitHub Issues](https://github.com/joinQuantish/limitless-mcp/issues)
- Email: hello@quantish.live

---

<div align="center">
  <sub>Built with precision by <a href="https://quantish.live">Quantish</a></sub>
</div>
