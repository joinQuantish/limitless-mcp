#!/bin/sh
set -e

echo "Starting Limitless MCP Server..."

# Wait for database to be ready with retry logic
MAX_RETRIES=30
RETRY_INTERVAL=2

for i in $(seq 1 $MAX_RETRIES); do
    echo "Checking database connection (attempt $i/$MAX_RETRIES)..."
    if npx prisma db push --skip-generate --accept-data-loss 2>&1; then
        echo "Database ready!"
        break
    fi

    if [ $i -eq $MAX_RETRIES ]; then
        echo "ERROR: Could not connect to database after $MAX_RETRIES attempts"
        exit 1
    fi

    echo "Database not ready, retrying in ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

echo "Starting Node.js server..."
exec node dist/index.js
