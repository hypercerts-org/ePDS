# Development

## Prerequisites

- Node.js >= 18.7.0
- pnpm 9+
- OpenSSL (for key generation)
- Docker and Docker Compose (optional, for running the full stack locally)

## Setup

```bash
# Clone and install
git clone <repo-url> epds
cd epds
pnpm install

# Generate a PLC rotation key
openssl ecparam -name secp256k1 -genkey -noout | \
  openssl ec -text -noout 2>/dev/null | \
  grep priv -A 3 | tail -n +2 | tr -d '[:space:]:'

# Copy .env.example and fill in values (including the key above)
cp .env.example .env
```

See [configuration.md](configuration.md) for a full reference of environment variables.

## Local Development

```bash
./scripts/dev.sh
```

This starts both services with `NODE_ENV=development`, which disables secure cookies
(needed for `http://localhost`).

| Service      | URL                   |
| ------------ | --------------------- |
| PDS Core     | http://localhost:3000 |
| Auth Service | http://localhost:3001 |

## Running with Docker Locally

```bash
docker compose up -d
docker compose logs -f
```

See [deployment.md](deployment.md) for more details on Docker usage.

## Package Structure

```
packages/
  shared/         # @certified-app/shared — DB, crypto, logger, types
  auth-service/   # @certified-app/auth-service — login UI, OTP, social login
  pds-core/       # @certified-app/pds-core — @atproto/pds wrapper
```

## Testing

```bash
pnpm test
```
