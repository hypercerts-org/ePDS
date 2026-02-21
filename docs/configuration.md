# Configuration

Copy `.env.example` to `.env` and fill in your values.

## PDS Core

| Variable                                    | Description                                                                              |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `PDS_HOSTNAME`                              | Your PDS domain (e.g. `epds-poc1.example.com`) — handles will be `<random>.PDS_HOSTNAME` |
| `PDS_PORT`                                  | Port for PDS Core (default `3000`)                                                       |
| `PDS_PUBLIC_URL`                            | Full public URL of the PDS, used as OAuth issuer (e.g. `https://epds-poc1.example.com`)  |
| `PDS_DATA_DIRECTORY`                        | Path to data directory (default `/data`)                                                 |
| `PDS_DID_PLC_URL`                           | AT Protocol PLC directory URL (default `https://plc.directory`)                          |
| `PDS_BSKY_APP_VIEW_URL`                     | Bluesky app view URL (default `https://api.bsky.app`)                                    |
| `PDS_BSKY_APP_VIEW_DID`                     | Bluesky app view DID (default `did:web:api.bsky.app`)                                    |
| `PDS_CRAWLERS`                              | AT Protocol crawlers (default `https://bsky.network`)                                    |
| `PDS_JWT_SECRET`                            | Secret for JWT signing — generate with `openssl rand -hex 32`                            |
| `PDS_DPOP_SECRET`                           | Secret for DPoP — generate with `openssl rand -hex 32`                                   |
| `PDS_ADMIN_PASSWORD`                        | PDS admin API password                                                                   |
| `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` | secp256k1 private key for PLC rotation — see [deployment.md](deployment.md)              |
| `PDS_INTERNAL_URL`                          | Internal URL for auth→PDS communication (e.g. `http://pds:3000` in Docker)               |
| `MAGIC_INVITE_CODE`                         | Pre-generated invite code for account creation (required if `PDS_INVITE_REQUIRED=true`)  |

## Auth Service

| Variable              | Description                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `AUTH_HOSTNAME`       | Auth subdomain (e.g. `auth.epds-poc1.example.com`) — must be a subdomain of `PDS_HOSTNAME` |
| `AUTH_PORT`           | Port for Auth Service (default `3001`)                                                     |
| `AUTH_SESSION_SECRET` | Session secret — generate with `openssl rand -hex 32`                                      |
| `AUTH_CSRF_SECRET`    | CSRF secret — generate with `openssl rand -hex 32`                                         |

## Shared Secrets

Both services must have matching values for these:

| Variable                | Description                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `MAGIC_CALLBACK_SECRET` | HMAC-SHA256 secret signing the `/oauth/magic-callback` redirect — generate with `openssl rand -hex 32`  |
| `MAGIC_INTERNAL_SECRET` | Shared secret for internal service-to-service calls (auth → PDS) — generate with `openssl rand -hex 32` |

## Better Auth

| Variable             | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `SESSION_EXPIRES_IN` | Session lifetime in seconds (default `604800` = 7 days) |
| `SESSION_UPDATE_AGE` | Session update age in seconds (default `86400` = 1 day) |

## Social Providers (optional)

Both variables must be set to enable a provider. When set, social login buttons appear on the login page.

| Variable               | Description                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `GOOGLE_CLIENT_ID`     | Google OAuth client ID — [Google Cloud Console](https://console.cloud.google.com/)           |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret                                                                   |
| `GITHUB_CLIENT_ID`     | GitHub OAuth client ID — [GitHub Developer Settings](https://github.com/settings/developers) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret                                                                   |

## Email

| Variable                | Description                                                         |
| ----------------------- | ------------------------------------------------------------------- |
| `EMAIL_PROVIDER`        | Provider: `smtp`, `sendgrid`, `ses`, or `postmark` (default `smtp`) |
| `SMTP_HOST`             | SMTP hostname (e.g. `smtp.resend.com`)                              |
| `SMTP_PORT`             | SMTP port (e.g. `465`)                                              |
| `SMTP_USER`             | SMTP username                                                       |
| `SMTP_PASS`             | SMTP password / API key                                             |
| `SMTP_FROM`             | Sender address — must be on a verified domain                       |
| `SMTP_FROM_NAME`        | Sender display name                                                 |
| `SENDGRID_API_KEY`      | SendGrid API key (for `EMAIL_PROVIDER=sendgrid`)                    |
| `AWS_REGION`            | AWS region for SES (default `us-east-1`)                            |
| `AWS_SES_SMTP_USER`     | AWS SES SMTP username                                               |
| `AWS_SES_SMTP_PASS`     | AWS SES SMTP password                                               |
| `POSTMARK_SERVER_TOKEN` | Postmark server token                                               |

## PDS Email (used by @atproto/pds)

Used for password reset, confirm-email, and other AT Protocol built-in emails.

| Variable                        | Description                                               |
| ------------------------------- | --------------------------------------------------------- |
| `PDS_EMAIL_SMTP_URL`            | SMTP URL (e.g. `smtps://user:pass@smtp.resend.com:465`)   |
| `PDS_EMAIL_FROM_ADDRESS`        | Sender address for PDS emails                             |
| `PDS_CONTACT_EMAIL_ADDRESS`     | Optional contact address shown in PDS well-known metadata |
| `PDS_MODERATION_EMAIL_SMTP_URL` | Optional separate SMTP for moderation reports             |
| `PDS_MODERATION_EMAIL_ADDRESS`  | Optional moderation report address                        |

## Blobstore

| Variable                      | Description                                            |
| ----------------------------- | ------------------------------------------------------ |
| `PDS_BLOBSTORE_DISK_LOCATION` | Path to blob storage directory (default `/data/blobs`) |

## Database

| Variable      | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `DB_LOCATION` | Path to the ePDS SQLite database (default `/data/epds.sqlite`) |

## Runtime

| Variable       | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `NODE_ENV`     | Set to `development` for dev mode (disables secure cookies) |
| `PDS_DEV_MODE` | Set to `true` for PDS dev mode                              |
