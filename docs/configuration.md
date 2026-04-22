# Configuration

Each package has its own `.env.example` documenting the variables it reads:

- [`packages/pds-core/.env.example`](../packages/pds-core/.env.example)
- [`packages/auth-service/.env.example`](../packages/auth-service/.env.example)
- [`packages/demo/.env.example`](../packages/demo/.env.example)

Run `./scripts/setup.sh` to create and populate all `.env` files and
auto-generate secrets. Safe to re-run — existing secrets are preserved.

## Deployment contexts

| Context             | How vars are loaded                                                                                                        |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **docker-compose**  | core, auth, and caddy load the top-level `.env` via `env_file`. demo loads `packages/demo/.env`.                           |
| **Railway**         | Each service reads only its own per-package `.env`. Run `setup.sh` locally, then paste into each service's raw env editor. |
| **`pnpm dev`**      | `dotenv.config()` in pds-core loads the top-level `.env`. Auth-service inherits the same process environment.              |
| **`pnpm dev:demo`** | Next.js loads `packages/demo/.env` automatically.                                                                          |

## Shared variables

> Set these on **both** pds-core and auth-service. In Docker Compose they come from the single top-level `.env`; on Railway, use a shared variable group or paste identical values into both services.

These must have **identical values** in pds-core and auth-service. They are
marked `[shared]` in the per-package `.env.example` files.

| Variable               | Description                                                                                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EPDS_VERSION`         | Override the version string returned by `/health`. In Docker/Railway builds this is set automatically to `<package.json version>+<8-char commit SHA>`. In dev it falls back to the root `package.json` version. Only set this if you need a custom override. |
| `PDS_HOSTNAME`         | Your PDS domain — handles will be `<random>.PDS_HOSTNAME`                                                                                                                                                                                                    |
| `PDS_PUBLIC_URL`       | Full public URL of the PDS, used as OAuth issuer (e.g. `https://pds.example.com`)                                                                                                                                                                            |
| `EPDS_CALLBACK_SECRET` | HMAC-SHA256 secret signing the `/oauth/epds-callback` redirect — generate with `openssl rand -hex 32`                                                                                                                                                        |
| `EPDS_INTERNAL_SECRET` | Shared secret for internal service-to-service calls (auth → PDS) — generate with `openssl rand -hex 32`                                                                                                                                                      |
| `PDS_ADMIN_PASSWORD`   | PDS admin API password (auth-service uses it for account provisioning)                                                                                                                                                                                       |
| `NODE_ENV`             | Set to `development` for dev mode (disables secure cookies)                                                                                                                                                                                                  |
| `LOG_LEVEL`            | Log verbosity: `fatal`, `error`, `warn`, `info` (default), `debug`, or `trace`. Applied to both pds-core and auth-service.                                                                                                                                   |

## PDS Core

> All variables in this section are set on the **pds-core** service only (except shared variables listed above).

| Variable                                    | Description                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PDS_PORT`                                  | Port for PDS Core. Resolved as `PDS_PORT` → `PORT` → `3000`, so platforms that inject `PORT` (e.g. Railway) work without a service-specific override. |
| `PDS_DATA_DIRECTORY`                        | Path to data directory (default `/data`)                                                                                                              |
| `PDS_DID_PLC_URL`                           | AT Protocol PLC directory URL (default `https://plc.directory`)                                                                                       |
| `PDS_BSKY_APP_VIEW_URL`                     | Bluesky app view URL (default `https://api.bsky.app`)                                                                                                 |
| `PDS_BSKY_APP_VIEW_DID`                     | Bluesky app view DID (default `did:web:api.bsky.app`)                                                                                                 |
| `PDS_CRAWLERS`                              | AT Protocol crawlers (default `https://bsky.network`)                                                                                                 |
| `PDS_JWT_SECRET`                            | Secret for JWT signing — generate with `openssl rand -hex 32`                                                                                         |
| `PDS_DPOP_SECRET`                           | Secret for DPoP — generate with `openssl rand -hex 32`                                                                                                |
| `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` | secp256k1 private key for PLC rotation — see [deployment.md](deployment.md)                                                                           |
| `PDS_EMAIL_SMTP_URL`                        | SMTP URL (e.g. `smtps://user:pass@smtp.resend.com:465`)                                                                                               |
| `PDS_EMAIL_FROM_ADDRESS`                    | Sender address for PDS emails                                                                                                                         |
| `PDS_BLOBSTORE_DISK_LOCATION`               | Path to blob storage directory (default `/data/blobs`)                                                                                                |
| `EPDS_INVITE_CODE`                          | Pre-generated invite code for account creation (see [deployment.md](deployment.md#invite-codes))                                                      |
| `PDS_INVITE_REQUIRED`                       | Whether invite codes are required for account creation (default `true`)                                                                               |

### Trusted clients and consent skip

| Variable                        | Description                                                                                                                                                                                                                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PDS_OAUTH_TRUSTED_CLIENTS`     | Comma-separated list of OAuth `client_id` URLs. Trusted clients get relaxed consent handling and [CSS branding injection](#css-branding-injection). Has no effect on public clients (`token_endpoint_auth_method: "none"`).                                                                  |
| `PDS_SIGNUP_ALLOW_CONSENT_SKIP` | When `true` (or `1`), trusted clients whose metadata includes `"epds_skip_consent_on_signup": true` can skip the consent screen on initial sign-up. All three conditions must be met: this env var is truthy, the client is in `PDS_OAUTH_TRUSTED_CLIENTS`, and the client metadata opts in. |

### CSS branding injection

Trusted clients (listed in `PDS_OAUTH_TRUSTED_CLIENTS`) can provide
custom CSS in their `client-metadata.json` under `branding.css`. When
present, ePDS injects a `<style>` tag into:

- auth-service pages: login, OTP, choose-handle, recovery
- PDS stock consent page (`/oauth/authorize`)

The CSS is size-capped at 32 KB and sanitised to prevent `</style>`
tag closure. The CSP `style-src` directive is updated with a SHA-256
hash of the injected CSS. Untrusted clients never get CSS injection
regardless of what their metadata contains.

Client-app developers can iterate on their `branding.css` without
walking through a real OAuth flow each time by setting
`AUTH_PREVIEW_ROUTES=1` on the auth-service (covers login / OTP /
choose-handle / recovery) and `PDS_PREVIEW_ROUTES=1` on pds-core
(covers the consent page). See the
["Iterating on `branding.css`" section of the client tutorial](./tutorial.md#iterating-on-brandingcss)
for the list of preview routes and example URLs. Intended for preview
envs and dev instances only, not production.

Optional PDS email variables:

| Variable                        | Description                                      |
| ------------------------------- | ------------------------------------------------ |
| `PDS_CONTACT_EMAIL_ADDRESS`     | Contact address shown in PDS well-known metadata |
| `PDS_MODERATION_EMAIL_SMTP_URL` | Separate SMTP for moderation reports             |
| `PDS_MODERATION_EMAIL_ADDRESS`  | Moderation report address                        |

## Auth Service

> All variables in this section are set on the **auth-service** only.

| Variable              | Description                                                                                                                                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_HOSTNAME`       | Auth subdomain (e.g. `auth.pds.example.com`) — must be a subdomain of `PDS_HOSTNAME`                                                                                                                        |
| `AUTH_PORT`           | Port for Auth Service. Resolved as `AUTH_PORT` → `PORT` → `3001`, so platforms that inject `PORT` (e.g. Railway) work without a service-specific override.                                                  |
| `AUTH_SESSION_SECRET` | Session secret — generate with `openssl rand -hex 32`                                                                                                                                                       |
| `AUTH_CSRF_SECRET`    | CSRF secret — generate with `openssl rand -hex 32`                                                                                                                                                          |
| `PDS_INTERNAL_URL`    | **Required.** Internal URL for auth→PDS calls. Docker: `http://core:3000`; Railway: `http://<service>.railway.internal:3000`; local dev: `http://localhost:3000`. Auth service crashes at startup if unset. |

### Verification link settings

| Variable                   | Description                                                |
| -------------------------- | ---------------------------------------------------------- |
| `EPDS_LINK_EXPIRY_MINUTES` | Link expiry in minutes (default `10`)                      |
| `EPDS_LINK_BASE_URL`       | Base URL for verification links — must match AUTH_HOSTNAME |

### OTP code

| Variable      | Description                                                                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OTP_LENGTH`  | Number of characters in the email verification code. Integer in the range 4–12 (default `8`). Values outside the range cause the auth service to fail on startup.                                     |
| `OTP_CHARSET` | Character set for the verification code: `numeric` (digits only, default) or `alphanumeric` (uppercase A–Z plus 0–9). Alphanumeric codes have higher entropy but lose the numeric on-screen keyboard. |

### Handle picker

| Variable                   | Description                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EPDS_DEFAULT_HANDLE_MODE` | Default handle assignment mode for new user signups when neither the OAuth `epds_handle_mode` query parameter nor the client metadata field is set. One of `picker`, `random`, or `picker-with-random` (default: `picker-with-random`). See [tutorial.md](tutorial.md) for the full precedence rules and per-client overrides. |

### Better Auth session

| Variable             | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `SESSION_EXPIRES_IN` | Session lifetime in seconds (default `604800` = 7 days) |
| `SESSION_UPDATE_AGE` | Session update age in seconds (default `86400` = 1 day) |

### Social providers (optional)

Both ID and SECRET must be set to enable a provider. When set, social login
buttons appear on the login page.

| Variable               | Description                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `GOOGLE_CLIENT_ID`     | Google OAuth client ID — [Google Cloud Console](https://console.cloud.google.com/)           |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret                                                                   |
| `GITHUB_CLIENT_ID`     | GitHub OAuth client ID — [GitHub Developer Settings](https://github.com/settings/developers) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret                                                                   |

### Email

| Variable                         | Description                                                                                                                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EMAIL_PROVIDER`                 | Provider: `smtp`, `sendgrid`, `ses`, or `postmark` (default `smtp`)                                                                                                                                                    |
| `SMTP_HOST`                      | SMTP hostname (e.g. `smtp.resend.com`)                                                                                                                                                                                 |
| `SMTP_PORT`                      | SMTP port (e.g. `465`)                                                                                                                                                                                                 |
| `SMTP_USER`                      | SMTP username                                                                                                                                                                                                          |
| `SMTP_PASS`                      | SMTP password / API key                                                                                                                                                                                                |
| `SMTP_FROM`                      | Sender address — must be on a verified domain                                                                                                                                                                          |
| `SMTP_FROM_NAME`                 | Sender display name                                                                                                                                                                                                    |
| `SENDGRID_API_KEY`               | SendGrid API key (for `EMAIL_PROVIDER=sendgrid`)                                                                                                                                                                       |
| `AWS_REGION`                     | AWS region for SES (default `us-east-1`)                                                                                                                                                                               |
| `AWS_SES_SMTP_USER`              | AWS SES SMTP username                                                                                                                                                                                                  |
| `AWS_SES_SMTP_PASS`              | AWS SES SMTP password                                                                                                                                                                                                  |
| `POSTMARK_SERVER_TOKEN`          | Postmark server token                                                                                                                                                                                                  |
| `EMAIL_TEMPLATE_ALLOWED_DOMAINS` | Optional comma-separated list of HTTPS hostnames from which `email_template_uri` can be fetched. If unset, any HTTPS URL is allowed. If set, templates hosted on unlisted domains are logged as a warning and ignored. |

### Database

| Variable      | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `DB_LOCATION` | Path to the ePDS SQLite database (default `/data/epds.sqlite`) |

## Demo

> All variables in this section are set on the **demo** service only.

The demo is standalone — it does not share variables with pds-core or
auth-service.

| Variable         | Description                                                                          |
| ---------------- | ------------------------------------------------------------------------------------ |
| `PUBLIC_URL`     | Public URL of the demo app (used for OAuth `client_id` and `redirect_uri`)           |
| `PDS_URL`        | URL of the ePDS instance to authenticate against                                     |
| `AUTH_ENDPOINT`  | Auth service's OAuth authorize URL (e.g. `https://auth.pds.example/oauth/authorize`) |
| `SESSION_SECRET` | Session signing secret — generate with `openssl rand -base64 32`                     |

Optional:

| Variable            | Description                                                                                                                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EPDS_CLIENT_THEME` | Named theme preset for the demo's own pages. When set, the demo renders with the preset's colour scheme and serves matching `branding.css` in its client metadata. Unset = default light theme. |
| `EPDS_CLIENT_NAME`  | Display name shown in the demo UI header (default `ePDS Demo`).                                                                                                                                 |
| `PLC_DIRECTORY_URL` | PLC directory for DID-to-handle resolution (default `https://plc.directory`).                                                                                                                   |

## Docker / Caddy

> These variables are for the Caddy reverse-proxy container only (not applicable on Railway).

| Variable        | Description                                                |
| --------------- | ---------------------------------------------------------- |
| `PDS_UPSTREAM`  | Override PDS reverse proxy upstream (default `core:3000`)  |
| `AUTH_UPSTREAM` | Override auth reverse proxy upstream (default `auth:3001`) |

## Runtime

> Set on **pds-core**.

| Variable       | Description                    |
| -------------- | ------------------------------ |
| `PDS_DEV_MODE` | Set to `true` for PDS dev mode |
