# E2E Testing with Headless Browser

End-to-end testing of the full ePDS stack (PDS, auth service, demo frontend)
via Playwright running a headless browser on the same machine.

**See also:** [`testing-gaps.md`](testing-gaps.md) — documents per-package
unit test coverage, hard-to-test areas, and which gaps specifically require
e2e tests (route handlers, pds-core, better-auth wiring).

## Goal

Automate the complete login flow: demo frontend -> PDS (PAR) -> auth service
(OTP) -> PDS (token exchange) -> demo welcome page. This exercises all three
packages working together.

## Constraints

### ATProto OAuth client ID rules

The `@atproto/oauth-provider` enforces two client ID formats:

1. **Discoverable** — must be `https://`, must be a domain (not IP), must have
   a path like `/client-metadata.json`. The PDS **fetches** this URL.
2. **Loopback** — must start with `http://localhost` exactly, no path (scope
   and redirect_uri are query params). The PDS uses **built-in defaults**
   instead of fetching metadata.

For localhost testing, the demo must use the **loopback** format since it
can't serve HTTPS.

### HTTPS in the PDS and auth service

The stock `@atproto/pds` has a dev-mode escape hatch:

- **`PDS_HOSTNAME=localhost`** → `cfg.service.publicUrl` becomes
  `http://localhost:{port}` (see `@atproto/pds/dist/config/config.js`)
- **`PDS_DEV_MODE=true`** → skips the HTTPS enforcement check on protected
  resource metadata, disables SSRF protection
- The OAuthProvider auto-adjusts cookie security when the issuer is `http://`

However, ePDS has **four hardcoded `https://` references** that break
HTTP-only dev mode:

| File                                                   | Line | Code                                            |
| ------------------------------------------------------ | ---- | ----------------------------------------------- |
| `packages/pds-core/src/index.ts`                       | 296  | `` const authUrl = `https://${authHostname}` `` |
| `packages/auth-service/src/better-auth.ts`             | 78   | `` baseURL: `https://${authHostname}` ``        |
| `packages/auth-service/src/better-auth.ts`             | 132  | `` baseURL: `https://${authHostname}` ``        |
| `packages/auth-service/src/routes/complete.ts`         | 121  | `` `https://${ctx.config.hostname}` ``          |
| `packages/auth-service/src/routes/account-settings.ts` | 138  | `'https://' + ctx.config.hostname`              |

These must be patched to respect a dev/test mode flag and use `http://` when
appropriate.

### Local dev pattern

For local development, `.env` should set:

```
PDS_HOSTNAME=localhost
AUTH_HOSTNAME=auth.localhost
PDS_PUBLIC_URL=http://localhost:3000
```

The e2e test setup should follow this same pattern.

## Architecture

### Test environment

All services run on localhost, no Caddy, no TLS:

| Service | URL                     | Notes                       |
| ------- | ----------------------- | --------------------------- |
| PDS     | `http://localhost:3000` | `PDS_HOSTNAME=localhost`    |
| Auth    | `http://localhost:3001` | `AUTH_HOSTNAME=localhost`\* |
| Demo    | `http://localhost:3002` | Loopback client ID          |

\* For dev/test mode, `AUTH_HOSTNAME` should be `localhost` (not
`auth.localhost`) since there's no Caddy to route subdomains. The auth
service listens on a separate port directly.

### Demo loopback client ID

In test mode, the demo's `/client-metadata.json` route and the
`/api/oauth/login` route need to use the ATProto loopback client ID format
instead of the discoverable format:

```
http://localhost?redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fapi%2Foauth%2Fcallback&scope=atproto+transition%3Ageneric
```

The PDS won't fetch this URL — it uses built-in defaults for loopback clients.
The demo should switch to this format when `USE_LOOPBACK_CLIENT=true` (or
similar env var) is set.

### Fixing the hardcoded `https://`

Introduce a helper function in `@certified-app/shared`:

```ts
export function authBaseUrl(hostname: string): string {
  const isLocal = hostname === 'localhost' || hostname.endsWith('.localhost')
  return isLocal ? `http://${hostname}` : `https://${hostname}`
}
```

Replace all five hardcoded `https://` references with this helper. This also
fixes the local dev flow (`pnpm dev`) which has the same problem.

### Playwright setup

- Add `@playwright/test` as a dev dependency at the monorepo root
- Create `playwright.config.ts` at the root
- Tests live in `e2e/` directory
- Playwright launches Chromium headless
- Tests manage their own env setup or assume services are already running

### Test flow

The core e2e test exercises the full OAuth login:

1. Navigate to `http://localhost:3002` (demo login page)
2. Enter an email address
3. Click "Sign in with Certified"
4. Browser is redirected through PDS (PAR) to auth service
5. Auth service shows OTP form (with email pre-filled via login_hint)
6. Extract OTP from MailHog API (`http://localhost:8025/api/v2/messages`)
7. Enter OTP in the auth form
8. Browser redirected back through PDS (epds-callback) to demo (callback)
9. Assert: welcome page shows handle and DID

### Services lifecycle

Two options:

**Option A — tests start their own services** (self-contained):
Use `docker compose --profile test up -d` from the test setup, wait for
health checks, run tests, tear down. Requires Docker.

**Option B — tests assume services are running** (simpler):
The developer or CI script starts services before running tests. Tests just
connect. Less complexity in the test harness.

Recommendation: **Option B** for now. A small setup script or `pnpm` command
starts services and runs Playwright. Individual test files don't manage lifecycle.

## Implementation steps

1. **Fix hardcoded `https://`** — add `authBaseUrl()` helper to shared
   package, patch the five callsites in pds-core and auth-service
2. **Add loopback client ID mode to demo** — env var `USE_LOOPBACK_CLIENT`
   switches the `/api/oauth/login` and `/client-metadata.json` routes to use
   the ATProto loopback format
3. **Add Playwright to monorepo** — `@playwright/test` dev dep, config file,
   `e2e/` directory
4. **Add `pnpm test:e2e` script** — starts PDS + auth + demo + MailHog in dev
   mode, waits for health, runs Playwright, reports results
5. **Write the login e2e test** — full Flow 1 (email login with OTP from
   MailHog)
6. **Add Flow 2 e2e test** — button-only login (no email form on demo side)

## Open questions

- **Docker vs bare-metal for e2e?** Docker adds build time but is
  self-contained. Bare-metal (via `pnpm dev` + MailHog container) is faster
  for iteration. The `pnpm test:e2e` script could support both modes.
- **CI integration** — GitHub Actions with Docker Compose, or bare-metal
  with MailHog service container? Defer until the local flow works.
- **Test accounts** — the ePDS auto-provisions accounts on first login. No
  pre-seeding needed, but the test email domain must match what the PDS
  accepts.
