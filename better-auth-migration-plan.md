# Migration Plan: auth-service to better-auth

## Goal

Replace the custom authentication infrastructure in `packages/auth-service`
with [better-auth](https://better-auth.com), enabling support for multiple
login methods (email OTP, magic link, Google, GitHub, etc.) while preserving
the AT Protocol OAuth integration with pds-core.

**Additionally:** fix the two critical security vulnerabilities identified in
the [magic-pds security review](https://gist.github.com/s-adamantine/c88df4fc940259cfe903e9de474f07fc#critical-vulnerabilities)
and incorporate architectural ideas from
[pds-gatekeeper](https://tangled.org/baileytownsend.dev/pds-gatekeeper).

## Current Architecture

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│        auth-service             │     │          pds-core                │
│  auth.pds.example  :3001        │     │  pds.example  :3000              │
│                                 │     │                                  │
│  Custom OTP token service       │     │  Stock @atproto/pds              │
│  Custom rate limiter            │────►│  /oauth/magic-callback           │
│  Custom session management      │     │  /_magic/check-email             │
│  Custom CSRF middleware         │     │  AS metadata override            │
│  Custom email sender            │     │                                  │
│  6 HTML form-based routes       │     │                                  │
│  10 account settings routes     │     │                                  │
└─────────────────────────────────┘     └──────────────────────────────────┘
             │
        pds.sqlite (shared)
```

### What auth-service currently owns

| Component                             | Files                                                   | Replaced by better-auth?                   |
|---------------------------------------|---------------------------------------------------------|--------------------------------------------|
| OTP generation, hashing, verification | `magic-link/token.ts`                                   | Yes — `emailOTP` plugin                    |
| Email-specific rate limiting          | `magic-link/rate-limit.ts`                              | Yes — built-in rate limiting               |
| Request rate limiting (per-IP)        | `middleware/rate-limit.ts`                              | Yes — built-in rate limiting               |
| CSRF protection                       | `middleware/csrf.ts`                                    | Yes — built-in CSRF                        |
| Account session cookies               | `middleware/account-auth.ts`                            | Yes — built-in session management          |
| Email sending (SMTP/SG/SES/PM)        | `email/sender.ts`                                       | Partially — `sendVerificationOTP` callback |
| Client metadata resolution            | `lib/client-metadata.ts`                                | No — AT Protocol-specific                  |
| Auto-provision PDS accounts           | `lib/auto-provision.ts`                                 | No — AT Protocol-specific                  |
| OAuth authorize flow (HTML forms)     | `routes/authorize.ts`, `send-code.ts`, `verify-code.ts` | Partially — see below                      |
| Consent screen                        | `routes/consent.ts`                                     | No — AT Protocol-specific                  |
| Account recovery                      | `routes/recovery.ts`                                    | Partially                                  |
| Account settings portal               | `routes/account-login.ts`, `account-settings.ts`        | Partially                                  |
| Backup email system                   | `routes/account-settings.ts`, `db.ts`                   | No — custom feature                        |

### What pds-core owns (changed by this migration)

- `GET /oauth/magic-callback` — resolves email→DID via `pds.ctx.accountManager.getAccountByEmail()`, creates PDS account, issues OAuth authorization code, redirects to client
- `GET /_internal/account-by-email` — replaces `/_magic/check-email`; protected internal endpoint for auth-service to look up email→DID
- AS metadata override — patches `authorization_endpoint`
- Stock `@atproto/pds` (XRPC, OAuth token endpoint, repo sync, etc.)

### Known critical vulnerabilities (from external review)

These exist in the current codebase and **must** be fixed as part of this
migration — not deferred.

**CRITICAL-1: Unsigned magic callback → account takeover.** The
`/oauth/magic-callback` endpoint accepts `email`, `approved`, and
`request_uri` as plain, unsigned query parameters. An attacker who can
reach the PDS port directly (misconfigured firewall, Docker port mapping,
open redirect) can skip OTP verification entirely and obtain an OAuth
authorization code for any email address. There is no cryptographic proof
that the auth-service actually verified the user.

**CRITICAL-2: OTP brute-force.** 6 digits = 1,000,000 possibilities.
5 attempts per token × 5 tokens per hour = 25 guesses/hour. Over days or
weeks this becomes non-trivial for a targeted attack.

### Additional medium-severity issues to address

| ID | Issue | Fix |
|----|-------|-----|
| MED-3 | Random password is a backdoor credential | Stop assigning random passwords; create accounts passwordless |
| MED-4 | `/_magic/check-email` is unauthenticated email enumeration | Replace with `/_internal/account-by-email` (shared secret required) |
| MED-5 | Consent screen hardcodes permissions | Show actual requested scopes |
| MED-6 | Admin password in auth-service memory | Use scoped tokens if possible |

---

## Target Architecture

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│        auth-service             │     │          pds-core                │
│  auth.pds.example  :3001        │     │  pds.example  :3000              │
│                                 │     │                                  │
│  better-auth instance           │     │  Stock @atproto/pds              │
│    - emailOTP plugin            │     │  /oauth/magic-callback           │
│    - Google social provider     │────►│    (uses accountManager directly)│
│    - GitHub social provider     │     │  /_internal/account-by-email     │
│    - (future providers)         │◄────│    (MAGIC_INTERNAL_SECRET)       │
│                                 │     │  AS metadata override            │
│  Custom bridge layer:           │     │                                  │
│    - AT Proto OAuth flow glue   │     │  account.sqlite (PDS-owned)      │
│    - Consent screen             │     │    email→DID, single source      │
│    - Account settings UI        │     │    of truth                      │
│    - Backup email system        │     │                                  │
│    - Client metadata resolver   │     │                                  │
└─────────────────────────────────┘     └──────────────────────────────────┘
              │
        auth-service.sqlite
   (better-auth tables: user, session, account, verification)
   (custom tables: backup_email, client_logins, ...)
```

### Key design decisions

1. **better-auth handles identity verification only.** It confirms "this
   person controls this email" (via OTP) or "this person authenticated via
   Google" (via OAuth). It does NOT issue AT Protocol tokens or interact with
   the PDS directly.

2. **A custom auth-service bridge route (`/auth/complete`) translates
   better-auth sessions into AT Protocol OAuth codes.** After better-auth
   establishes a session, the bridge reads the session, extracts the
   verified email, and redirects to pds-core `/oauth/magic-callback` —
   same as today.

3. **The magic-callback is cryptographically signed (CRITICAL-1 fix).**
   The bridge route no longer sends bare query params. Instead it sends an
   HMAC-SHA256 signature over the callback parameters using a shared secret
   between auth-service and pds-core. pds-core verifies the signature before
   issuing an authorization code. See "Phase 0" below.

4. **OTP is 8 digits (CRITICAL-2 fix).** better-auth's `emailOTP` plugin
   supports configurable `otpLength`. We use 8 digits (100,000,000
   possibilities) combined with better-auth's built-in `allowedAttempts`
   and our existing per-email rate limiting. This makes brute-force
   infeasible even for sustained targeted attacks.

5. **pds-core no longer opens the auth-service database.** Email→DID
   lookups in pds-core's magic-callback handler use
   `pds.ctx.accountManager.getAccountByEmail()` — the PDS's own API
   against `account.sqlite` — rather than reading the auth-service's
   SQLite file. The `account_email` mirror table and its associated
   fallback chain (`getDidByEmail`, `getDidFromPdsAccount`,
   `setAccountEmail`) are eliminated entirely.

6. **Auth-service looks up email→DID via HTTP.** The auth-service calls
   a new protected pds-core endpoint (`/_internal/account-by-email`)
   instead of reading from a mirrored `account_email` table. One source
   of truth: `account.sqlite` owned by the PDS.

7. **Single SQLite database for auth-service.** better-auth's tables
   (`user`, `session`, `account`, `verification`) don't collide with the
   remaining auth-service tables (`backup_email`, `client_logins`, etc.).
   Point better-auth at the auth-service's own SQLite file directly.

8. **Accounts are created without passwords** so that `createSession` and
   password reset endpoints remain functional but are simply not usable for
   passwordless accounts (the PDS rejects login when there's no password
   hash). Users who explicitly set a password via account settings can still
   use `createSession` normally. See "Phase 0" below.

---

## Phase 0: Fix critical vulnerabilities (do this first, before any migration)

These fixes are independent of the better-auth migration and should be
applied to the current codebase immediately. They apply equally whether
or not better-auth is adopted.

### 0.1 CRITICAL-1 fix: Sign the magic callback with HMAC

**Problem:** `/oauth/magic-callback` accepts plain query params. Anyone who
can reach the PDS port can forge a callback and take over any account.

**Fix:** Add a shared secret between auth-service and pds-core. The auth
service computes an HMAC-SHA256 signature over the callback parameters and
appends it. pds-core verifies it before proceeding.

**Implementation:**

1. Add `MAGIC_CALLBACK_SECRET` env var (shared by both services). Generate
   with `openssl rand -hex 32`.

2. In auth-service, when building the redirect URL to `/oauth/magic-callback`:

   ```typescript
   import { createHmac } from "crypto";

   function signCallback(params: {
     request_uri: string;
     email: string;
     approved: string;
     new_account: string;
   }, secret: string): string {
     const ts = Math.floor(Date.now() / 1000).toString();
     const payload = [
       params.request_uri,
       params.email,
       params.approved,
       params.new_account,
       ts,
     ].join("\n");
     const sig = createHmac("sha256", secret)
       .update(payload)
       .digest("hex");
     return sig;
   }

   // Add &ts=...&sig=... to the redirect URL
   ```

3. In pds-core `/oauth/magic-callback` handler, verify before any account
   operations:

   ```typescript
   const { request_uri, email, approved, new_account, ts, sig } = req.query;

   // Reject if timestamp is older than 5 minutes
   const age = Math.floor(Date.now() / 1000) - parseInt(ts);
   if (age > 300 || age < 0) return res.status(400).json({ error: "Expired" });

   // Verify HMAC
   const expected = createHmac("sha256", secret)
     .update([request_uri, email, approved, new_account, ts].join("\n"))
     .digest("hex");
   if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
     return res.status(403).json({ error: "Invalid signature" });
   }
   ```

4. The timestamp prevents replay attacks. The HMAC prevents forgery.

**Alternative considered: JWT.** An HMAC signature is simpler and sufficient
here — we don't need the overhead of JWT parsing, and both services share
a secret anyway.

### 0.2 CRITICAL-2 fix: Increase OTP to 8 digits

**Problem:** 6-digit OTP with 5 attempts × 5 tokens/hour = 25 guesses/hour.
Over months this becomes non-trivial.

**Fix (current codebase):** Change `generateOtpCode()` in
`packages/shared/src/crypto.ts` to generate 8-digit codes. Update the email
templates to show 8 digits.

**Fix (after better-auth migration):** Set `otpLength: 8` in the `emailOTP`
plugin config.

Additionally, add a per-email lockout after N total failed attempts across
all tokens (e.g., 15 total failures in 1 hour → lock the email for 1 hour).
This is orthogonal to per-token attempt limits.

### 0.3 MED-3 fix: Stop assigning random passwords

**Problem:** Accounts are currently created with a random 64-byte hex
password (`crypto.randomBytes(64).toString('hex')` in `pds-core/src/index.ts:130`
and `auto-provision.ts:20`). This password is never shown to users but is a
valid credential for `createSession`. If it were ever leaked (logs, memory
dump, DB access), it bypasses the entire auth service.

**Fix:** Pass `password: undefined` when creating accounts. The PDS
`accountManager.createAccount()` already handles this — it sets
`passwordScrypt` to `undefined`, meaning:
- `createSession` rejects login (no hash to compare against)
- Password reset has nothing to reset
- Users who later set a password explicitly (via account settings) can use
  `createSession` and password reset normally

This keeps `createSession` and password reset endpoints fully functional
for users who choose to have a password, while making passwordless accounts
genuinely passwordless.

**Changes:**
- `pds-core/src/index.ts:130`: change `password: randomBytes(64).toString('hex')`
  to `password: undefined`
- `auto-provision.ts:20`: same change
- Verify the PDS handles passwordless accounts correctly — test that
  `createSession` returns a proper error (not a crash) when there's no
  password hash

**Setting a password later:** Users who want password-based login can use
the stock PDS `requestPasswordReset` → `resetPassword` flow. This works
even when no password was previously set (it creates a new scrypt hash,
not comparing against an old one). No custom route needed.

### 0.4 MED-4 fix: Replace `/_magic/check-email` with a proper internal endpoint

**Problem:** `/_magic/check-email` returns `{ exists: true/false, did: "..." }`
for any email with no authentication. It's an email enumeration oracle. It
also reads from the `account_email` mirror table, which we're eliminating.

**Fix:** Replace it with `/_internal/account-by-email`, which:
- Requires `x-internal-secret` header matching `MAGIC_INTERNAL_SECRET`
- Queries `pds.ctx.accountManager.getAccountByEmail()` directly — no mirror table
- Returns `{ did: string } | { did: null }` — no redundant `exists` field

```typescript
// In pds-core:
app.get("/_internal/account-by-email", (req, res) => {
  if (req.headers["x-internal-secret"] !== process.env.MAGIC_INTERNAL_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const email = req.query.email as string;
  if (!email) return res.status(400).json({ error: "Missing email" });
  const account = await pds.ctx.accountManager.getAccountByEmail(email);
  res.json({ did: account?.did ?? null });
});
```

Delete `/_magic/check-email` once auth-service is updated to call the new
endpoint. Auth-service passes the secret via the `x-internal-secret` header.

---

## Phase 1: Set up better-auth alongside existing code

### 1.1 Install dependencies

```bash
pnpm add better-auth better-sqlite3
# better-sqlite3 is already a dependency — verify version compatibility
```

### 1.2 Create better-auth configuration

Create `packages/auth-service/src/better-auth.ts`:

```typescript
import { betterAuth } from "better-auth";
import { emailOTP } from "better-auth/plugins";
import Database from "better-sqlite3";

// Build social providers object from env vars — only providers
// with both client ID and secret configured will be enabled.
function buildSocialProviders() {
  const providers: Record<string, { clientId: string; clientSecret: string }> = {};

  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    providers.google = {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    };
  }

  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    providers.github = {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    };
  }

  // Add more providers following the same pattern.

  return providers;
}

export const socialProviders = buildSocialProviders();

export const auth = betterAuth({
  database: new Database(process.env.DB_LOCATION ?? "./data/magic-pds.sqlite"),
  baseURL: `https://${process.env.AUTH_HOSTNAME}`,
  basePath: "/api/auth",  // keep better-auth routes namespaced

  // Email OTP replaces custom token service
  plugins: [
    emailOTP({
      async sendVerificationOTP({ email, otp, type }) {
        // Reuse existing EmailSender from email/sender.ts
        // Wire up here — details in Phase 2
      },
      otpLength: 8,        // CRITICAL-2 fix: 8 digits, not 6
      expiresIn: 600,      // 10 minutes, matching current config
      allowedAttempts: 5,  // matching current maxAttemptsPerToken
      storeOTP: "hashed",
    }),
  ],

  // Only includes providers whose env vars are set
  socialProviders,

  // Session config — values in seconds, defaults match current behaviour
  session: {
    expiresIn: parseInt(process.env.SESSION_EXPIRES_IN  ?? String(60 * 60 * 24 * 7)),  // default 7 days
    updateAge:  parseInt(process.env.SESSION_UPDATE_AGE ?? String(60 * 60 * 24)),       // default 1 day
  },
});
```

The `socialProviders` object is also exported so the login page template
can check which providers are available and only render buttons for
enabled ones (e.g. `if ("google" in socialProviders) { ... }`).

### 1.3 Run better-auth migrations

```bash
pnpm dlx @better-auth/cli migrate
```

This creates the `user`, `session`, `account`, and `verification` tables in
`pds.sqlite` alongside the existing custom tables.

### 1.4 Mount better-auth on Express

In `packages/auth-service/src/index.ts`, mount the better-auth handler
alongside existing routes:

```typescript
import { toNodeHandler } from "better-auth/node";
import { auth } from "./better-auth";

// Mount better-auth BEFORE express.json() (per better-auth docs)
app.all("/api/auth/*", toNodeHandler(auth));

// Existing routes continue to work
app.use(express.json());
// ... existing route mounts
```

No files are deleted yet — better-auth runs alongside the existing code.

---

## Phase 2: Build the AT Protocol bridge

This is the critical custom layer. It connects better-auth's identity
verification to the AT Protocol OAuth flow.

### 2.1 The problem: threading `request_uri`

The AT Protocol OAuth flow starts with a PAR `request_uri` that must survive
the authentication process and arrive at `/oauth/magic-callback`.

Currently, this is threaded through HTML hidden form fields and stored in the
`magic_link_token` DB row. With better-auth, the OTP/social-login flow is
opaque — we can't embed `request_uri` in better-auth's internal state.

### 2.2 Solution: session-scoped `request_uri` storage

**Before redirecting to better-auth's login flow**, store the `request_uri` in
a short-lived record keyed to a random ID, and pass that ID through the flow
via a cookie or query parameter.

```
auth-service GET /oauth/authorize?request_uri=...&client_id=...
    │
    ├── Store { request_uri, client_id } in DB, keyed by random auth_flow_id
    ├── Set cookie: magic_auth_flow=<auth_flow_id> (10 min, httpOnly)
    │
    └── Render login page with options:
        ├── "Sign in with email" → auth-service better-auth emailOTP flow
        ├── "Sign in with Google" → auth-service better-auth Google OAuth flow
        └── "Recover with backup email" → auth-service custom recovery flow
```

After better-auth establishes a session (user verified), the auth-service
bridge route `/auth/complete`:

1. Reads the `magic_auth_flow` cookie to recover `auth_flow_id`
2. Looks up `{ request_uri, client_id }` from DB
3. Reads the better-auth session to get verified email
4. Redirects to pds-core `/oauth/magic-callback?request_uri=...&email=...&approved=1&sig=...`

### 2.3 New table: `auth_flow`

```sql
CREATE TABLE auth_flow (
  flow_id TEXT PRIMARY KEY,
  request_uri TEXT NOT NULL,
  client_id TEXT,
  email TEXT,            -- populated after verification
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
```

Cleanup: delete expired rows on the same 5-minute interval as existing token
cleanup.

### 2.4 New routes

All routes in this section are on the **auth-service** (`auth.pds.example`)
unless explicitly noted otherwise.

#### auth-service: `GET /oauth/authorize` (replaces existing)

This is the entry point from the pds-core AS metadata redirect. It becomes
a landing page offering multiple login methods.

```
Receives: ?request_uri=...&client_id=...&prompt=...&login_hint=...
Does:
  1. Create auth_flow row (flow_id, request_uri, client_id)
  2. Set magic_auth_flow cookie
  3. Resolve client metadata for branding (reuse existing resolver)
  4. Render login page with:
     - Email OTP form (calls better-auth /api/auth/* endpoints on auth-service)
     - "Sign in with Google" button (calls better-auth /api/auth/sign-in/google on auth-service)
     - "Sign in with GitHub" button
     - "Recover with backup email" link
```

**Delete on completion:** `routes/authorize.ts`, `routes/send-code.ts`,
`routes/verify-code.ts`, `magic-link/token.ts`, `magic-link/rate-limit.ts`,
`middleware/rate-limit.ts`, `middleware/csrf.ts`. Drop `magic_link_token`
table from auth-service SQLite. Drop `account_email` table — no longer
needed since pds-core uses `accountManager` directly and auth-service calls
`/_internal/account-by-email`. Delete `shared/src/db.ts` methods
`getDidByEmail`, `getDidFromPdsAccount`, `setAccountEmail`. Delete
`/_magic/check-email` from pds-core (replaced by `/_internal/account-by-email`
in Phase 0.4). Remove pds-core's `MagicPdsDb` instantiation — pds-core no
longer opens the auth-service database.

#### auth-service: `GET /auth/complete` (new — the bridge)

This is the route better-auth redirects to after successful authentication.
It's the `callbackURL` passed to better-auth's sign-in methods.

```
Does:
  1. Read magic_auth_flow cookie → get flow_id
  2. Look up auth_flow row → get request_uri, client_id
  3. Get better-auth session (via auth.api.getSession({ headers }))
  4. Extract verified email from session
  5. Check consent needed (reuse existing client_logins logic)
  6. If consent needed → redirect to auth-service /auth/consent?flow_id=...
  7. Otherwise → build signed redirect URL:
     - Compute HMAC-SHA256(request_uri || email || approved || new_account || ts, secret)
     - Redirect to pds-core /oauth/magic-callback?...&ts=...&sig=...
  8. Delete auth_flow row + clear cookie
```

The HMAC signature (Phase 0.1) ensures pds-core can cryptographically
verify that the auth-service actually authenticated the user. This is the
CRITICAL-1 fix applied to the new architecture.

#### auth-service: `GET/POST /auth/consent` (replaces existing)

Same consent screen logic, but reads `flow_id` from query instead of
`request_uri` directly. Looks up `auth_flow` to get `request_uri`.

**Delete on completion:** the old `routes/consent.ts` (replaced in-place).

### 2.5 Social provider callback handling

When a user signs in via Google, better-auth handles the entire OAuth
exchange internally on the auth-service (redirect to Google → Google
redirects back to auth-service `/api/auth/callback/google` → better-auth
creates user + session). The user's browser is then redirected to the
`callbackURL` we specified — which is auth-service `/auth/complete`.

From there, the bridge route picks up the verified email from the
better-auth session and continues the AT Protocol flow as normal.

**Account linking concern:** If a user first logged in with email OTP, then
later uses Google, better-auth links the Google account to the existing user
if the email matches. This is the desired behavior — same email = same
identity = same DID.

### 2.6 context.ts cleanup

Once the bridge is in place and the old OTP routes are deleted, remove
`tokenService` and `rateLimiter` from `context.ts`.

---

## Phase 3: Migrate account settings portal

### 3.1 Replace account session with better-auth session

The `/account/*` routes currently use a custom `account_session` table and
`magic_account_session` cookie. Replace this with better-auth's built-in
session.

**On completion, delete:** `middleware/account-auth.ts`,
`routes/account-login.ts`, `middleware/session.ts`. Drop `account_session`
table from `pds.sqlite`.

Replace `requireAuth(ctx)` with a wrapper that calls
`auth.api.getSession({ headers })`. The "Account Settings Login" flow
becomes: render login page → user authenticates via better-auth → session
established → redirect to auth-service `/account`.

### 3.2 What stays custom in account settings

These routes interact with PDS admin APIs and custom DB tables — they cannot
be replaced by better-auth:

| Route | Reason it stays custom |
|-------|----------------------|
| `POST /account/handle` | Calls `com.atproto.admin.updateAccountHandle` |
| `POST /account/delete` | Calls `com.atproto.admin.deleteAccount` |
| `POST /account/backup-email/*` | Custom backup_email table + verification |
| `POST /account/session/revoke` | Delegates to better-auth `revokeSession` |
| `POST /account/sessions/revoke-all` | Delegates to better-auth `revokeSessions` |

### 3.3 Metrics endpoint

Update auth-service `GET /metrics` to query better-auth's tables (user
count, session count) alongside the existing custom tables — all in
`pds.sqlite`.

---

## Phase 4: Add social providers

Since `buildSocialProviders()` auto-detects from env vars and the login
page template conditionally renders buttons based on what's in the exported
`socialProviders` object, enabling a new provider is just:

1. Add `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (or equivalent) to `.env`
2. Restart auth-service

For providers not yet in `buildSocialProviders()`, a one-line addition to
that function is needed. No changes to pds-core, the bridge route, or the
consent flow. The bridge always works the same way: read better-auth
session → extract email → redirect to magic-callback.

### Provider-specific concerns

**Google:** User's Google email must match their PDS account email for
account linking. If a user signs up with `alice@gmail.com` via OTP, then
later signs in via Google (which returns `alice@gmail.com`), better-auth
links the accounts automatically.

**Email mismatch risk:** If a user has a PDS account under `alice@a.com`
but signs in via Google as `alice@b.com`, the bridge will see `alice@b.com`
and either create a new PDS account or fail to find the existing one.
Mitigation: the login page should display the email being used and warn if
it differs from a known account. This is a UX concern, not a technical
blocker.

---

## Ideas from pds-gatekeeper

[pds-gatekeeper](https://tangled.org/baileytownsend.dev/pds-gatekeeper) is
a Rust microservice that adds 2FA and captcha to self-hosted PDSes by
intercepting specific XRPC endpoints at the reverse proxy layer (Caddy
routes certain paths to gatekeeper instead of the PDS). It also directly
accesses the PDS's SQLite databases.

### What we adopt

1. **Reverse proxy as a security boundary.** Gatekeeper's core pattern —
   Caddy routes specific XRPC endpoints to a gatekeeper process instead of
   the PDS — demonstrates that the reverse proxy layer is the right place to
   enforce access control for PDS endpoints. We don't need to intercept
   `createSession` (since passwordless accounts simply have no password to
   authenticate with), but the pattern is useful if we later want to add 2FA
   to password-based login (route `createSession` through a gatekeeper layer
   that verifies a second factor before proxying to the PDS).

2. **Captcha on account creation.** Gatekeeper supports requiring hCaptcha
   on `com.atproto.server.createAccount`. This is worth adding as a Phase 5+
   enhancement to prevent bot account creation. In our architecture, the
   captcha would live in the auth-service login page (before the
   `/auth/complete` bridge route creates the PDS account).

3. **Migration-only mode.** Gatekeeper's `GATEKEEPER_ALLOW_ONLY_MIGRATIONS`
   flag blocks `createAccount` except for account migrations (checks for
   `serviceAuth` token). This is a useful operational toggle we should
   support — configurable via env var.

### What we do differently

1. **No direct PDS SQLite access from the sidecar.** Gatekeeper mounts the
   PDS's `/pds` directory and reads its databases directly. This creates
   tight schema coupling — a PDS update could break gatekeeper. Our
   auth-service already uses a separate `pds.sqlite` and communicates
   with the PDS via authenticated HTTP endpoints (`/_magic/check-email`,
   admin XRPC calls). This is more robust.

2. **No endpoint interception for auth.** Gatekeeper intercepts the stock
   PDS `/@atproto/oauth-provider/~api/sign-in` endpoint and proxies through
   its 2FA layer. Our architecture instead replaces the
   `authorization_endpoint` entirely via AS metadata override, which is
   cleaner — the PDS's built-in sign-in UI is never shown.

3. **Auth middleware for custom endpoints.** Gatekeeper's `AuthRules` system
   (DID matching, handle suffix matching, scope checking) is a nice pattern
   for protecting custom XRPC endpoints. Not needed now but worth noting if
   we add custom XRPC endpoints later.

### Considered and rejected: single-domain architecture

Gatekeeper runs on the same domain as the PDS (Caddy routes by path, not
hostname). We considered this but kept the subdomain split for the reasons
already documented (cookie isolation, security header isolation, independent
deployability). The Caddy path-based routing is fine for Gatekeeper because
it's a thin interception layer — our auth service is a full web app with
HTML forms, static assets, and its own cookie domain.

---

## Risks and Open Questions

### Note: Two user stores (not a risk)

better-auth's `user` table and the PDS's `account` table in `account.sqlite`
both reference users, but they serve distinct, non-overlapping roles:
better-auth `user` = "who authenticated with the auth-service UI."
PDS `account` = the AT Protocol identity record. There is no
`account_email` mirror — `account.sqlite` is the single source of truth
for email→DID, accessed by pds-core directly and by auth-service via
`/_internal/account-by-email`. The bridge route is the only place these
two stores intersect, and it handles the lookup chain
(email → DID → create if missing).

### Risk: better-auth session vs AT Protocol session

better-auth's session (cookie-based, stored in `session` table) is for the
auth-service UI only. It has nothing to do with AT Protocol access/refresh
JWTs. These are separate authentication domains — same as today, where the
`magic_account_session` cookie is completely separate from AT Protocol
tokens.

### Risk: Cookie domain

better-auth sets a session cookie on `auth.pds.example`. This is fine — it's
the same domain the auth-service already uses for `magic_account_session`
and `magic_csrf`. No change in cookie scoping.

### Open question: Custom email templates

The current system supports client-specific email templates fetched from
`email_template_uri` in OAuth client metadata. better-auth's `emailOTP`
plugin has a `sendVerificationOTP` callback where you control email sending
entirely — so this can be preserved by calling the existing `EmailSender`
from within that callback.

However, the current template system needs the `client_id` to resolve
branding. During an email OTP flow, we'd need to pass the `client_id` from
the `auth_flow` row to the email sender. This is achievable by reading the
`magic_auth_flow` cookie in the `sendVerificationOTP` callback, or by
storing the `client_id` in better-auth's user metadata.

### Open question: Recovery via backup email

The current recovery flow allows login via a backup email that isn't the
primary. This is orthogonal to better-auth — it's a custom lookup that
says "this backup email maps to DID X." This flow should remain custom but
can use better-auth's OTP infrastructure for the verification step by
calling `auth.api.sendVerificationOTP()` directly.

### Open question: Anti-enumeration

The current system returns identical responses regardless of whether an
email exists (to prevent account enumeration). better-auth's `emailOTP`
plugin auto-creates users on sign-in by default. We can set
`disableSignUp: true` on the plugin and handle account creation ourselves
in the bridge route — but this changes the semantics. Alternatively, keep
`disableSignUp: false` and let better-auth create users freely (they're
just better-auth users, not PDS accounts — PDS account creation still
happens in the bridge).

**Recommendation:** Keep `disableSignUp: false`. Let better-auth create
users on first OTP sign-in. PDS account creation is handled separately in
the bridge/magic-callback. This maintains the current anti-enumeration
behavior (always send OTP, always show the code form).

### Open question: Consent screen should show actual scopes

Currently the consent screen hardcodes "Read and write posts, Access your
profile, Manage your follows" regardless of what the client actually
requested. The fix is to read the actual `scope` parameter from the PAR
request (available in the `auth_flow` table via the `request_uri`, which
can be resolved from `provider.requestManager.get()`). This is a pds-core
change — it should pass the requested scopes to the auth service as part
of the callback data, or the consent route should fetch them via an
internal API.

### Risk: HMAC secret management

Phase 0.1 introduces a shared secret (`MAGIC_CALLBACK_SECRET`) between two
services. Both Docker containers need it in their environment. If it's
compromised, the CRITICAL-1 fix is void. Mitigation: rotate the secret
periodically; store it in a secrets manager; never log it.

### Risk: 8-digit OTP UX

Longer codes are harder to type. 8 digits is still standard (many banking
apps use 8-digit codes). The UX impact is minimal, especially with
auto-fill on mobile. The security benefit (100x harder brute-force) far
outweighs the friction.

---

## Migration Order Summary

| Phase | Scope | Risk | Can be deployed independently? |
|-------|-------|------|-------------------------------|
| **0** | **Fix critical vulns: HMAC callback, 8-digit OTP, block stock login, protect check-email** | **Low** | **Yes — apply to current codebase immediately** |
| 1 | Install better-auth, mount alongside existing routes | Low | Yes — no behavior change |
| 2 | Build bridge layer, new login page with email OTP; delete replaced code | Medium | Yes — feature flag the new `/oauth/authorize` |
| 3 | Migrate account settings to better-auth sessions; delete replaced code | Low | Yes — after Phase 2 |
| 4 | Add social providers, captcha, migration-only mode | Low | Yes — just config + UI |

**Phase 0 is non-negotiable and should ship before anything else.** The
unsigned callback (CRITICAL-1) is an account-takeover vulnerability that
exists regardless of the better-auth migration. It can and should be fixed
in the current codebase today.

Each subsequent phase can be deployed and tested independently. Phase 2 is
the highest-risk phase and should be developed behind a feature flag or on a
staging environment first.

---

## Files Changed Summary

### Phase 0 changes (security fixes — apply to current codebase)

| File | Changes |
|------|---------|
| `packages/pds-core/src/index.ts` | Add HMAC verification to `/oauth/magic-callback`; add `/_internal/account-by-email` endpoint (replaces `/_magic/check-email`); change `password` to `undefined` in `createAccount` call |
| `packages/auth-service/src/routes/verify-code.ts` | Add HMAC signing to redirect URL |
| `packages/auth-service/src/routes/consent.ts` | Add HMAC signing to redirect URL |
| `packages/auth-service/src/lib/auto-provision.ts` | Change `password` to `undefined` in `createAccount` call |
| `packages/shared/src/crypto.ts` | Add `signCallback()` and `verifyCallback()` functions; change OTP to 8 digits |
| `.env.example` | Add `MAGIC_CALLBACK_SECRET`, `MAGIC_INTERNAL_SECRET` |

### New files (Phase 1+)

| File | Purpose |
|------|---------|
| `packages/auth-service/src/better-auth.ts` | better-auth configuration |
| `packages/auth-service/src/routes/complete.ts` | Bridge route: better-auth session → HMAC-signed AT Proto redirect |
| `packages/auth-service/src/routes/login-page.ts` | Unified login page with multiple methods |

### Modified files (Phase 1+)

| File | Changes |
|------|---------|
| `packages/pds-core/src/index.ts` | Replace `magicDb.*` calls in magic-callback with `pds.ctx.accountManager.getAccountByEmail()`; remove `MagicPdsDb` instantiation |
| `packages/auth-service/src/index.ts` | Mount better-auth handler, remove old middleware |
| `packages/auth-service/src/context.ts` | Remove tokenService, rateLimiter; add auth reference |
| `packages/auth-service/src/routes/consent.ts` | Read from auth_flow table |
| `packages/auth-service/src/routes/recovery.ts` | Use better-auth OTP; call `/_internal/account-by-email` for backup email lookup |
| `packages/auth-service/src/routes/account-settings.ts` | Use better-auth session instead of custom session |
| `packages/auth-service/src/email/sender.ts` | Keep; wire into sendVerificationOTP callback |
| `packages/shared/src/db.ts` | Add auth_flow table; remove account_email, getDidByEmail, getDidFromPdsAccount, setAccountEmail; drop magic_link_token + account_session |
| `packages/auth-service/package.json` | Add better-auth dependency |
| `.env.example` | Add `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `SESSION_EXPIRES_IN`, `SESSION_UPDATE_AGE` |

### Deleted files (inline with each phase)

| File | Deleted in |
|------|-----------|
| `packages/auth-service/src/magic-link/token.ts` | Phase 2 |
| `packages/auth-service/src/magic-link/rate-limit.ts` | Phase 2 |
| `packages/auth-service/src/middleware/csrf.ts` | Phase 2 |
| `packages/auth-service/src/middleware/rate-limit.ts` | Phase 2 |
| `packages/auth-service/src/middleware/session.ts` | Phase 2 |
| `packages/auth-service/src/routes/authorize.ts` | Phase 2 |
| `packages/auth-service/src/routes/send-code.ts` | Phase 2 |
| `packages/auth-service/src/routes/verify-code.ts` | Phase 2 |
| `packages/auth-service/src/middleware/account-auth.ts` | Phase 3 |
| `packages/auth-service/src/routes/account-login.ts` | Phase 3 |

### Unchanged

| File | Reason |
|------|--------|
| `packages/auth-service/src/lib/client-metadata.ts` | Still needed for branding |
| `packages/auth-service/src/lib/auto-provision.ts` | Still used by recovery path |
