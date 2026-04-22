# Design: Fix Consent Flow to Use Upstream OAuth UI

## Problem

The ePDS consent page (`packages/auth-service/src/routes/consent.ts`) is a
broken reimplementation of the consent UI that already exists in the upstream
`@atproto/oauth-provider-ui` package. Specifically:

1. **Hard-coded permissions** — the consent page shows "Read and write posts",
   "Access your profile", "Manage your follows" regardless of what OAuth scopes
   the client actually requested.

2. **Ignores OAuth scopes entirely** — never reads `parameters.scope` from the
   PAR request. A client requesting `transition:chat.bsky` would still see
   generic permissions.

3. **Separate consent tracking** — uses its own `client_logins` table
   (`hasClientLogin` / `recordClientLogin`) instead of the atproto provider's
   built-in `authorizedClients` tracking, which already handles scope-level
   consent (re-prompting when new scopes are requested).

4. **Missing consent on signup** — the new-user flow (handle picker →
   `epds-callback`) bypasses `complete.ts` step 5c, so `recordClientLogin` is
   never called. The user sees the consent page on their second login instead
   of their first.

## Root Cause

The `epds-callback` endpoint bypasses the stock OAuth middleware entirely. It
calls `requestManager.get()` and `requestManager.setAuthorized()` directly
instead of going through `provider.authorize()`, which is what the stock PDS
uses (via `oauthMiddleware` in `auth-routes.ts`).

The stock PDS delegates the full authorization UI to `oauthMiddleware` from
`@atproto/oauth-provider`, which serves a React-based UI from the
`@atproto/oauth-provider-ui` package. This UI includes a proper consent view
(`consent-view.tsx`) that displays actual requested scopes/permissionSets.

## Fix: Hand Back to the Stock OAuth Flow After Authentication

After the auth-service authenticates the user (OTP) and pds-core creates the
account (if new), redirect back through the stock `/oauth/authorize` endpoint
instead of calling `setAuthorized()` directly.

### Flow Change

**Current flow (broken consent):**

```text
OTP verify → /auth/complete → check consent (auth-service) →
  → show broken consent page (auth-service) →
  → /oauth/epds-callback → setAuthorized() → redirect to client
```

**Fixed flow:**

```text
OTP verify → /auth/complete →
  → /oauth/epds-callback → create account if needed, upsertDeviceAccount →
  → redirect to /oauth/authorize?request_uri=... (stock middleware) →
  → stock middleware calls provider.authorize() →
  → if consent needed: renders upstream consent-view.tsx with real scopes →
  → if no consent needed: auto-approves (SSO match) →
  → redirect to client
```

### Implementation Steps

#### Step 1: Modify `epds-callback` to redirect through stock OAuth flow

In `packages/pds-core/src/index.ts`, after account creation and
`upsertDeviceAccount`, instead of calling `requestManager.setAuthorized()`
and building the redirect URL ourselves:

- Redirect to `/oauth/authorize?request_uri=<requestUri>&client_id=<clientId>`
- The stock `oauthMiddleware` will handle this request, find the existing
  device session (just created via `upsertDeviceAccount`), check consent via
  `provider.authorize()`, and either auto-approve or show the upstream
  consent UI.

The `epds-callback` handler should **stop calling**:

- `requestManager.setAuthorized()`
- `provider.checkConsentRequired()`
- `provider.accountManager.setAuthorizedClient()`

These are all handled internally by the stock middleware when it processes the
`/oauth/authorize` redirect.

#### Step 2: Remove auth-service consent page

Delete or disable:

- `packages/auth-service/src/routes/consent.ts`
- The consent route registration in `packages/auth-service/src/index.ts`
- The `needsConsent` check in `packages/auth-service/src/routes/complete.ts`
  (step 5b) — the auth-service no longer decides whether consent is needed
- `ctx.db.hasClientLogin()` and `ctx.db.recordClientLogin()` methods
- The `client_login` table (add a migration to drop it)

#### Step 3: Simplify `complete.ts`

`/auth/complete` no longer needs to check consent. Its only job is:

1. Verify the auth flow cookie and better-auth session
2. For new users → redirect to `/auth/choose-handle`
3. For existing users → redirect to `/oauth/epds-callback` (which then
   redirects through the stock OAuth flow)

#### Step 4: Verify the stock middleware handles the redirect correctly

The key assumption to verify: when `oauthMiddleware` receives
`/oauth/authorize?request_uri=...` and finds an existing device session
(created by `upsertDeviceAccount` moments earlier), it should:

- Call `provider.authorize()` which returns `sessions` with
  `consentRequired` and `loginRequired` flags
- Since `loginRequired` should be false (device session just created) and
  `consentRequired` depends on whether this client was previously authorized,
  it should either auto-approve or show consent
- The `permissionSets` from the requested scopes will be displayed correctly

**Risk**: the stock middleware might require a full browser login flow (cookies,
CSRF) rather than just a device session. This needs to be tested. If the
middleware requires its own session state, we may need to ensure that the
device session created by `upsertDeviceAccount` is sufficient for the
middleware to recognize the user as authenticated.

### Consent-Skip on Sign-Up

For trusted clients, a new user flow can optionally skip the consent screen
entirely on initial sign-up. This requires all three conditions:

1. **`PDS_SIGNUP_ALLOW_CONSENT_SKIP=true`** in the PDS environment
2. **Client is trusted** — listed in `PDS_OAUTH_TRUSTED_CLIENTS`
3. **Client metadata** includes `"epds_skip_consent_on_signup": true`

When all conditions are met, `epds-callback` issues the authorization code
directly (via `requestManager.setAuthorized()`) and records the client's
scopes as authorized (via `setAuthorizedClient()`). The browser goes straight
to the client app without any intermediate screen.

When consent-skip does NOT apply (e.g. untrusted client, env var disabled),
new users are redirected to `/oauth/authorize?prompt=consent`, which skips
the account selection screen (unnecessary for a just-created account) and
shows the upstream consent UI directly.

Existing users always go through the normal `/oauth/authorize` flow (no
`prompt` override) which auto-approves or shows consent as appropriate.

### What This Fixes

- Consent page shows actual requested scopes (from upstream `consent-view.tsx`)
- Consent tracking uses the atproto provider's `authorizedClients` system
  (scope-aware, re-prompts for new scopes)
- No more hard-coded "Read and write posts" etc.
- No more separate `client_login` table
- New users see consent at the right time (determined by the provider)
- Trusted clients can skip consent on sign-up (opt-in, triple-gated)
- Removes ~250 lines of auth-service code (`consent.ts` + DB methods)

### Research Findings (Resolved Questions)

1. **Device identification** — the stock middleware uses `dev-id` and `ses-id`
   HTTP cookies (set by `deviceManager.load()` with ~10-year expiry). Since
   the browser carries these cookies on both the original `/oauth/authorize`
   visit and the redirect back from `epds-callback`, the deviceId will match.
   `upsertDeviceAccount(deviceId, sub)` creates the device-account association
   that `authorize()` finds via `listDeviceAccounts(deviceId)`.

2. **PAR request state** — `requestManager.get()` called WITHOUT a deviceId
   (as we now do in `epds-callback`) does NOT bind a deviceId to the request.
   When the stock middleware subsequently calls `get(requestUri, deviceId,
clientId)`, it binds the browser's deviceId for the first time. This is
   the expected PAR → redirect → authorize flow.

3. **Auto-approve conditions** — `provider.authorize()` auto-approves when:
   - `prompt=none` with a single matching session (no login/consent required)
   - No explicit prompt + `login_hint` matching one session (no login/consent)
   - For unauthenticated clients (`token_endpoint_auth_method: 'none'`),
     `requestManager.validate()` forces `prompt: 'consent'`, so consent is
     always shown — this is correct behavior.

4. **Consent UI rendering** — the stock middleware serves a React SPA from
   `@atproto/oauth-provider-ui`. It injects hydration data (requestUri,
   clientMetadata, scope, permissionSets, sessions with consentRequired flags)
   as `window.__authorizeData`. The SPA calls back to
   `/oauth/authorize/api/consent` which internally calls `setAuthorized()`.

5. **AS metadata override** — the redirect from `epds-callback` to
   `/oauth/authorize` is a 303 redirect on the same pds-core host. The AS
   metadata's `authorization_endpoint` (pointing to the auth service) is
   irrelevant here since the browser follows the redirect directly.
