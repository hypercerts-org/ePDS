# Iframe-Embedded Auth Flow

Design exploration for embedding the full auth-service login flow (OTP, consent,
handle picker) in a cross-origin iframe, so the user never leaves the client
app's page.

**Status:** Implemented and deployed (with temporary triage shortcuts)  
**Date:** 2026-04-08  
**Last updated:** 2026-04-08

## Goal

Any allowlisted client app can embed the auth-service UI in an iframe instead of
redirecting the user away. The user completes OTP verification, consent, and
handle selection without leaving the client page. When the flow completes, the
parent window receives the OAuth authorization code.

## Current Flow (redirect-based)

```
Client App                    PDS                     Auth Service
    |                          |                          |
    |-- POST /oauth/par ------>|                          |
    |<-- { request_uri } ------|                          |
    |                          |                          |
    |-- 302 browser redirect --|-- /oauth/authorize ----->|
    |                          |                          |-- render login page
    |                          |                          |-- (OTP send/verify via fetch)
    |                          |                          |-- 303 /auth/complete
    |                          |                          |-- 303 /auth/consent (maybe)
    |                          |                          |-- 303 /auth/choose-handle (maybe)
    |                          |                          |
    |                          |<-- 303 /oauth/epds-callback (HMAC-signed)
    |                          |-- 303 /api/oauth/callback?code=...&state=...
    |<-- token exchange ------>|                          |
    |-- redirect to /welcome   |                          |
```

The user leaves the client app at step 2 and doesn't return until the final
callback redirect. The entire auth-service UI (login, consent, handle picker)
renders as full pages on `auth.pds.example`.

## Proposed Flow (iframe-embedded)

```
Client App (parent window)         Auth Service (iframe)         PDS
    |                                    |                        |
    |-- POST /oauth/par (server-side) -->|                        |
    |<-- { request_uri } ---------------|                        |
    |                                    |                        |
    |-- create <iframe src="/oauth/authorize?...&epds_delivery=iframe"> -->|
    |                                    |-- render login page    |
    |                                    |-- OTP send/verify      |
    |                                    |-- consent (in-iframe)  |
    |                                    |-- handle picker        |
    |                                    |                        |
    |                                    |-- 303 /oauth/epds-callback (HMAC-signed)
    |                                    |                        |
    |                                    |<-- postMessage({ type: 'epds:auth-complete',
    |                                    |      code, state, iss })
    |<-- parent receives postMessage ----|                        |
    |-- token exchange (server-side) --->|                        |
    |-- update UI, no redirect           |                        |
```

Key difference: instead of the final redirect chain landing at the client app's
`/api/oauth/callback`, the auth flow terminates with a `postMessage` to the
parent window. The client app's JS receives the authorization code and completes
the token exchange via its own server.

## Terminology

- **`epds_delivery`** — query param on `/oauth/authorize` that signals iframe mode. Value: `iframe`. Absent means normal redirect flow.
- **`delivery`** — the column name in the `auth_flow` DB row. Values: `'redirect'` (default) | `'iframe'`. Extensible to `'popup'` in future.
- **`delivery` in HMAC params** — the field in `CallbackParams` that travels from auth-service to pds-core via the signed callback URL. This is the only leg where it needs to be explicitly passed — auth-service routes read it from the DB row via the flow cookie.

---

## Implementation Plan

### `packages/shared/`

#### `src/db.ts`

- Migration v9: `ALTER TABLE auth_flow ADD COLUMN delivery TEXT NOT NULL DEFAULT 'redirect'`
- Update `AuthFlowRow` interface: add `delivery: 'redirect' | 'iframe'`
- Update `createAuthFlow` to accept and store `delivery`
- Update `getAuthFlow` SELECT to include `delivery`

#### `src/crypto.ts`

- Add `delivery?: string` to `CallbackParams` interface
- Add as 7th field in the newline-joined HMAC payload: `params.delivery ?? 'redirect'`
- Update both `signCallback` and `verifyCallback` atomically — both sides must agree on the payload format

---

### `packages/auth-service/`

#### `src/routes/login-page.ts`

- Read `epds_delivery` from query string on `GET /oauth/authorize`
- Store `delivery: req.query.epds_delivery === 'iframe' ? 'iframe' : 'redirect'` in the `auth_flow` row at creation time
- When `flow.delivery === 'iframe'`, set `epds_auth_flow` and `epds_csrf` cookies with `SameSite=none; Secure; Partitioned` instead of `SameSite=lax`
- After flow lookup, call `res.removeHeader('X-Frame-Options')` and set `frame-ancestors` to the client's origin (derived from `PDS_OAUTH_TRUSTED_CLIENTS`) when `flow.delivery === 'iframe'`

#### `src/routes/complete.ts`

- After flow lookup, if `flow.delivery === 'iframe'`: `res.removeHeader('X-Frame-Options')` and set `frame-ancestors`
- Pass `delivery: flow.delivery` into `callbackParams` for `signCallback` on all exit paths

#### `src/routes/consent.ts` (flow-id mode only)

- After flow lookup, if `flow.delivery === 'iframe'`: override headers as above
- Pass `delivery: flow.delivery` into `callbackParams` for `signCallback`
- Note: legacy mode (direct query params, no flow lookup) does not support iframe delivery — this is acceptable since `complete.ts` always uses flow-id mode

#### `src/routes/choose-handle.ts`

- After `getFlowAndSession()`, if `flow.delivery === 'iframe'`: override headers as above
- Pass `delivery: flow.delivery` into `callbackParams` for `signCallback`
- The `handle_taken` redirect from pds-core back to `/auth/choose-handle` works correctly — the flow row is intentionally never deleted by this route, so `flow.delivery` survives the round-trip

#### `src/middleware/csrf.ts`

- When setting the `epds_csrf` cookie: look up the flow via `epds_auth_flow` cookie → if `flow.delivery === 'iframe'`, use `SameSite=none; Secure; Partitioned`

#### `src/index.ts`

- No change to the global security middleware — per-route `res.removeHeader` + `res.setHeader` after the flow lookup handles it correctly (Express sends headers at response finalisation, so route handlers overwrite middleware-set values)

---

### `packages/pds-core/`

#### `src/index.ts`

- Read `delivery` from the verified HMAC callback params
- In Step 8 of `/oauth/epds-callback`, add a third branch alongside `query` and `fragment`:

```ts
if (delivery === 'iframe') {
  const targetOrigin = new URL(redirectUri).origin
  res.removeHeader('X-Frame-Options')
  res.setHeader('Content-Security-Policy', `frame-ancestors ${targetOrigin}`)
  res.type('html').send(
    renderPostMessagePage({
      type: 'epds:auth-complete',
      code,
      state: parameters.state,
      iss: pdsUrl,
      targetOrigin,
    }),
  )
} else if (responseMode === 'fragment') {
  // existing code unchanged
} else {
  // existing code unchanged
}
```

- New `renderPostMessagePage()` template: tiny HTML page, fires `window.parent.postMessage(payload, targetOrigin)` on `DOMContentLoaded`, no links, no external resources
- Apply the same `delivery === 'iframe'` branch to the **error path** (lines 359–372): send `{ type: 'epds:auth-error', error: 'server_error' }` postMessage instead of redirecting to `redirect_uri?error=...`

---

### `packages/demo/` — reference implementation

#### `src/app/api/oauth/login/route.ts`

- When request has `?delivery=iframe`, return `{ authorizeUrl: '...&epds_delivery=iframe' }` JSON instead of 302 redirect
- In PAR DPoP nonce-retry path, apply the same iframe JSON behavior (do not redirect in `delivery=iframe`), otherwise browser `fetch()` follows cross-origin redirect and fails CORS

#### `src/app/api/oauth/exchange/route.ts` — new file

- `POST` endpoint: receives `{ code, state, iss }` from client-side JS
- Validates `state` against the signed OAuth session cookie
- Exchanges code for tokens using same DPoP logic as existing `/api/oauth/callback`
- Sets session cookie, returns `{ ok: true }`
- Client-side JS updates the page — no redirect

#### `src/app/components/EmbeddedLogin.tsx` — new file

- Calls `/api/oauth/login?delivery=iframe` to get the authorize URL
- Renders `<iframe src={authorizeUrl}>` inside a modal/overlay
- Modal opens immediately on click; spinner overlay is shown from start and removed on iframe `onLoad`
- Listens for `postMessage` — validates `event.origin` matches the expected PDS origin before acting
- On `epds:auth-complete`: calls `POST /api/oauth/exchange` with `{ code, state, iss }`, then updates UI
- On `epds:auth-error`: shows error state, destroys iframe
- Intercepts `popstate` to prevent parent-page back-navigation destroying the flow mid-auth
- Includes temporary debug logs for message-origin and exchange diagnostics during deployment triage

#### `src/app/flow-embed/page.tsx` — new file

- Demo page showing the embedded flow in action
- Currently hardcodes `pdsOrigin` as a temporary deployment workaround (to validate origin mismatch issues)

---

## What does not change

| Thing                              | Why                                                                                                                                                                               |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connect-src 'self'` CSP           | Fetch calls inside the iframe are same-origin (`auth.pds.example`) — no change needed                                                                                             |
| `window.location.href` navigations | Navigate the iframe correctly, not the parent — no change needed                                                                                                                  |
| better-auth session cookie         | **Changed during deployment triage:** configured for iframe compatibility using `SameSite=None; Secure; Partitioned` to ensure `/auth/complete` can read session in embedded flow |
| CSRF validation logic              | Double-submit pattern is unchanged — only the cookie attribute changes                                                                                                            |
| Social login buttons               | Not supported in iframe mode — no change needed                                                                                                                                   |
| `X-Frame-Options: ALLOW-FROM`      | Dropped entirely — never supported by Chrome or Safari, removed from Firefox 70                                                                                                   |

---

## Key decisions

| Question                                           | Decision                                                                                                                                                                                   |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Allowlist source                                   | `PDS_OAUTH_TRUSTED_CLIENTS` env var — extract origins from the client_id URLs                                                                                                              |
| Cookie policy                                      | `SameSite=none; Secure; Partitioned` (CHIPS) for `epds_auth_flow` and `epds_csrf` in iframe mode only. CHIPS now has universal browser support (Chrome 114+, Firefox 141+, Safari 26.2+)   |
| better-auth session cookie                         | Updated for deployed iframe flow: better-auth default cookie attributes set to `SameSite=None; Secure; Partitioned`                                                                        |
| `delivery` propagation between auth-service routes | Stored in `auth_flow` DB row, read by all routes via `epds_auth_flow` cookie lookup — no query param threading                                                                             |
| `delivery` propagation to pds-core                 | Via HMAC-signed callback params — the only cross-service boundary                                                                                                                          |
| `response_mode=web_message`                        | Rejected — `OAuthResponseMode` in the atproto SDK is a strict Zod enum (`query \| fragment \| form_post`) that doesn't include `web_message` and can't be extended without forking the SDK |
| `X-Frame-Options` in iframe mode                   | Removed per-response via `res.removeHeader('X-Frame-Options')` in route handlers after flow lookup                                                                                         |
| postMessage target origin                          | Always `new URL(redirectUri).origin` — never `*`                                                                                                                                           |
| Error postMessage                                  | `{ type: 'epds:auth-error', error: '...' }` on terminal errors and user deny                                                                                                               |

---

## Security considerations

### Clickjacking

Embedding the auth flow in an iframe is what clickjacking attacks exploit.
The difference here is an explicit allowlist derived from `PDS_OAUTH_TRUSTED_CLIENTS`.
Only origins in that list get a `frame-ancestors` directive — all other origins
are blocked by the default `X-Frame-Options: DENY`.

Mitigations:

- The user must actively type their OTP — pure click-overlay attacks don't work
- The consent screen shows which app is requesting access
- The authorization code is delivered via postMessage to the `redirect_uri`
  origin only (never `*`)

### Cookie downgrade (`SameSite=none`)

`epds_auth_flow` and `epds_csrf` cookies use `SameSite=none; Secure; Partitioned`
in iframe mode. During deployment triage, better-auth session cookies were also
configured with `SameSite=none; Secure; Partitioned` so `/auth/complete` can
reliably read session state inside the iframe. The `Partitioned` attribute
(CHIPS) scopes these cookies to the (top-level-site, service-site) pair — a
different top-level site gets a different partition and cannot see or trigger
these cookies. CHIPS has universal browser support: Chrome 114+, Firefox 141+,
Safari 26.2+.

### Token leakage via postMessage

The authorization code is sent via `window.parent.postMessage(...)`. The
`targetOrigin` must always be `new URL(redirectUri).origin` — never `*`. This
ensures only the registered client origin can receive the code.

### Session fixation

Not a concern in current implementation: session and flow cookies are
`httpOnly`, flow cookie is short-lived (10 min), and callback delivery uses
strict `postMessage` target origin (`redirect_uri` origin, never `*`).

---

## Notes

### Existing CSP precedent

The global security middleware in `auth-service/src/index.ts` already reads
`client_id` from the query string to add the client's origin to `img-src` (for
client branding logos). The `frame-ancestors` change follows the exact same
pattern — read the client origin, add it to the CSP directive.

### Migration version

The `auth_flow` table was created in migration v6, `handle_mode` column added in
v8. The `delivery` column will be migration v9.

### Legacy consent path

`consent.ts` has a legacy mode that reads `request_uri`/`email`/`client_id`
directly from query params without touching the `auth_flow` table. This path
does not support iframe delivery. This is acceptable because `complete.ts`
always redirects to consent using `flow_id` mode — the legacy path is
unreachable from an iframe flow.

---

## Effort estimate

| Area                                    | Estimate      |
| --------------------------------------- | ------------- |
| `shared/` DB + crypto changes           | 0.5 day       |
| `auth-service/` cookie + header changes | 1 day         |
| `auth-service/` delivery flag in routes | 1 day         |
| `pds-core/` postMessage endpoint        | 0.5 day       |
| `demo/` iframe integration              | 1–2 days      |
| Testing                                 | 1 day         |
| **Total**                               | **~5–6 days** |

---

## Deployment issues and fixes (Railway)

### 1) CORS error after clicking Sign in in iframe mode

**Symptom**

- Browser error: fetch to auth `/oauth/authorize` blocked by CORS.
- Request path showed redirect from `/api/oauth/login?delivery=iframe`.

**Root cause**

- In `packages/demo/src/app/api/oauth/login/route.ts`, the PAR DPoP nonce-retry path still returned `NextResponse.redirect(authUrl)` even when `delivery=iframe`.
- Browser `fetch()` followed the cross-origin redirect and failed CORS.

**Fix**

- Added missing iframe branch in nonce-retry success path:
  - return JSON `{ authorizeUrl: '...&epds_delivery=iframe' }`
  - set OAuth session cookie
  - keep redirect behavior only for non-iframe mode.

### 2) OTP verified, then flow looped back to email screen

**Symptom**

- After OTP verification, `/auth/complete` redirected back to login page.

**Root cause**

- better-auth session cookie was not reliably available in cross-origin iframe context.

**Fix**

- Updated better-auth cookie defaults for iframe compatibility:
  - `SameSite=None`
  - `Secure=true`
  - `Partitioned=true`

### 3) Framing blocked by CSP / X-Frame-Options

**Symptom**

- Browser error:
  - `frame-ancestors 'self'` block, or
  - `X-Frame-Options: DENY`.

**Root cause**

- `PDS_OAUTH_TRUSTED_CLIENTS` configured with bare hostname instead of full URL.
- Code parses entries with `new URL(...)`; invalid entries collapsed allowlist to empty, resulting in `'self'` only.

**Fix**

- Set `PDS_OAUTH_TRUSTED_CLIENTS` using full URL values (prefer client metadata URL), e.g.:
  - `https://<demo-domain>/client-metadata.json`
- Verified `frame-ancestors` includes demo origin.

### 4) Blank iframe at end of flow (postMessage not consumed)

**Symptom**

- pds-core logs showed `Auth code issued via postMessage`, but parent UI stayed stuck on blank iframe.

**Root cause**

- `EmbeddedLogin` dropped messages due origin mismatch:
  - `event.origin` from pds-core did not equal `expectedOrigin`.
  - `expectedOrigin` resolved to fallback `https://localhost:3000`.

**Fix**

- Added frontend diagnostics before origin check.
- For immediate validation, hardcoded `pdsOrigin` in `flow-embed/page.tsx` to deployed pds-core URL.

### 5) UX issue: white screen before iframe content appears

**Symptom**

- Modal showed empty white area while iframe loaded.

**Fix**

- Updated `EmbeddedLogin` UX:
  - modal opens immediately on click
  - spinner overlay shown from start
  - overlay removed on iframe `onLoad`
  - cancel remains available.

## Temporary shortcuts currently in repo

1. **Hardcoded pds origin in demo page**
   - `packages/demo/src/app/flow-embed/page.tsx` currently uses a fixed URL for `pdsOrigin`.
   - This was done to quickly validate origin-filtering issues in production.

2. **Verbose debug logs in `EmbeddedLogin`**
   - Logs include message origin/payload and exchange call traces.

## Remaining gaps / follow-up (if pursuing hardening)

1. Replace hardcoded `pdsOrigin` with robust runtime configuration.
2. Reduce or gate frontend debug logs for production.
3. Add deployment-time validation for `PDS_OAUTH_TRUSTED_CLIENTS` format (must be valid URLs).
4. Add regression tests for:
   - PAR nonce-retry iframe path
   - postMessage origin handling
   - iframe completion path to `/api/oauth/exchange`.
