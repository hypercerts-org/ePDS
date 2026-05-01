# PDS White-Boxing: Internal Dependencies on @atproto

This document catalogues where the ePDS codebase relies on internal,
non-exported, or undocumented behavior of the upstream `@atproto/pds` and
`@atproto/oauth-provider` packages. These are all forms of technical debt
arising from wrapping the PDS and modifying its behavior.

Any upstream version bump should be checked against this list.

## Critical Risk (core authorization flow breaks)

### 1. `provider.requestManager` — not re-exported

**File:** `packages/pds-core/src/index.ts` (4 call sites)

`requestManager` is a `public readonly` property on `OAuthProvider`, but the
`RequestManager` class is not re-exported from the package's `index.ts`, so
TypeScript cannot see the type. All access requires `as any` casts.

Methods used:

- `.get(requestUri, deviceId?)` — fetches a pending authorization request.
  Also has an **undocumented side effect** of resetting the `expiresAt`
  sliding window (see item 8 below). Used in the `/oauth/epds-callback`
  handler and the `/_internal/ping-request` keepalive.
- `.setAuthorized(requestUri, client, account, deviceId, deviceMetadata)` —
  marks a request as authorized and issues an authorization code. Used in the
  consent-skip path.
- `.store.readRequest(requestId)` / `.store.updateRequest(requestId, data)` —
  direct store access to patch the PAR request's stored `parameters`. Used to
  set `login_hint` for new accounts so the stock authorize UI auto-selects the
  session and skips account selection. The provider already mutates parameters
  during `validate()` (forcing `prompt: 'consent'` for unauthenticated clients),
  so this is consistent with upstream behavior.

**Breakage scenario:** Method renamed, signature changed, or `requestManager`
made private. The entire authorization code issuance flow stops working.

### 2. `provider.accountManager.createAccount()` signature

**File:** `packages/pds-core/src/index.ts` (2 call sites)

```ts
provider.accountManager.createAccount(deviceId, deviceMetadata, {
  locale,
  handle,
  email,
  password,
  inviteCode,
})
```

The call assumes:

- `createAccount` takes `(deviceId, deviceMetadata, opts)` with those exact
  option keys
- A real password string is **required** — passing `undefined` skips
  `registerAccount()` internally, leaving the `account` table empty and
  breaking `upsertDeviceAccount()` FK constraints
- Returns an `Account` object with a `.sub` property (the DID)

The `Account` type is not exported, so the return value is typed `any`.

**Breakage scenario:** Parameter reordering, new required fields, or password
handling changes. Account creation fails entirely.

### 3. `pds.ctx.oauthProvider`

**File:** `packages/pds-core/src/index.ts`

All OAuth provider access goes through `pds.ctx.oauthProvider`. If this
property is renamed or made private, the entire ePDS integration is dead.

### 4. Express `_router.stack` manipulation

**File:** `packages/pds-core/src/index.ts` (lines ~405–421)

The AS (Authorization Server) metadata override injects middleware by
directly manipulating Express's undocumented `_router.stack` array:

```ts
const stack = (pds.app as any)._router?.stack
```

It locates a layer named `expressInit` and inserts a metadata-rewriting
middleware before the PDS's own handlers.

**Breakage scenario:** Any Express major version could remove `_router`,
rename `stack`, or change `expressInit`. The metadata override would silently
stop working, serving stock metadata instead of pointing
`authorization_endpoint` at the auth service subdomain. OAuth clients would
be sent to the wrong URL.

### 5. `sec-fetch-site` validation on `/oauth/authorize`

**File:** `packages/pds-core/src/lib/sec-fetch-site-rewrite.ts`,
`packages/pds-core/src/index.ts`

The upstream `@atproto/oauth-provider` validates the `sec-fetch-site` request
header on `GET /oauth/authorize` and allows `same-origin`, `cross-site`, and
`none` — but rejects `same-site`. There is a
[`@TODO`](https://github.com/bluesky-social/atproto/blob/2a9221d244a0821490458785d70d100a6943ea91/packages/oauth/oauth-provider/src/router/create-authorization-page-middleware.ts#L75-L77)
in the upstream source acknowledging this gap.

ePDS puts the auth service on a subdomain of the PDS (e.g.
`auth.pds.example` / `pds.example`). When the browser follows the 303
redirect chain from auth → PDS `/oauth/epds-callback` → PDS
`/oauth/authorize`, it sends `sec-fetch-site: same-site` because the chain
crosses origins within the same registrable domain.

pds-core works around this by injecting middleware (via the same
`_router.stack` manipulation as item 4) that rewrites `same-site` →
`same-origin` before the request reaches the upstream validation.

**Breakage scenario:** If the upstream validation logic moves to a different
layer (e.g., a lower-level HTTP handler that runs before Express middleware),
or if additional endpoints gain the same validation, the middleware workaround
would need updating. Also at risk if the upstream `@TODO` is resolved by
adding `same-site` to the allowed list — the middleware would become a no-op
(harmless but unnecessary).

## High Risk (individual features break)

### 6. `pds.ctx.accountManager` methods

**File:** `packages/pds-core/src/index.ts` (multiple internal endpoints)

Methods accessed on the PDS-level account manager:

| Method                     | Usage                         | Assumed return type       |
| -------------------------- | ----------------------------- | ------------------------- |
| `getAccountByEmail(email)` | DID lookup for email          | `{ did: string } \| null` |
| `getAccount(handleOrDid)`  | Polymorphic handle/DID lookup | `{ did, email } \| null`  |

**Note:** There are **two different `accountManager` instances** in play:
`pds.ctx.accountManager` (PDS-level, manages the SQLite account table) and
`provider.accountManager` (OAuth-provider-level, manages OAuth sessions).
The code assumes these are kept in sync by the upstream PDS.

### 7. `provider.deviceManager.load()`

**File:** `packages/pds-core/src/index.ts`

```ts
const deviceInfo = await provider.deviceManager.load(
  req as unknown as http.IncomingMessage,
  res as unknown as http.ServerResponse,
)
```

Assumes `deviceManager.load()` accepts raw Node.js request/response objects
and returns `{ deviceId, deviceMetadata }`. The double cast
(`as unknown as http.IncomingMessage`) strips Express-specific properties.

### 8. PAR inactivity timeout assumption

**Files:** `packages/pds-core/src/index.ts`, `packages/auth-service/src/routes/choose-handle.ts`

The `/_internal/ping-request` endpoint relies on:

- `AUTHORIZATION_INACTIVITY_TIMEOUT` being 5 minutes (hardcoded in
  `@atproto/oauth-provider/src/constants.ts`)
- `requestManager.get()` resetting `expiresAt` as a side effect

If the timeout value changes, or if `.get()` stops refreshing the expiry
(e.g., becomes a pure read), the handle picker would fail for users who take
more than the timeout duration.

The right fix is to upstream a public keepalive/refresh API on
`@atproto/oauth-provider`.

### 9. OAuth consent tracking (consent-skip path)

**File:** `packages/pds-core/src/index.ts`

When `PDS_SIGNUP_ALLOW_CONSENT_SKIP` is enabled, the consent-skip code path
uses several provider internals to issue an authorization code directly:

- `provider.clientManager.getClient(clientId)` — fetches the `Client` object.
  The returned `client.info.isTrusted` boolean is used to gate consent-skip.
  `clientManager` is a `public readonly` property but `ClientManager` and
  `Client` are not re-exported.
- `provider.requestManager.get(requestUri, deviceId)` — binds the device to
  the PAR request (same as item 1 above).
- `provider.requestManager.setAuthorized(requestUri, client, account, deviceId, deviceMetadata)` —
  issues the authorization code (same as item 1 above).
- `provider.accountManager.setAuthorizedClient(account, client, { authorizedScopes })` —
  records the client as authorized so future logins can auto-approve.

The normal (non-skip) consent path delegates to the stock `/oauth/authorize`
endpoint and does not use these internals.

### 10. `provider.metadata`

**File:** `packages/pds-core/src/index.ts`

```ts
res.json({ ...provider!.metadata, authorization_endpoint: '...' })
```

Assumes `metadata` is a plain spreadable object containing standard AS
metadata fields.

### 15. Device-session cookie names for cross-subdomain rewrite

**File:** `packages/pds-core/src/cookie-domain.ts`, wired in
`packages/pds-core/src/index.ts`

When `AUTH_HOSTNAME` is a subdomain of `PDS_HOSTNAME`, pds-core installs a
middleware that rewrites outbound `Set-Cookie` headers to inject
`Domain=<parent>` so the auth-service sibling subdomain can read the upstream
device-session cookies. The set of cookie names to rewrite is **hardcoded**:

```ts
export const DEVICE_COOKIE_NAMES = new Set<string>([
  'dev-id',
  'ses-id',
  'dev-id:hash',
  'ses-id:hash',
])
```

These names are `@atproto/oauth-provider` internals — the two device-session
cookies and their signed-`:hash` sidecars. The middleware also wraps
`res.appendHeader` because upstream's cookie helper writes via Node's
`appendHeader` directly rather than through `setHeader`.

**Breakage scenario:** Upstream renames `dev-id`/`ses-id`, adds a new
session cookie (e.g. a rotated second device ID), or drops the `:hash`
sidecar convention. The rewrite silently no-ops for the renamed cookies,
they stay host-only on the pds-core hostname, the auth-service cannot see
them, and cross-client session reuse regresses to "email/OTP every time"
without any error. Also at risk if upstream switches from `appendHeader` to
a different Node API for writing `Set-Cookie`.

### 16. `/account` chooser HTML rewrite and `__deviceSessions` payload

**File:** `packages/pds-core/src/chooser-enrichment.ts`, wired in
`packages/pds-core/src/index.ts`

Middleware intercepts HTML responses for `GET /oauth/authorize` and
`GET /account*` and injects a `<script>` tag at the start of `<head>` that
(a) appends each bound account's email next to its handle in the chooser UI,
(b) hides upstream's "Sign up" button on the chooser (ePDS routes signup
through auth-service, not upstream), and (c) rebinds upstream's "Another
account" button (`<div role="button" aria-label="Login to account that is
not listed">`) with a capture-phase click listener that hard-navigates to
`auth.<host>/oauth/authorize?prompt=login&<orig params>`, beating React's
delegated root-level click handler and preventing the SPA from swapping
the chooser for its stock sign-in form. The injected script reads two
upstream globals set by the server-rendered SPA:

```ts
// /oauth/authorize inline chooser
interceptGlobal('__sessions')
// /account standalone SPA
interceptGlobal('__deviceSessions')
```

Both carry `{ account: { sub, email, preferred_username, ... } }` entries.
The enrichment script then walks the rendered DOM looking for leaf elements
whose own text contains a known handle or DID, and appends the email as a
sibling span. The middleware also appends a `sha256-<hash>` of the injected
script to the response's CSP `script-src` directive.

Per-request, the middleware additionally resolves the current OAuth flow's
handle-assignment mode (query `epds_handle_mode` → client metadata
`epds_handle_mode` → `EPDS_DEFAULT_HANDLE_MODE` env → `picker-with-random`,
shared with auth-service via `resolveHandleMode` in
`@certified-app/shared`) and injects a `<meta name="epds-handle-mode">`
tag alongside the enrichment script. When the mode resolves to `random`,
the runtime script hides each handle row and exposes the handle via a
`title=` tooltip on the email label — the email remains the primary
identifier. `meta` elements do not contribute to `script-src`, so the
enrichment script stays hash-stable across all requests.

Depends on:

- The `/account` and `/oauth/authorize` chooser routes being server-rendered
  HTML that the middleware can rewrite in-flight (not a pure SPA fetching
  JSON post-load).
- The global variable names `__sessions` and `__deviceSessions`.
- The account payload shape (`sub`, `email`, `preferred_username`).
- The chooser rendering handle text as visible DOM text that a tree-walker
  can find.

**Breakage scenario:** Upstream renames the globals, changes the account
payload shape, restructures the chooser into a JSON-fetching SPA, or drops
the `/account` route. The enrichment silently fails — the page still
renders because the script is fail-safe — and users see stock upstream
handle-only rows again with no email disambiguation and no "Use a different
account" escape hatch.

### 17. `dev-id` cookie detection on the auth-service side

**File:** `packages/auth-service/src/lib/session-reuse.ts`, called from
`packages/auth-service/src/routes/login-page.ts`

The auth-service's `GET /oauth/authorize` route reads the upstream
`dev-id` cookie directly to decide whether to bypass its own email/OTP form
and redirect to pds-core's stock `/oauth/authorize`:

```ts
export function hasDeviceSessionCookie(req: SessionReuseRequest): boolean {
  if (req.cookies && typeof req.cookies['dev-id'] === 'string') return true
  const raw = req.headers.cookie ?? ''
  return /(?:^|;\s*)dev-id=/.test(raw)
}
```

The auth-service does not parse or verify the cookie; it just treats
presence as "the browser has an upstream device session, defer to pds-core".

**Breakage scenario:** Same `dev-id` rename/removal risk as item 15. If
upstream renames or splits the device-session cookie, this check returns
`false` for all requests, session reuse silently regresses, and every
re-authorization prompts for email/OTP again. If upstream starts setting
`dev-id` under circumstances that don't actually indicate a usable device
session, we'd redirect unconditionally and the user would bounce through
pds-core back to the auth-service in a loop.

### 18. Welcome-page guard pre-routes `/oauth/authorize` and `/account*`

**File:** `packages/pds-core/src/auth-ui-guard.ts`, wired in
`packages/pds-core/src/index.ts`

A pre-route Express middleware intercepts `GET /oauth/authorize` and
`GET /account*` before upstream's signin handler runs, parses the
`dev-id`/`ses-id` cookie pair side-effect-free, and calls
`provider.accountManager.listDeviceAccounts(deviceId)` to count bound
accounts on the device. If the cookies are missing/malformed or the
device has zero bindings, it responds `303` to auth-service's email
form and clears the stale cookies. This makes upstream's three-button
stock welcome page ("Authenticate / Create new account / Sign in /
Cancel") structurally unreachable. See
`docs/design/session-reuse-bugs.md` for the full failure-mode taxonomy.

Depends on:

- The public exports `DEVICE_ID_PREFIX`, `DEVICE_ID_BYTES_LENGTH`,
  `SESSION_ID_PREFIX`, `SESSION_ID_BYTES_LENGTH`, and the `DeviceId`
  branded type from `@atproto/oauth-provider`. Regex built from the
  prefix and hex byte-length must keep parity with upstream's Zod
  schemas in `device-id.ts` / `session-id.ts`.
- `provider.accountManager.listDeviceAccounts(deviceId)` — the public
  method that returns the DeviceAccount rows for a device. This is the
  same call used by upstream's own chooser to populate `__sessions`.
- `/oauth/authorize` and `/account*` remaining the only routes through
  which upstream can render the stock welcome page.
- Express `_router.stack` manipulation to splice this middleware right
  after `expressInit` (same technique as items 4, 5, 15, 16).

**Breakage scenario:** Upstream renames a constant, changes the DeviceId
cookie format (e.g. switches from hex to base64url or from a "dev-"
prefix), introduces a third route that can render the welcome page, or
renames/removes `listDeviceAccounts` on the public AccountManager. The
regex stops matching valid cookies — every request fails the parse step
and bounces to auth-service, trapping users in a tight redirect loop
even for completely valid sessions. A renamed `listDeviceAccounts` fails
at build time (typecheck catches it), a changed signature fails
similarly. Silent regression risk: a new upstream route that shows the
welcome page without being `/oauth/authorize` or `/account*` is not
caught by the guard and the stock page reappears.

## Moderate Risk (public APIs, less likely to break)

### 11. `@atproto/syntax` exports

**File:** `packages/shared/src/handle.ts`

```ts
import {
  normalizeAndEnsureValidHandle,
  InvalidHandleError,
} from '@atproto/syntax'
```

These are public exports. Risk is mainly from validation rule changes in
major version bumps (e.g., allowing/disallowing characters that ePDS's
product constraints assume).

### 12. `HandleUnavailableError`

**File:** `packages/pds-core/src/index.ts`

```ts
import { HandleUnavailableError } from '@atproto/oauth-provider'
```

Public export, used in `catch` blocks to detect handle collisions. Could
break if the error class is renamed or if `createAccount()` starts throwing
a different error type.

### 13. XRPC admin endpoints

**File:** `packages/auth-service/src/routes/account-settings.ts`

Uses `com.atproto.admin.updateAccountHandle` and
`com.atproto.admin.deleteAccount` via HTTP. These are documented protocol
endpoints with stable schemas, lowest risk of breakage.

## Dead Code / Contradictions

### 14. `auto-provision.ts` — passwordless createAccount

**File:** `packages/auth-service/src/lib/auto-provision.ts`

Calls `com.atproto.server.createAccount` via XRPC **without a password**.
This contradicts the documented gotcha in AGENTS.md that passing `undefined`
for password breaks FK constraints. This file may be dead code or a latent
bug — needs investigation.

## Mitigation Strategies

1. **Pin `@atproto/*` versions exactly** in `package.json` (no `^` ranges)
   and treat every bump as a potentially breaking change.
2. **Add integration tests** that exercise the full OAuth flow end-to-end,
   so internal API breakage is caught before deployment.
3. **Upstream contributions**: request public APIs for the operations ePDS
   needs (keepalive for PAR requests, exported types for Account/RequestUri,
   a supported way to override AS metadata).
4. **Wrap internal accesses** behind adapter modules so breakage is
   concentrated in one place rather than scattered across the codebase.
