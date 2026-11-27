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

### 2. `provider.accountManager.createAccount()` signature and `upsertDeviceAccount`

**File:** `packages/pds-core/src/index.ts` (3 call sites)

```ts
const { account } = await provider.accountManager.createAccount(
  deviceId,
  deviceMetadata,
  { locale, handle, email, password, inviteCode },
)
await provider.accountManager['upsertDeviceAccount'](deviceId, did)
```

The call assumes:

- `createAccount` takes `(deviceId, deviceMetadata, opts)` with those exact
  option keys. `email` must be `${string}@${string}`; the callback validates it
  with `isEmailAddress()` first.
- A real password string is **required** — passing `undefined` skips
  `registerAccount()` internally, leaving the `account` table empty and
  breaking `upsertDeviceAccount()` FK constraints
- Returns `{ account, remembered }` as of oauth-provider 0.27 (earlier: the
  `Account` itself). We pass no `clientId`, so `remembered` defaults to true and
  we ignore it. The account's DID property was `.sub` up to `@atproto/pds`
  0.4.x and is `.did` as of 0.5.23. Renames have broken these call sites twice.
- `accountManager.getAccount(did)` is nullable as of 0.27. A null is treated
  as an account-resolution failure (500).
- `upsertDeviceAccount` is `protected` as of 0.27. Upstream binds a device to an
  account only inside sign-up and login; the epds-callback never runs login(),
  so without our call a returning user (existing account, new device or expired
  binding) is never bound and SSO breaks. We reach it with bracket access, which
  bypasses `protected` at compile time only. Rejected alternative: writing
  `account_device` rows ourselves (direct PDS table access). Long-term fix: ask
  upstream for a public hook.

**Breakage scenario:** Parameter reordering, new required fields, password
handling changes, or the method being renamed/removed. Account creation or
returning-user device binding fails.

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

**Status as of oauth-provider 0.27:** the upstream allow-list is now
`same-origin`, `same-site`, `cross-site`, `none`
(`create-authorization-page-middleware.js`), so the rewrite is a no-op. It is
kept for now and should be removed in a follow-up PR once the upgrade is
deployed.

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

### 19. Direct `account` table read in the email-confirmation backfill

**File:** `packages/pds-core/src/backfill-email-confirmed.ts`

```ts
const accounts: BackfillCandidate[] = await pds.ctx.accountManager.db.db
  .selectFrom('account')
  .select(['did', 'email', 'emailConfirmedAt'])
  .execute()
```

This reaches past the `accountManager` methods catalogued in item 6 and
queries upstream's SQLite `account` table directly, via the nested
`.db.db` Kysely instance. It is the only place in the codebase that does
so, and it is the documented exception to AGENTS.md's "do not directly
read or modify `@atproto/pds` database tables" rule.

**Why there is no supported alternative:** as of `@atproto/pds` 0.5.23,
`AccountManager` exposes `getAccount(handleOrDid)`,
`getAccounts(dids)` and `getAccountByEmail(email)` — every one of which
requires knowing the identifier up front. There is no "list all accounts"
query, and a backfill cannot know the DIDs in advance. Adding a wrapper
helper would relocate the same raw query rather than remove it.

**Scope of the exposure:** confined to an operator-invoked one-off script.
pds-core's request path never does this, and the _writes_ still go through
the public `createEmailToken` / `confirmEmail` pair (see item 6).

**Breakage scenario:** upstream renames the `account` table or the `did` /
`email` / `emailConfirmedAt` columns, or restructures `AccountDb` so
`accountManager.db.db` is no longer a Kysely instance. The backfill script
fails — loudly, at run time, in an operator's terminal rather than in a
user-facing path. Lowest-consequence failure of anything in this document,
but it fails with no type-checking safety net, since `.db.db` is untyped
at this depth.

**If upstream ever adds an enumeration API**, switch to it and delete both
this entry and the exception in AGENTS.md's "Database" section.

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
  issues the authorization code (same as item 1 above). **Returns
  `{ code, parameters }` as of oauth-provider 0.27** (earlier: the bare code).
  An untyped `as any` call hid this and produced `code=[object Object]` in the
  redirect. The call now lives in `packages/pds-core/src/lib/consent-skip.ts`
  behind a structural `ConsentSkipProvider` type, so tsc checks the return
  shape, with a unit test asserting the redirect `code` is the string.
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
account" control (a native `<button>` in provider UI 0.10.3 and 0.11.2, previously
`<div role="button">`) with a capture-phase click listener that hard-navigates to
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
- The account-switch control being a native button or `[role="button"]`,
  with a recognized aria-label (`Sign in to an account that is not listed`
  or the older `Login to account that is not listed`) or visible text
  (`Select another account` or `Another account`). Existing Gherkin
  account-switch scenarios exercise the resulting email-form navigation.
- The chooser rendering handle text as visible DOM text that a tree-walker
  can find.

**Breakage scenario:** Upstream renames the globals, changes the account
payload shape, restructures the chooser into a JSON-fetching SPA, or drops
the `/account` route. The enrichment silently fails — the page still
renders because the script is fail-safe — and users see stock upstream
handle-only rows again with no email disambiguation and no "Use a different
account" escape hatch.

**Provider UI 0.11.2 (static check only):** the strings "Another account",
"Select another account" and "Sign up" still exist in the bundle, and the
`__sessions` / `__deviceSessions` globals are unchanged. UI 0.11.2 also ships a
"manage" page with an email one-time-code toggle backed by
`/oauth/api/enable-email-otp` and `/disable-email-otp`; ePDS does not hide it.
DOM behaviour needs an AiaB/browser run to confirm.

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

### 20. better-auth `onRequest` hook ahead of the rate limiter (flow-email)

**File:** `packages/auth-service/src/lib/flow-email-plugin.ts`
(registered in `packages/auth-service/src/better-auth.ts`)

Not an `@atproto` dependency, but the same kind of coupling to a wrapped
upstream: the login page for handle/DID `login_hint`s sends `useFlowEmail`
instead of the account's private email, and this hook swaps the address stored
on the `auth_flow` row into the request body.

It relies on better-auth behaviour (last checked against 1.7.26;
`dist/api/index.mjs`, router `onRequest`):

- the rate limiter runs first, on the original request (it keys on IP and
  path, which the rewrite does not change), then every plugin's `onRequest`;
  the `{ request }` the hook returns is what the origin check and endpoint
  receive. The hook's own 400/500 answers therefore count against the
  limiter (on 1.4.18 they did not);
- `toNodeHandler` builds the `Request` from the Node request with a
  streaming body and the original `content-length` header (the hook reads
  a bounded clone, passes the original through unread, and drops
  `content-length` from the request it rewrites);
- better-auth's own cookie parsing (last duplicate wins) differs from
  cookie-parser's (first wins), which the rest of auth-service uses. The hook
  therefore parses the `epds_auth_flow` cookie itself and refuses a duplicated
  cookie rather than depend on either library's tie-break.

**Breakage scenario:** a better-auth release stops forwarding the returned
request, or changes the OTP endpoint paths or body shape. Handle/DID-hinted
sign-ins then fail at the code step (the page sends no `email`).
`flow-email-router.test.ts` drives the real router, session cookie and rate
limiter, and is the canary on a better-auth bump.

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
