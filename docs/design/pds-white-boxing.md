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
