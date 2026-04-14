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
  sliding window (see item 7 below). Used in the `/oauth/epds-callback`
  handler and the `/_internal/ping-request` keepalive.
- `.setAuthorized(requestUri, client, account, deviceId, deviceMetadata)` —
  marks a request as authorized and issues an authorization code. This is the
  core of the ePDS callback mechanism.

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

## High Risk (individual features break)

### 5. `pds.ctx.accountManager` methods

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

### 6. `provider.deviceManager.load()`

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

### 7. PAR inactivity timeout assumption

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

### 8. OAuth consent tracking

**File:** `packages/pds-core/src/index.ts`

- `provider.checkConsentRequired(parameters, clientData)` — assumed to
  return a boolean
- `provider.accountManager.setAuthorizedClient(account, client, { authorizedScopes })` —
  assumed signature for recording consent

### 9. `provider.metadata`

**File:** `packages/pds-core/src/index.ts`

```ts
res.json({ ...provider!.metadata, authorization_endpoint: '...' })
```

Assumes `metadata` is a plain spreadable object containing standard AS
metadata fields.

## Moderate Risk (public APIs, less likely to break)

### 10. `@atproto/syntax` exports

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

### 11. `HandleUnavailableError`

**File:** `packages/pds-core/src/index.ts`

```ts
import { HandleUnavailableError } from '@atproto/oauth-provider'
```

Public export, used in `catch` blocks to detect handle collisions. Could
break if the error class is renamed or if `createAccount()` starts throwing
a different error type.

### 12. XRPC admin endpoints

**File:** `packages/auth-service/src/routes/account-settings.ts`

Uses `com.atproto.admin.updateAccountHandle` and
`com.atproto.admin.deleteAccount` via HTTP. These are documented protocol
endpoints with stable schemas, lowest risk of breakage.

## Dead Code / Contradictions

### 13. `auto-provision.ts` — passwordless createAccount

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
