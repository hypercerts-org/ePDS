# Testing Gaps & Hard-to-Test Areas

Analysis of ePDS code areas that are difficult or impractical to cover
with unit/functional tests, and strategies for addressing them.

**See also:** [`e2e-testing.md`](e2e-testing.md) — end-to-end test
architecture for the gaps that unit tests cannot cover (route handlers,
pds-core callback, full OAuth flow).

## Coverage Summary (as of this analysis)

| Package / Area                | Coverage | Notes                                                                  |
| ----------------------------- | -------- | ---------------------------------------------------------------------- |
| `shared/`                     | ~96%     | Near-complete; only `index.ts` re-exports and one logger branch remain |
| `auth-service/lib/`           | ~77%     | `auto-provision.ts` at 0% (needs live PDS)                             |
| `auth-service/middleware/`    | ~91%     | `rate-limit.ts` timer cleanup at 82%                                   |
| `auth-service/email/`         | ~71%     | Template conditional branches partially covered                        |
| `auth-service/routes/`        | 0%       | All seven route files — see below                                      |
| `auth-service/better-auth.ts` | 0%       | better-auth wiring — see below                                         |
| `auth-service/context.ts`     | 0%       | Minimal glue class                                                     |
| `auth-service/index.ts`       | 0%       | Express app assembly + `main()`                                        |
| `demo/lib/auth.ts`            | ~51%     | Network-dependent resolution functions                                 |
| `pds-core/index.ts`           | 0%       | Entire file — see below                                                |

## Areas That Are Genuinely Hard to Unit Test

### 1. `pds-core/src/index.ts` (0% — 658 lines)

**Why it's hard:**

- The entire file is a monolithic `main()` function that creates a `PDS`
  instance from `@atproto/pds`. `PDS.create()` requires a real SQLite
  database, a PLC directory, crypto keys, and a running HTTP server.
- The `/oauth/epds-callback` handler calls deep into `@atproto/oauth-provider`
  internals (`provider.requestManager`, `provider.deviceManager`,
  `provider.accountManager`) which are not mockable without substantial
  effort — these are branded opaque types with complex state machines.
- Express middleware injection (`_router.stack` manipulation) is inherently
  tied to Express internals that differ across versions.

**What can be tested (with effort):**

- `verifyInternalSecret()` — a pure function (lines 433–440) that could be
  extracted and unit-tested. It uses `crypto.timingSafeEqual` on SHA-256
  hashes, which is straightforward to test in isolation.
- `checkHandleRoute()` — could be tested if `PDS` context were mockable,
  but the `pds.ctx.accountManager.getAccount()` and
  `pds.ctx.cfg.identity.serviceHandleDomains` lookups make this hard
  without a real PDS instance.
- `renderError()` — trivial HTML template, easy to extract and test.

**Recommended strategy:**

- Extract `verifyInternalSecret`, `checkHandleRoute`, and `renderError` into
  a separate `lib/` module within pds-core so they can be unit-tested.
- The callback handler and AS metadata override are integration-level
  concerns that should be covered by end-to-end tests (see
  `docs/design/e2e-testing.md`).

### 2. `auth-service/src/routes/` (0% — 7 route files, ~2300 lines total)

**Files:** `login-page.ts`, `consent.ts`, `recovery.ts`, `account-login.ts`,
`account-settings.ts`, `choose-handle.ts`, `complete.ts`

**Why they're hard:**

- Every route handler requires an `AuthServiceContext` with a live `EpdsDb`
  and `EmailSender`, plus a better-auth instance wired to a real SQLite
  database.
- Many routes call `auth.api.getSession()` / `auth.api.signInEmailOTP()` /
  `auth.api.sendVerificationOTP()` which require a running better-auth
  instance backed by its own tables (user, session, account, verification).
- Routes that interact with the PDS (e.g., `complete.ts` calling
  `getDidByEmail`) need `PDS_INTERNAL_URL` and `EPDS_INTERNAL_SECRET`
  env vars pointing to a running pds-core instance.
- Most routes render server-side HTML via template literal functions —
  testing the rendered output is fragile and not very useful.

**What can be tested:**

- The DB-level logic used by these routes is already well-covered via
  `consent.test.ts` (auth_flow operations, client login tracking,
  signCallback round-trip).
- Pure helper functions within routes (e.g., handle validation in
  `choose-handle.ts`) could be extracted and tested.

**Recommended strategy:**

- Accept that route handlers are integration-level code. They glue together
  already-tested components (DB operations, crypto, email sending).
- Cover route handlers via HTTP-level integration tests using `supertest`
  with a test fixture that spins up the full auth-service Express app
  against an in-memory SQLite database and a mock better-auth instance.
- Alternatively, cover them via e2e tests (Playwright or similar) that
  exercise the full stack.

### 3. `auth-service/src/better-auth.ts` (0% — 213 lines)

**Why it's hard:**

- `createBetterAuth()` instantiates a `betterAuth()` instance with
  database and plugin configuration. Testing it requires the full
  better-auth + better-sqlite3 stack, which is heavy.
- `runBetterAuthMigrations()` creates tables in SQLite — this is
  integration-level and depends on the better-auth schema.
- The `sendVerificationOTP` callback inside the emailOTP plugin reads
  cookies from the better-auth request context (`ctx.getCookie`), queries
  the auth_flow table, and calls the email sender — this deep wiring is
  hard to trigger in isolation.

**What can be tested:**

- `buildSocialProviders()` is already tested (indirectly) in
  `social-providers.test.ts` by reimplementing the logic.
- The social provider detection could be tested directly if
  `buildSocialProviders` were exported.

**Recommended strategy:**

- Consider exporting `buildSocialProviders` for direct unit testing.
- The OTP email wiring is best verified by integration or e2e tests
  that trigger a real OTP flow.
- `extractOtp` in `e2e/support/mailpit.ts` uses heuristic regex patterns
  rather than `OTP_LENGTH` / `OTP_CHARSET` env vars. This is slightly flaky
  by nature — the robust alternative would be keeping those env vars in sync
  between the deployed service and `e2e/.env`, but that requires manual
  coordination on every config change and is error-prone across environments
  (e.g. Railway vs local). The heuristic is preferred since the email
  templates are in-repo and their structure is stable.

### 4. `auth-service/src/context.ts` and `index.ts` (0%)

**Why:**

- `AuthServiceContext` is a thin constructor that wires DB + email sender +
  cleanup interval. Testing it would just be testing constructor wiring.
- `index.ts` is the Express app assembly entry point (`createAuthService` +
  `main()`). Testing `createAuthService` would be an integration test.

**Recommended strategy:**

- `AuthServiceContext` is simple enough that the constructor is implicitly
  tested whenever the auth-service starts. Not worth a dedicated unit test.
- `createAuthService` should be covered by integration/e2e tests.

### 5. `auth-service/src/lib/auto-provision.ts` (0% — 48 lines)

**Why:**

- Calls `fetch()` against the PDS's XRPC `createAccount` endpoint.
  Requires a running PDS instance or careful fetch mocking.

**What can be tested:**

- With `globalThis.fetch` mocking (similar to `client-metadata.test.ts`),
  both success and failure paths could be tested. This is feasible but
  hasn't been prioritized since the function is only used as a fallback
  code path and the primary account creation now happens in pds-core.

### 6. `demo/src/lib/auth.ts` — network functions (lines 138–249)

**Functions:** `resolveHandleToDid`, `resolveDidToPds`, `discoverOAuthEndpoints`

**Why:**

- These functions make real HTTP requests to external services
  (`bsky.social`, PLC directory, PDS OAuth metadata endpoints).
- Mocking fetch is possible but the functions have multiple fallback paths
  (XRPC → well-known, did:plc → did:web) that are hard to exercise
  comprehensively.

**What is tested:**

- The pure crypto functions (PKCE, DPoP, state generation, key pair
  management) are fully covered.

**Recommended strategy:**

- Add fetch-mocked unit tests for the happy path + common error cases.
- Rely on e2e tests for full resolution chain testing.

## Remaining Low-Hanging Fruit

These items could improve coverage with minimal effort:

1. **`shared/src/index.ts`** — This is just re-exports. It shows as 0%
   because v8 coverage doesn't track re-exports well. Not actionable.

2. **`shared/src/logger.ts` line 14** — The development-mode `formatters`
   branch. Could be tested by setting `NODE_ENV=development` in a test, but
   the value is low.

3. **`shared/src/handle.ts` line 44** — The `throw err` branch for
   non-`InvalidHandleError` exceptions. Would require forcing
   `normalizeAndEnsureValidHandle` to throw a non-InvalidHandleError,
   which is difficult without monkey-patching.

4. **`shared/src/db.ts` lines 485–492** — `recordClientLogin` (INSERT OR
   IGNORE). The function works but the coverage tool reports it as uncovered
   because it's hit via `hasClientLogin`/`recordClientLogin` sequence in
   consent.test.ts which runs in a different test file's coverage scope.

5. **`auth-service/email/sender.ts`** — Additional template rendering
   branches (custom subject templates, conditional sections) could be
   covered with more fetch mock scenarios.

## Summary

The biggest coverage gaps are in **route handlers** and **pds-core**, both
of which are integration-level code that depends on running instances of
better-auth, Express, and @atproto/pds. The recommended path forward is:

1. **Extract testable pure functions** from monolithic files (especially
   pds-core) into dedicated modules.
2. **Add integration tests** using `supertest` for auth-service route
   handlers against an in-memory database.
3. **Implement e2e tests** (see `docs/design/e2e-testing.md`) to cover the
   full OAuth flow end-to-end.
