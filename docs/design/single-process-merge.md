# Full Merge: One Origin, One Process

**Status:** Proposal (tracked in [#200](https://github.com/hypercerts-org/ePDS/issues/200))

This document specifies the **maximal** collapse of the two-service
architecture: not just a single origin (covered in
[single-domain-migration.md](single-domain-migration.md)) but a **single Node
process** hosting both the PDS and the auth UI on one Express app.

Read [single-domain-migration.md](single-domain-migration.md) first — this doc
assumes the single-origin work is done or done concurrently, and only adds the
process-collapse layer on top. The "Two levels of merge" section there defines
the origin-merge vs. process-merge distinction; this is the process-merge half,
specced in full.

## Why go all the way to one process

Single-origin already dissolves every cross-origin cost. Merging the _processes_
adds a distinct set of wins that single-origin alone cannot deliver:

- **The HMAC callback boundary disappears.** `/oauth/epds-callback` exists so
  auth-service can prove to pds-core that a redirect came from a legitimate auth
  flow, over the wire, signed with `EPDS_CALLBACK_SECRET`. In one process the
  auth flow can call the code-issuance path **directly** as a function — no
  HMAC, no secret to rotate, no signature-verification code. Note this removes
  only the cross-service _authenticity_ check; the one-time, session-bound
  issuance gating must be preserved in the direct path (see "Preserving
  one-time issuance" below).
- **The internal HTTP lookups disappear.** `/_internal/account-by-email` (which
  replaced the old unauthenticated `/_magic/check-email`) and the
  `/_internal/ping-request` keepalive become
  in-process function calls against the same objects (`pds.ctx.accountManager`,
  `provider.requestManager`) that pds-core already holds. No auth, no JSON
  round-trip, no drift between caller and callee.
- **One deploy unit, one health check, one log stream, one restart.** True
  operational singularity, not just one origin.
- **Shared in-memory state becomes trivial.** Today the PAR-keepalive
  (`ping-request`) and session-reuse logic reason about state across an HTTP
  boundary; in-process they share the live objects.

The cost of going this far — and the reason single-origin is the safer default —
is the integration hazards in the next section and the npm-version risk below.

## Target architecture

Both packages already make this feasible:

- `packages/auth-service/src/index.ts` exposes `createAuthService(config)` which
  **returns a mountable `express.Express`** plus its context — it does not
  hardwire a server. The `app.listen()` is a thin wrapper below the factory.
- `packages/pds-core/src/index.ts` mounts all its middleware onto **`pds.app`**,
  the upstream PDS's own Express instance.

So the merge is: build the auth app (or a router equivalent), **mount it onto
`pds.app` under `/auth`**, and delete auth-service's own `listen()`. One process,
one Express tree, one port.

```
pds.app  (single Express instance, single listen)
├── (upstream PDS routes: xrpc, /oauth/authorize, /oauth/par, …)
├── asMetadataOverride            → authorization_endpoint = <host>/auth/oauth/authorize
├── /auth/oauth/authorize         → auth UI (was auth-service /oauth/authorize)
├── /auth/api/auth/*              → better-auth handler
├── /auth/account/*               → account settings
├── /auth/complete, /auth/choose-handle, …
└── (code issuance called in-process, no /oauth/epds-callback HTTP hop)
```

## Integration hazards (the real work)

These are concrete Express-level collisions between the two apps. Each must be
resolved deliberately; they are why this is a spec and not a one-line mount.

### 1. Body-parser ordering — the sharp edge

auth-service mounts better-auth **before** `express.json()`:

```ts
// auth-service/src/index.ts
app.all('/api/auth/*', toNodeHandler(betterAuthInstance)) // BEFORE json()
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
```

better-auth parses its own request bodies and breaks if a JSON parser consumes
the stream first. pds-core's app already has its own body-parsing. **On the
merged app, `/auth/api/auth/*` must be registered ahead of any global
`express.json()`**, or scoped so the global parser skips that path. This is the
single most likely source of a silent runtime break. Mount order is
load-bearing.

### 2. Duplicate `/static` and favicon

Both apps do `app.use('/static', express.static(publicDir))` and serve a
favicon. Merged, these collide. Namespace the auth assets under `/auth/static`
(and `/auth/favicon`) so the two static roots don't shadow each other.

### 3. `trust proxy`, CSRF, rate-limit — set once, not twice

Both set `app.set('trust proxy', 1)` and install their own CSRF + rate-limit
middleware. On one app: set `trust proxy` once; scope the auth CSRF/rate-limit
middleware to the `/auth` mount (`app.use('/auth', csrfProtection(...))`) so
they don't wrap PDS routes that have their own protections.

### 4. Error / not-found handlers

auth-service ends with `notFoundHandler` + `errorHandler` as terminal
middleware. Terminal handlers mounted globally would swallow PDS routes. Scope
them to the `/auth` router, not the merged app root.

### 5. CSP middleware convergence

Both set CSP per-route (auth via `security-headers.ts`, pds-core by rewriting
upstream's CSP). These already coexist per-response, so no origin change is
needed — but confirm the auth CSP middleware only fires on `/auth/*` once
co-mounted, and does not leak `unsafe-inline` onto PDS routes.

### 6. Shared context / DB handles

auth-service builds `AuthServiceContext` (its own `db`, `emailSender`); pds-core
holds `pds.ctx`. Merged, decide whether they share one SQLite handle or keep
separate connections to the same files. The migration plan already notes
`account.sqlite` is the single source of truth for email→DID; in-process, the
direct-lookup replacements for `/_internal/account-by-email` read it through
`pds.ctx.accountManager` rather than a second connection.

## Replacing the HMAC callback in-process

Today: auth flow → HMAC-signed 303 → `pds-core` `/oauth/epds-callback` →
`provider.requestManager.setAuthorized(...)` issues the code.

Merged: the auth-complete handler calls the same `setAuthorized` path
**directly**. Concretely:

- Extract the body of the `/oauth/epds-callback` handler (the part that calls
  `requestManager.setAuthorized` / `createAccount`) into a plain function on a
  shared module, taking typed args instead of a signed request.
- The auth `/auth/complete` handler calls that function directly.
- **Preserve the one-time issuance gating in the extracted function.** Dropping
  HMAC removes only the cross-service _authenticity_ check — it does **not**
  remove the need for one-time, session-bound, idempotent guards. The direct
  path must still ensure a repeated or replayed `/auth/complete` cannot mint a
  second authorization code (the auth-flow row is consumed exactly once, keyed
  to the session). Carry these guards into the shared function; they are
  independent of the HMAC and must not be deleted alongside it.
- **Retain `EPDS_CALLBACK_SECRET`, the signature-verification middleware, and
  the HTTP `/oauth/epds-callback` route while any legacy Auth instance can
  still call it.** During a rolling deploy an old auth-service may still POST
  the signed callback; deleting the verifier early would either break it or
  (worse) expose an unauthenticated issuance route. Remove the secret, the
  verifier, and the route **only** in a later compatibility gate, after all old
  callers are drained and the direct-call path is fully deployed (see rollout
  steps 4–5).

This is the highest-value deletion in the whole merge and also the most
security-sensitive change — the HMAC existed to stop an attacker forging a
callback. In-process there is no forgeable wire boundary, but the review must
confirm no other caller (including a partially-migrated deployment) can still
reach the code-issuance path unauthenticated.

## npm version clash — now in play

Unlike single-origin, one process forces **one resolution** of every shared or
peer dependency across `better-auth` and the `@atproto/*` stack.

- The repo is a pnpm workspace with non-flat `node_modules`, so today the two
  packages resolve independently. Merging their runtime removes that isolation.
- Current overlap is small: the only shared runtime dep is `express ^4.18.2`
  (aligned). The realistic future conflict is `express` majors, or a transitive
  peer both pull (e.g. a differing `zod`/`@types/node` peer requirement between
  better-auth and an @atproto package).
- **Mitigation:** before merging, run a dedup/peer audit (`pnpm why express`,
  `pnpm dedupe --check`) and pin the shared set. Treat any unresolvable peer
  conflict as a blocker that keeps the two processes separate (fall back to the
  origin-merge-only outcome).

## Phased rollout (extends the single-domain phases)

The single-origin phases (see [single-domain-migration.md](single-domain-migration.md))
come first. This process-merge adds:

1. **Peer-dependency audit.** `pnpm why` / `pnpm dedupe --check` across the
   merged dependency set; pin shared deps. Gate: no unresolvable peer conflict.
2. **Extract the callback core.** Refactor `/oauth/epds-callback`'s issuance
   logic into a directly-callable function; leave the HTTP route delegating to
   it (no behaviour change yet). Ship and test this alone.
3. **Mount auth onto `pds.app`.** Convert `createAuthService` into a router
   mounted at `/auth` on the PDS app; resolve hazards 1–6 above. Keep
   auth-service's standalone `listen()` behind a flag for rollback.
4. **Switch `/auth/complete` to the in-process call.** Route code issuance
   through the extracted function; stop signing/sending the HMAC callback. The
   signed HTTP route stays live and verified here — it is not yet removed.
5. **Compatibility gate — delete only once legacy callers are drained.** After
   confirming no old auth-service instance still POSTs the callback, delete
   `EPDS_CALLBACK_SECRET`, the callback signature middleware, the HTTP
   `/oauth/epds-callback` route, the `/_internal/*` HTTP endpoints, and
   auth-service's standalone server. Retire the second process.

Each step is independently shippable and reversible until step 5.

## Recommendation

Do the single-origin merge first and independently — it captures most of the
value at a fraction of the risk. Treat the process merge as a **follow-on**,
gated on the peer-dependency audit (step 1) and the callback-extraction refactor
(step 2), both of which are worth doing on their own merits regardless of whether
the final process collapse happens.
