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
- **Authentication facts stop being re-serialised.** The HMAC boundary carries
  _authenticity_ (this redirect is genuine) but not _content_ — anything
  pds-core needs to know about **how** the user authenticated has to be encoded
  into the signed payload as an explicit field, or else inferred. Inference is
  the dangerous default: it is invisible, it looks correct for as long as only
  one sign-in flow exists, and it silently becomes wrong the day a second one
  is added. In one process there is nothing to serialise — the code that
  verified the user calls the code that records the result, and the fact cannot
  drift from its use. See "Auth facts across the boundary" below for the worked
  example that motivated this bullet.
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

## Auth facts across the boundary

A worked example of the "authentication facts stop being re-serialised" bullet,
from HYPER-219 (PR #234). It is the clearest evidence so far of a cost that is
_structural_, not incidental — no amount of care in either service removes it.

**The task.** Every ePDS account is created after the user verifies an emailed
one-time code, so the address genuinely is verified. But the PDS `account`
table's `emailConfirmedAt` stayed null, so `email_verified` was false in every
OIDC claim and upstream's email-change verification gate never engaged.

**In one process** this is a single call at the point of proof: where
better-auth confirms the code, call `accountManager.confirmEmail(...)`. The
invariant — _record confirmation only where control of the address was
proved_ — is enforced by control flow. There is no way to express the bug.

**Across two processes** the code that knows the fact (auth-service, holding
the better-auth session) cannot reach the API that records it (pds-core, sole
owner of `account.sqlite`; auth-service does not even depend on `@atproto/pds`).
So the fact has to travel. The first implementation instead let pds-core
_infer_ it: a valid signed callback had only ever followed an OTP, so arrival
was treated as proof. That inference is correct today and silently wrong the
moment a second sign-in flow exists — a passkey flow would legitimately send a
signed callback carrying `email` merely to locate the account, having proved
nothing about that address, and pds-core would mark it confirmed. The failure
is in the worst direction: asserting `email_verified: true` to relying parties
on no evidence, and arming the email-change gate on an unproven address.

**What the boundary cost to make safe:**

- a new required `email_verified` field on the shared `CallbackParams` type;
- a change to the positional HMAC payload in both `signCallback` and
  `verifyCallback`, so the claim is tamper-proof rather than a query param
  anyone holding the URL could flip from `0` to `1`;
- wiring it through **both** callback producers in auth-service
  (`/auth/complete` and `/auth/choose-handle`);
- a consumer check in pds-core that confirms only on an explicit `'1'`;
- tests pinning tamper-resistance and fail-closed behaviour.

Two details are worth carrying into any future boundary work:

- **Make such fields required, not sentinel-defaulted.** `handle` and
  `client_id` use an empty-string sentinel so absent means "not set". Applying
  that to an auth fact would mean a future flow that forgets it gets
  "unverified" silently. Because the payload is positional, a **required**
  field means an omitting caller signs a different payload and is rejected at
  the trust boundary — the failure is loud, and cannot be a false claim of
  verification.
- **Rebinding the subject invalidates the fact.** The recovery path swaps
  `email` from the verified backup address to the account's primary address.
  The session's "verified" flag refers to the address the user actually proved,
  so it must be reset to `false` when the subject changes. In-process this
  hazard is far easier to see, because the fact and its use sit together.

**The general shape.** Each authentication fact pds-core needs is a field that
must be added to the payload, signed, produced by every producer, consumed
correctly, and tested — and the cost recurs per fact. `email_verified` answers
only "was control of this address proved?". A future `auth_method`
(`otp` / `passkey` / …), or step-up/assurance data, is another full round of
the same work. In one process these are ordinary function arguments, or simply
not needed because the caller already holds the session.

This does not by itself justify the merge — the integration hazards above are
real and the rollout is not free. It does mean the boundary's cost is not
one-off: it is a recurring tax on every future authentication mechanism, paid
in exactly the area where silent errors are most damaging.

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

One update since this was first written: the boundary's cost is now known to
_recur_, not just to sit as a fixed overhead. "Auth facts across the boundary"
records a live example (HYPER-219 / PR #234) where a fact known to auth-service
had to be re-serialised into the signed payload before pds-core could act on it
safely, and where the natural implementation inferred the fact instead — correct
for today's single sign-in flow, silently wrong for the next one. Every future
authentication mechanism (passkeys, step-up, assurance levels) pays that tax
again. This does not change the phasing recommended above, but it does raise the
standing cost of _not_ merging, and it is a reason to keep the
callback-extraction refactor (step 2) moving even if the final collapse stays
deferred.
