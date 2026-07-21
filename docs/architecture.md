# Architecture — ePDS (extended Personal Data Server)

## System Overview

```
                  +-----------------+
                  |   OAuth Client  |
                  | (Bluesky, custom|
                  |   apps, etc.)   |
                  +-------+---------+
                          |
                   1. PAR  |  9. Token exchange
                          v
           +-----------------------------+
           |          PDS Core           |
           |  (stock @atproto/pds +      |
           |   epds-callback endpoint)  |
           +-----------------------------+
                   |             ^
   2. AS metadata  |             | 8. Auth code issued
   redirects to    |             |    via /oauth/epds-callback
   auth subdomain  v             |
           +-----------------------------+
           |        Auth Service         |
           |  /oauth/authorize           |
           |  /auth/choose-handle (new)  |
           |  /auth/complete             |
           |  /account/* (settings)      |
           |  (better-auth OTP backend)  |
           +-----------------------------+
                          |
             3-6. Email   |  OTP code flow
           7. Handle pick |  (new users only)
                          v
                     User's inbox
```

The PDS Core is a thin wrapper around the stock [`@atproto/pds`](https://github.com/bluesky-social/atproto)
package. Its AS (Authorization Server) metadata points `authorization_endpoint` at the Auth Service
subdomain, delegating all user authentication to it.

The Auth Service handles the login UI and session management via [Better Auth](https://www.better-auth.com/).
On successful authentication, it calls back to PDS Core via the HMAC-signed `/oauth/epds-callback`
endpoint to issue an AT Protocol authorization code. For new users, a handle-picker step
(`/auth/choose-handle`) is inserted after OTP verification and before the callback to PDS Core.

## Packages

| Package                       | Description                                              |
| ----------------------------- | -------------------------------------------------------- |
| `@certified-app/shared`       | Database (SQLite), crypto utilities, types, logger       |
| `@certified-app/auth-service` | Auth UI, OTP code flow via better-auth, account settings |
| `@certified-app/pds-core`     | Wraps `@atproto/pds` with epds-callback integration      |

## Key Design Decisions

- **Better Auth** manages user sessions, OTP codes, and (optionally) social login.
  It does not replace AT Protocol OAuth — it sits alongside it and bridges into it
  via the `/auth/complete` → `/oauth/epds-callback` path.

- **User-chosen handles**: new users pick their handle local part (5–20 chars, no dots)
  during signup via `/auth/choose-handle`. The handle is included in the HMAC-signed
  callback so PDS Core creates the account with the chosen handle. If the handle is
  taken at creation time (race condition), PDS Core redirects back to the picker to
  retry. A random-handle fallback (`generateRandomHandle`) still exists for backward
  compatibility but is not used in the current signup flow.

- **Single invite code**: `EPDS_INVITE_CODE` is a high-`useCount` invite code used for
  all account creation, avoiding the need to distribute individual invite codes.

- **Passwordless accounts**: PDS accounts are created with a random unguessable password.
  Users can only log in via the OTP flow (or social providers if configured).

- **HMAC-signed callback**: the redirect from Auth Service to PDS Core's
  `/oauth/epds-callback` is signed with `EPDS_CALLBACK_SECRET` so PDS Core can verify
  it was produced by a legitimate auth flow.

- **Auth Service on a subdomain, not a single shared domain**: the
  recommended production relationship is `AUTH_HOSTNAME` as a subdomain of
  `PDS_HOSTNAME` (e.g. `auth.pds.example` / `pds.example`). This is not a hard
  runtime requirement — the code also supports unrelated hostnames (e.g.
  Railway preview envs where both services sit under `up.railway.app`), in
  which case the shared cookie domain is `null` and device cookies stay
  host-only (`deriveCookieDomain` in `pds-core/src/cookie-domain.ts`). The
  cross-subdomain **device-session reuse** path only works when the subdomain
  relationship holds, which is why it is the recommended arrangement. A
  single-domain design — one origin, routing the auth paths
  by path prefix the way [pds-gatekeeper](https://tangled.org/baileytownsend.dev/pds-gatekeeper)
  does — was **considered and rejected**. The reasons:
  - **Mechanism (how the takeover happens)**: PDS Core overrides the
    Authorization Server metadata so `authorization_endpoint` points at the
    Auth Service. OAuth clients redirect the browser straight there, so the
    stock `@atproto/pds` sign-in UI is never shown. This alone does not
    _require_ a separate origin — PDS Core already wraps upstream heavily and
    could shadow `/oauth/authorize` in place — so it is the mechanism, not the
    motivation. The takeover does, however, carry its own recurring cost
    _independent of origin or process topology_: because clients are pointed
    away from the stock UI, PDS Core must police every path on which upstream
    `@atproto/oauth-provider` might still render one of its two unreachable
    auth UIs (welcome page, password sign-in-view). The render decision lives
    in upstream-private logic PDS Core cannot cleanly wrap, so the guard
    (`auth-ui-guard.ts`; [pds-white-boxing.md](design/pds-white-boxing.md)
    item 18) either mirrors that decision pre-route or detects it in the
    rendered HTML — both brittle by construction (see
    [HYPER-367](https://linear.app/hypercerts/issue/HYPER-367)). Merging the
    origin does not remove this; merging the two ePDS _processes_ does not
    either, because the opaque boundary here is PDS Core ↔ upstream atproto,
    not PDS Core ↔ Auth Service.

  - **Cookie isolation (the motivation)**: the Auth Service's session cookies
    (the Better Auth session cookie; historically `magic_account_session`,
    no longer present in code) are a
    _separate authentication domain_ from AT Protocol access/refresh tokens.
    Giving the Auth Service its own origin keeps the two cookie namespaces from
    colliding by construction. (Note the tension: cross-subdomain cookie
    _sharing_ for the device-session reuse path is a _cost_ of this split — see
    [pds-white-boxing.md](design/pds-white-boxing.md) items 14–15 — whereas
    isolation between the two auth systems is the _benefit_.)

  - **Security-header isolation**: the Auth Service is a full web app (HTML
    forms, static assets, inline scripts/styles) that needs its own CSP and
    security headers, independent of PDS Core's stricter policy. Separate
    origins let each set headers without one breaking the other.

  - **Independent deployability**: separate service and process, deployable and
    restartable on its own.

  The contrast with pds-gatekeeper is the crux: path-based single-domain
  routing is fine for a _thin interception layer_, but the Auth Service is a
  _full web app with its own cookie domain_, so it was given its own origin.

  Costs of the subdomain choice (accepted, and only partly documented at the
  time): the `same-site` → `same-origin` `sec-fetch-site` rewrite and the
  cross-subdomain cookie-domain plumbing, both in
  [pds-white-boxing.md](design/pds-white-boxing.md) (items 5, 14, 15).

  **On re-examination, none of the three benefits is a non-negotiable, and all
  the costs are artifacts of being cross-origin-but-same-site:**
  - _Cookie isolation_ is already done by explicit cookie **naming**
    (`epds_csrf`, `epds_auth_flow`, the Better Auth session cookie, and the
    `DEVICE_COOKIE_NAMES` device-session set), not by origin — so it survives a
    collapse to one origin. Concretely, on a shared origin the contract is:
    guaranteed-unique names, and **no parent `Domain` attribute** (cookies stay
    host-only). This unique-name isolation is distinct from — and does not
    require — `__Host-` prefixing; note `__Host-` mandates `Path=/` and so
    cannot be combined with a `/auth` path scope, whereas plain path scoping
    (`Path=/auth`) is an available but separate hardening option. The split
    does not just fail to be _required_ for isolation; it actively _creates_ a
    cookie problem — the `Domain=<parent>` sharing in items 14–15 — that a
    single origin deletes outright.
  - _Security-header isolation_ is already per-route in both packages
    (`auth-service/src/lib/security-headers.ts` sets an auth-specific CSP per
    request; `pds-core` already rewrites the upstream CSP per response in
    `chooser-enrichment.ts` / `client-css-injection.ts`). Per-route CSP does
    not need per-origin hosting.
  - _Independent deployability_ is a soft benefit already weakened by a shared
    repo, build, and data volume.
  - The `sec-fetch-site` rewrite (item 5) exists **only** because the redirect
    chain is `same-site`; a single origin makes it `same-origin`, which
    upstream already allows — so the one upstream validation that looks like a
    constraint actually _favors_ single-origin.

  Beyond dissolving those costs, collapsing to one origin has **positive**
  benefits the split forecloses:
  - **Fewer privileged cross-service endpoints.** The split forces the two
    services to talk over authenticated HTTP: the HMAC-signed
    `/oauth/epds-callback` and the `/_internal/*` lookup endpoints (e.g.
    `/_internal/account-by-email`, which replaced the old unauthenticated
    `/_magic/check-email`), each an attack surface that has to be signed,
    gated, and kept in sync. **Note this benefit requires merging the
    _processes_, not just the origin**: a single origin with two processes
    still has an HTTP boundary (merely same-origin now). Only a process merge
    turns these into in-process calls with no wire boundary to secure — a
    separate decision from origin-merging; see the migration doc.

  - **Operational simplicity.** One origin means one TLS cert, one DNS record,
    one CSP surface, and one set of cross-origin edge cases to reason about,
    instead of a parent/subdomain pair whose relationship is itself
    load-bearing config.

  A **countervailing risk** applies only if the two _processes_ are merged
  (not if they stay separate behind path routing): sharing one Node runtime
  could surface npm peer-dependency conflicts between `auth-service`'s
  `better-auth` and `pds-core`'s `@atproto/*` stack. In practice the repo is a
  pnpm workspace with a non-flat `node_modules`, so each package already
  resolves its own versions and the overlap today is minimal (`express`,
  aligned). The risk is real but bounded, and avoided entirely by the
  keep-two-processes option.

  The remaining real risk is not any of the three benefits but external
  addressability of `auth.<host>`: `authorization_endpoint` is published in AS
  metadata and cached by clients, and `EPDS_LINK_BASE_URL` appears in live
  email links — so a migration is a published-URL change needing a transition,
  not a flip. (There is _no_ AT Protocol identity coupling: DIDs reference the
  PDS host, and OAuth `redirect_uri` is always the client's.) This
  re-evaluation, and a concrete single-domain migration design, are tracked in
  [#200](https://github.com/hypercerts-org/ePDS/issues/200); see
  [design/single-domain-migration.md](design/single-domain-migration.md).

  Origin rationale: `better-auth-migration-plan.md`, section "Considered and
  rejected: single-domain architecture" (introduced in commit `e6d6a08`; the
  design itself was inherited whole from the upstream `magic-pds` project at
  the initial commit `de3876e`).
