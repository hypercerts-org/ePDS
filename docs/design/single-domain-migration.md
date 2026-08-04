# Single-Domain Migration: Collapse `auth.<host>` into the PDS origin

**Status:** Proposal (tracked in [#200](https://github.com/hypercerts-org/ePDS/issues/200))

This document designs the migration from the current two-origin architecture
(`auth.pds.example` + `pds.example`) to a single origin, where the Auth Service
is served under a path prefix (e.g. `pds.example/auth/*`) on the PDS host.

For _why_ this is worth doing, see the "Auth Service on a subdomain" decision
in [../architecture.md](../architecture.md) and the cost inventory in
[pds-white-boxing.md](pds-white-boxing.md) items 5, 14, 15. This doc assumes
that case is accepted and focuses on _how_.

## Summary of the change

| Concern                                | Today (two origins)                                                                | After (one origin)                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Auth UI location                       | `https://auth.pds.example/oauth/authorize`, `/auth/*`, `/account/*`                | `https://pds.example/auth/*` — including `/auth/oauth/authorize` and `/auth/account/*` (see path-shadowing note below) |
| `authorization_endpoint` (AS metadata) | `https://auth.<host>/oauth/authorize`                                              | `https://<host>/auth/oauth/authorize`                                                                                  |
| `sec-fetch-site` on `/oauth/authorize` | `same-site`, rewritten to `same-origin` (item 5)                                   | naturally `same-origin` — rewrite **deleted**                                                                          |
| Device-session cookies                 | `Domain=<parent>` so sibling subdomain can read them (items 14–15)                 | host-only on the single origin — **plumbing deleted** (see Set-Cookie contract below)                                  |
| Auth session cookie                    | Better Auth session cookie (historically `magic_account_session`) on `auth.<host>` | same cookie, host-only on `<host>` (see Set-Cookie contract below)                                                     |
| CSP                                    | per-route in each service (unchanged approach)                                     | per-route, unchanged                                                                                                   |
| Deploy units                           | two services                                                                       | still two processes, one origin (Caddy path-routes) — or merged later                                                  |

The routing model is exactly pds-gatekeeper's: **Caddy routes by path**, sending
the auth surface to the auth-service process and everything else to the PDS. The
auth-service stays a separate process; only its _origin_ changes.

### Path shadowing — the auth surface must move under `/auth`

On a single origin the auth service **cannot** keep serving `/oauth/authorize`
and `/account/*` at the root: upstream `@atproto/oauth-provider` already renders
`/oauth/*` and `/account*` on pds-core, so routing those roots to auth-service
would shadow the PDS's own endpoints. The migration therefore exposes the entire
auth surface under a non-conflicting prefix — `/auth/oauth/authorize`,
`/auth/account/*`, `/auth/*` — optionally with a Caddy path-strip rewrite so the
auth-service process can keep its current internal route paths unchanged.

### Set-Cookie contract on the merged origin

With one origin, the cookie isolation that the subdomain previously provided by
separation must instead be provided by the cookie attributes:

- **Auth session cookie** (Better Auth) and **CSRF / auth-flow cookies**
  (`epds_csrf`, `epds_auth_flow`): guaranteed-**unique names**, **no `Domain`
  attribute** (host-only), `Secure`, `HttpOnly` where applicable,
  `SameSite=Lax`. Optionally scope non-`__Host-` cookies with `Path=/auth`.
- **Device-session cookies** (`DEVICE_COOKIE_NAMES`): host-only — emit with **no
  `Domain` attribute** at all, deleting the `Domain=<parent>` broadening (items
  14–15).
- `__Host-` prefixing is a possible hardening but is **mutually exclusive with a
  `/auth` path scope**: `__Host-` requires `Path=/`. Pick unique-name +
  host-only as the baseline; add either `__Host-` (at `Path=/`) or `Path=/auth`
  scoping, not both.

**In-flight sessions do not survive the host change.** These cookies are
host-only by design, so a cookie set at `auth.<host>` is never sent to
`<host>` — RFC 6265bis host-only semantics. The transition redirects in step 4
carry the path and query, and therefore the request parameters, but they carry
**no cookies**: `epds_csrf`, `epds_auth_flow`, and the Better Auth session all
vanish across the hop. A user mid-sign-in at cutover lands on the new origin
with the right URL and no state.

Pick one of these explicitly before cutting over — the migration is not
complete without it:

- **Controlled drain (recommended).** Stop issuing new flows on the subdomain,
  wait out the auth-flow TTL (OTP `expiresIn: 600`, so ~10 minutes), then flip.
  In-flight users restart sign-in; nobody sees a broken state because there are
  no live flows left. Cheapest, and the TTL is short enough to make it
  practical.
- **Server-side handoff.** Redirect through a one-time, short-TTL token that the
  new origin exchanges for the session server-side. Preserves in-flight flows at
  the cost of a new exchange endpoint — which is itself a credential-bearing
  redirect and needs the same scrutiny as the HMAC callback.

Whichever is chosen, the restart path must be graceful: a user arriving without
the expected cookies must get the "start sign-in again" flow, not an error.

## Two levels of "merge" — keep them distinct

This matters for both benefits and risks, so fix the terms up front:

- **Merge the _origin_ (recommended baseline).** One hostname, Caddy path-routes
  to two still-separate processes. Dissolves every cross-origin cost; keeps the
  HMAC trust boundary; carries **no** npm-version risk.
- **Merge the _processes_ (optional, later).** Fold auth-service into the
  pds-core Node process. Adds the "fewer privileged endpoints" benefit in full
  (calls become in-process) but is the only variant that can surface
  dependency conflicts. Treat as a separate, later decision — specced in full
  in [single-process-merge.md](single-process-merge.md).

## Positive benefits (beyond deleting costs)

- **Fewer privileged cross-service endpoints.** The split _requires_ the two
  services to communicate over authenticated HTTP: the HMAC-signed
  `/oauth/epds-callback` plus the internal lookup endpoints (`/_internal/*`,
  e.g. `/_internal/account-by-email`, which replaced the old unauthenticated
  `/_magic/check-email`). Each is an attack surface that
  must be signed, gated, and version-matched across the boundary. Merging the
  origin lets some of these relax; merging the processes lets most become
  in-process calls with no wire boundary at all.
- **Operational simplicity.** One TLS cert, one DNS record, one CSP surface, one
  origin's worth of cross-origin edge cases — instead of a parent/subdomain pair
  whose `endsWith('.'+pdsHostname)` relationship is itself load-bearing config
  threaded through several modules.

## Risk: npm version clashes (process-merge only)

Applies **only** to the process-merge variant, not the origin-merge baseline.

- Today the repo is a **pnpm workspace** (`pnpm --recursive`) with pnpm's
  default non-flat `node_modules`, so `auth-service` and `pds-core` already
  resolve their dependencies independently.
- Overlap is small: `pds-core` owns the heavy `@atproto/*` stack, `auth-service`
  owns `better-auth`; the only shared runtime dep is `express ^4.18.2`, already
  aligned.
- A single Node process would force one resolution of any shared/peer dep. The
  realistic conflict surface is a future `express` (or a transitive peer both
  pull) diverging. Bounded, but a real reason to prefer keeping two processes
  unless the in-process-call benefit is specifically wanted.

## What gets deleted

The whole point. These exist solely because of cross-origin-same-site:

1. **`packages/pds-core/src/lib/sec-fetch-site-rewrite.ts`** — the `same-site` →
   `same-origin` rewrite (white-boxing item 5). On one origin the header is
   `same-origin`, which upstream `@atproto/oauth-provider` already accepts.
   Delete the middleware and its `_router.stack` injection.
2. **Cross-subdomain device-cookie plumbing** (white-boxing items 14–15) — the
   `Domain=<parent>` broadening in `pds-core` and the sibling-reading logic in
   `auth-service/src/lib/session-reuse.ts`. On one origin the device session is
   directly readable; cookies stay host-only.
3. **`authHostname.endsWith('.' + pdsHostname)` special-casing** — e.g.
   `session-reuse.ts:195-200`, the `parentCookieDomain` derivation in
   `pds-core/src/index.ts:930`, and `authOrigin` derivation in
   `chooser-enrichment.ts`. The two hostnames become one.
4. **(Process-merge only) some privileged cross-service endpoints** — the
   `/_internal/*` HTTP lookups become in-process calls. The
   HMAC-signed `/oauth/epds-callback` can also collapse to an in-process call
   if the processes merge. See "Two levels of merge" above.

## What stays

- The `authorization_endpoint` **metadata override** (`pds-core/src/index.ts:643`).
  Still needed — it just points at a path on the same host instead of a
  subdomain. The upstream sign-in UI is still never shown.
- The **HMAC-signed `/oauth/epds-callback`** bridge. The trust boundary between
  auth-service and pds-core is unchanged; they still communicate over
  authenticated HTTP, not shared memory.
- **Per-route CSP** in both packages. No change.
- The **handle picker, consent, OTP** flows. No change to their logic.

## Migration blockers (external addressability of `auth.<host>`)

None of the three stated benefits is a blocker; these published-URL references
are the real work.

### 1. `authorization_endpoint` is cached by OAuth clients

`pds-core/src/index.ts:643` publishes `https://auth.<host>/oauth/authorize` in
the AS metadata document. Clients fetch this and may cache it. A hard switch
would strand in-flight and cached clients.

**Mitigation:** keep `auth.<host>` resolving during a transition window. Serve a
301/302 (or continue proxying) from `auth.<host>/oauth/authorize` →
`<host>/auth/oauth/authorize` until metadata TTLs expire and clients re-fetch.
The redirect/proxy **must preserve the complete request target** — full path and
query string — because the authorization request carries `client_id`,
`redirect_uri`, `code_challenge`, `state`, etc.; dropping the query breaks
in-flight logins. Only retire the subdomain DNS/cert after the window.

### 2. `EPDS_LINK_BASE_URL` appears in live email links

`auth-service/.env.example:94` — `EPDS_LINK_BASE_URL=https://auth.pds.example/auth/verify`.
Verification/recovery links already delivered to inboxes point at the subdomain.

**Mitigation:** same transition redirect covers these — and, as above, it must
**preserve the full path and query string** so the verification token in the
link survives the hop. Update the env var to the new path-based URL for _new_
emails; keep the subdomain redirecting for the lifetime of the longest-lived
link (OTP/verification TTLs are short — `expiresIn: 600` in
`auth-service/src/better-auth.ts` — so this window is small).

### 3. `AUTH_HOSTNAME` is load-bearing config

Referenced in `pds-core/src/index.ts:138`, `auth-service/src/index.ts:138`,
`session-reuse.ts`, `chooser-enrichment.ts` (`authOrigin`),
`sec-fetch-site-rewrite.ts` allowlist, `demo/.env.example` (`AUTH_ENDPOINT`).

**Approach:** keep these as distinct values rather than conflating them —
`PDS_HOSTNAME + AUTH_PATH_PREFIX` yields `pds.example/auth`, which is a **base
URL/path, not an origin**, and today's `AuthServiceConfig.hostname` expects a
bare hostname while public-URL config carries the scheme. So:

- keep `AuthServiceConfig.hostname` a hostname;
- introduce `AUTH_PATH_PREFIX` (default `/auth`) as the path the auth surface
  mounts under;
- derive the full mount point from an explicit **origin** (`https://<host>`)
  joined with the prefix — or introduce an explicit `AUTH_BASE_URL` — and update
  URL-joining so paths and origins are never concatenated as bare strings.

Keep `AUTH_HOSTNAME` as an optional legacy override so existing subdomain
deployments keep working during transition (config-gated, not a hard cutover).

### Non-blockers (confirmed)

- **No AT Protocol identity coupling.** DIDs are `did:web:<pds-host>` (the PDS
  host), never `auth.<host>`. Grep for `did:web` shows only PDS-host and test
  fixtures.
- **OAuth `redirect_uri` is always the client's**, never the auth service's.
  Nothing to migrate there.
- **CORS.** The only `Access-Control-Allow-Origin: *` headers are on the demo's
  public JSON documents (`client-metadata.json`, `jwks.json`) and a pds-core
  metadata response — none depend on the auth origin being distinct.

## Phased rollout

1. **Config plumbing.** Add `AUTH_PATH_PREFIX`; derive auth origin from it;
   keep `AUTH_HOSTNAME` as a legacy override. No behaviour change yet.
2. **Caddy path routing.** Add a single-origin Caddyfile variant that routes
   **only `/auth/*`** to auth-service and everything else to the PDS. Routing
   `/oauth/authorize` or `/account/*` at the public root would shadow the PDS's
   own endpoints — see "Path shadowing" above; the auth equivalents are reached
   as `/auth/oauth/authorize` and `/auth/account/*`. Either strip the `/auth`
   prefix before forwarding (so auth-service keeps its current internal route
   paths) or register `/auth`-prefixed routes in auth-service; pick one
   explicitly, because the two choices are not interchangeable at the
   redirect-target level (step 4). Stand it up in a test/preview env.
3. **Delete the cross-origin workarounds** (items 5, 14, 15 above) _behind the
   single-origin config path_ so subdomain deployments are unaffected until they
   flip.
4. **Transition redirects.** Serve path-specific redirects for the
   metadata-TTL + email-link-TTL window, preserving the full path and query
   string on each:

   | Legacy                        | Target                        |
   | ----------------------------- | ----------------------------- |
   | `auth.<host>/oauth/authorize` | `<host>/auth/oauth/authorize` |
   | `auth.<host>/account/*`       | `<host>/auth/account/*`       |
   | `auth.<host>/auth/*`          | `<host>/auth/*`               |

   A blanket `auth.<host>/* → <host>/auth/*` rule is wrong: existing links
   already carry an `/auth` segment (`EPDS_LINK_BASE_URL` is
   `https://auth.pds.example/auth/verify`), so it would produce
   `/auth/auth/verify` and break every verification email in flight.

5. **Cut over** `authorization_endpoint` and `EPDS_LINK_BASE_URL` to the new
   path-based URLs.
6. **Retire** the `auth.<host>` DNS record, TLS cert, and the legacy
   `AUTH_HOSTNAME` code paths after the transition window.

## Open questions

- Do we keep two processes (Caddy path-routes) indefinitely, or eventually merge
  auth-service into the pds-core process? The process split is cheap to keep and
  preserves the HMAC trust boundary; recommend keeping it and only collapsing
  the _origin_.
- Preview/e2e environments assume the subdomain in several fixtures
  (`preview.ts`, `preview-emails.ts`, `demo/.env.example`). These need updating
  in lockstep with step 1; enumerate them before starting.
- Does any downstream trusted client hardcode `auth.<host>` anywhere other than
  by fetching AS metadata? Needs a check with the known trusted-client operators
  before retiring the subdomain (step 6).
