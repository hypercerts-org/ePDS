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

| Concern | Today (two origins) | After (one origin) |
| --- | --- | --- |
| Auth UI location | `https://auth.pds.example/oauth/authorize`, `/auth/*`, `/account/*` | `https://pds.example/auth/*` (path-prefixed) |
| `authorization_endpoint` (AS metadata) | `https://auth.<host>/oauth/authorize` | `https://<host>/auth/oauth/authorize` |
| `sec-fetch-site` on `/oauth/authorize` | `same-site`, rewritten to `same-origin` (item 5) | naturally `same-origin` — rewrite **deleted** |
| Device-session cookies | `Domain=<parent>` so sibling subdomain can read them (items 14–15) | host-only on the single origin — **plumbing deleted** |
| Auth session cookie | `magic_account_session` / better-auth `session` on `auth.<host>` | same names, path-scoped `/auth` on `<host>` |
| CSP | per-route in each service (unchanged approach) | per-route, unchanged |
| Deploy units | two services | still two processes, one origin (Caddy path-routes) — or merged later |

The routing model is exactly pds-gatekeeper's: **Caddy routes by path**, sending
`/auth/*` (and the auth-owned `/oauth/authorize`, `/account/*`) to the
auth-service process and everything else to the PDS. The auth-service stays a
separate process; only its _origin_ changes.

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
Only retire the subdomain DNS/cert after the window.

### 2. `EPDS_LINK_BASE_URL` appears in live email links

`auth-service/.env.example:94` — `EPDS_LINK_BASE_URL=https://auth.pds.example/auth/verify`.
Verification/recovery links already delivered to inboxes point at the subdomain.

**Mitigation:** same transition redirect covers these. Update the env var to the
new path-based URL for _new_ emails; keep the subdomain redirecting for the
lifetime of the longest-lived link (OTP/verification TTLs are short — 600s per
`auth-flow.ts` — so this window is small).

### 3. `AUTH_HOSTNAME` is load-bearing config

Referenced in `pds-core/src/index.ts:138`, `auth-service/src/index.ts:138`,
`session-reuse.ts`, `chooser-enrichment.ts` (`authOrigin`),
`sec-fetch-site-rewrite.ts` allowlist, `demo/.env.example` (`AUTH_ENDPOINT`).

**Approach:** introduce an `AUTH_PATH_PREFIX` (default `/auth`) and derive the
auth origin as `PDS_HOSTNAME + AUTH_PATH_PREFIX`. Keep `AUTH_HOSTNAME` as an
optional legacy override so existing subdomain deployments keep working during
transition (config-gated, not a hard cutover).

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
   `/auth/*`, `/oauth/authorize`, `/account/*` to auth-service and the rest to
   the PDS. Stand it up in a test/preview env.
3. **Delete the cross-origin workarounds** (items 5, 14, 15 above) _behind the
   single-origin config path_ so subdomain deployments are unaffected until they
   flip.
4. **Transition redirects.** Serve `auth.<host>/*` → `<host>/auth/*` for the
   metadata-TTL + email-link-TTL window.
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
