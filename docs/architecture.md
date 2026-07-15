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

- **Auth Service on a subdomain, not a single shared domain**: `AUTH_HOSTNAME`
  must be a subdomain of `PDS_HOSTNAME` (e.g. `auth.pds.example` /
  `pds.example`). A single-domain design — one origin, routing the auth paths
  by path prefix the way [pds-gatekeeper](https://tangled.org/baileytownsend.dev/pds-gatekeeper)
  does — was **considered and rejected**. The reasons:

  - **Mechanism (how the takeover happens)**: PDS Core overrides the
    Authorization Server metadata so `authorization_endpoint` points at the
    Auth Service. OAuth clients redirect the browser straight there, so the
    stock `@atproto/pds` sign-in UI is never shown. This alone does not
    _require_ a separate origin — PDS Core already wraps upstream heavily and
    could shadow `/oauth/authorize` in place — so it is the mechanism, not the
    motivation.

  - **Cookie isolation (the motivation)**: the Auth Service's session cookies
    (Better Auth's `session`, historically `magic_account_session`) are a
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
  [pds-white-boxing.md](design/pds-white-boxing.md) (items 5, 14, 15). Whether
  these accumulated costs still outweigh the isolation benefits — given that
  PDS Core already wraps upstream and could host the auth UI in-process — has
  not been formally re-evaluated (tracked in
  [#200](https://github.com/hypercerts-org/ePDS/issues/200)).

  Origin rationale: `better-auth-migration-plan.md`, section "Considered and
  rejected: single-domain architecture" (introduced in commit `e6d6a08`; the
  design itself was inherited whole from the upstream `magic-pds` project at
  the initial commit `de3876e`).
