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
