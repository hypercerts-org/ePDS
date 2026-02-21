# Architecture

## System Overview

```
                  +-----------------+
                  |   OAuth Client  |
                  | (Bluesky, custom|
                  |   apps, etc.)   |
                  +-------+---------+
                          |
                   1. PAR  |  8. Token exchange
                          v
           +-----------------------------+
           |          PDS Core           |
           |  (stock @atproto/pds +      |
           |   magic-callback endpoint)  |
           +-----------------------------+
                   |             ^
   2. AS metadata  |             | 7. Auth code issued
   redirects to    |             |    via /oauth/magic-callback
   auth subdomain  v             |
           +-----------------------------+
           |        Auth Service         |
           |  /oauth/authorize           |
           |  /auth/complete             |
           |  /account/* (settings)      |
           |  (better-auth OTP backend)  |
           +-----------------------------+
                          |
              3-6. Email  |  OTP code flow
                          v
                     User's inbox
```

The PDS Core is a thin wrapper around the stock [`@atproto/pds`](https://github.com/bluesky-social/atproto)
package. Its AS (Authorization Server) metadata points `authorization_endpoint` at the Auth Service
subdomain, delegating all user authentication to it.

The Auth Service handles the login UI and session management via [Better Auth](https://www.better-auth.com/).
On successful authentication, it calls back to PDS Core via the HMAC-signed `/oauth/magic-callback`
endpoint to issue an AT Protocol authorization code.

## Packages

| Package | Description |
|---------|-------------|
| `@magic-pds/shared` | Database (SQLite), crypto utilities, types, logger |
| `@magic-pds/auth-service` | Auth UI, OTP code flow via better-auth, account settings |
| `@magic-pds/pds-core` | Wraps `@atproto/pds` with magic-callback integration |

## Key Design Decisions

- **Better Auth** manages user sessions, OTP codes, and (optionally) social login.
  It does not replace AT Protocol OAuth — it sits alongside it and bridges into it
  via the `/auth/complete` → `/oauth/magic-callback` path.

- **Random handles**: users get a random handle (e.g. `a3x9kf.epds-poc1.example.com`)
  rather than an email-derived one, for privacy.

- **Single invite code**: `MAGIC_INVITE_CODE` is a high-`useCount` invite code used for
  all account creation, avoiding the need to distribute individual invite codes.

- **Passwordless accounts**: PDS accounts are created with a random unguessable password.
  Users can only log in via the OTP flow (or social providers if configured).

- **HMAC-signed callback**: the redirect from Auth Service to PDS Core's
  `/oauth/magic-callback` is signed with `MAGIC_CALLBACK_SECRET` so PDS Core can verify
  it was produced by a legitimate auth flow.
