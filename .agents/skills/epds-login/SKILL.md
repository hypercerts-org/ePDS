---
name: epds-login
description: Implement AT Protocol OAuth login against an ePDS instance. Covers two flows — Flow 1 (email-first, hand-rolled PAR/DPoP) and Flow 2 (via @atproto/oauth-client-node, accepting no hint / handle / DID). Use when building passwordless OTP login, configuring client metadata (confidential vs public), or integrating NodeOAuthClient.
---

# Implementing ePDS Login

ePDS lets your users sign in to [AT Protocol](https://atproto.com/) apps — like
[Bluesky](https://bsky.app/) — using familiar login methods: **email OTP**, **Google**,
**GitHub**, or any other provider [Better Auth](https://www.better-auth.com/) supports.
Under the hood it is a standard AT Protocol PDS wrapped with a pluggable authentication
layer. Users just sign in with their email or social account and get a presence in the
AT Protocol universe (a DID, a handle, a data repository) automatically provisioned.

From your app's perspective, ePDS uses standard AT Protocol OAuth (PAR + PKCE + DPoP).
The reference implementation is `packages/demo` in the [ePDS repository](https://github.com/hypercerts-org/ePDS).

## Two Flows

| Flow | App provides            | How user starts              | Implementation       |
| ---- | ----------------------- | ---------------------------- | -------------------- |
| 1    | Email address           | OTP screen immediately       | Hand-rolled PAR/DPoP |
| 2    | Nothing, handle, or DID | Depends on input (see below) | `NodeOAuthClient`    |

**Why the split?** `@atproto/oauth-client-node`'s `authorize()` method accepts
a handle or DID as input but explicitly omits `login_hint` from its options —
the library resolves the identity itself and overrides the hint. Flow 1 needs
to pass a raw email as `login_hint` on the auth redirect URL (not in the PAR
body), which the library cannot do. Flow 1 must therefore use hand-rolled
PAR + DPoP requests.

Flow 2 covers three input variants — all use the same `NodeOAuthClient` code:

- **No identifier** — pass the PDS URL; auth server shows its own email form
- **Handle** — pass an AT Protocol handle (e.g. `alice.pds.example.com`); auth server resolves it and sends OTP directly
- **DID** — pass a DID (e.g. `did:plc:abc123...`); auth server resolves it and sends OTP directly

> **Important:** `login_hint` must **never** go in the PAR body when the value
> is an email address. The PDS core validates `login_hint` as an ATProto
> identity (handle or DID) and rejects emails with `Invalid login_hint`. Put
> email `login_hint` only on the **auth redirect URL** — that request goes to
> the ePDS auth service (Better Auth layer), which accepts emails.

## Quick Start — Flow 2 (recommended)

Use `@atproto/oauth-client-node` for any flow that does not require passing a
raw email as `login_hint`.

### 1. Client Metadata (confidential client)

Host at your `client_id` URL (must be HTTPS in production). Provide the
public key via `jwks_uri` (remote endpoint) or inline `jwks` — the two
are mutually exclusive:

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App",
  "redirect_uris": ["https://yourapp.example.com/api/oauth/callback"],
  "scope": "atproto transition:generic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks_uri": "https://yourapp.example.com/jwks.json",
  "dpop_bound_access_tokens": true
}
```

Alternatively, replace `jwks_uri` with an inline `jwks` object containing
the public key directly — see
[client-metadata.md](references/client-metadata.md) for both forms, the
force-consent gotcha with public clients, and key generation instructions.

### 2. Create the OAuth client

```typescript
import { NodeOAuthClient } from '@atproto/oauth-client-node'
import { JoseKey } from '@atproto/jwk-jose'

const privateJwk = JSON.parse(process.env.OAUTH_PRIVATE_KEY!)

const client = new NodeOAuthClient({
  clientMetadata: {
    client_id: 'https://yourapp.example.com/client-metadata.json',
    client_name: 'Your App',
    redirect_uris: ['https://yourapp.example.com/api/oauth/callback'],
    scope: 'atproto transition:generic',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    jwks_uri: 'https://yourapp.example.com/jwks.json',
    dpop_bound_access_tokens: true,
  },
  keyset: [await JoseKey.fromImportable(privateJwk, privateJwk.kid)],

  stateStore: {
    async set(key, value) {
      /* store in DB/Redis */
    },
    async get(key) {
      /* retrieve */
    },
    async del(key) {
      /* delete */
    },
  },
  sessionStore: {
    async set(key, value) {
      /* store in DB/Redis */
    },
    async get(key) {
      /* retrieve */
    },
    async del(key) {
      /* delete */
    },
  },
})
```

### 3. Login handler

```typescript
// No identifier — auth server shows email form
const authUrl = await client.authorize('https://pds.example.com')

// With a handle — auth server resolves and sends OTP
const authUrl = await client.authorize('alice.pds.example.com')

// With a DID — same behaviour as handle
const authUrl = await client.authorize('did:plc:abc123...')
```

Redirect the user's browser to `authUrl`.

### 4. Callback handler

```typescript
const { session, state } = await client.callback(
  new URLSearchParams(callbackQueryString),
)
// session.did — the user's DID (e.g. "did:plc:abc123...")
// session.fetchHandler() — authenticated fetch for AT Protocol API calls
```

### 5. Restore a session

```typescript
const session = await client.restore(userDid)
// Use session.fetchHandler() for API calls
```

### 6. Serve library endpoints

Your `client_id` URL must be publicly reachable. If you use `jwks_uri`
(rather than inline `jwks`), that endpoint must also be reachable. You
can serve both from the `NodeOAuthClient` instance:

```typescript
app.get('/client-metadata.json', (req, res) => {
  res.json(client.clientMetadata)
})

// Only needed when using jwks_uri (not inline jwks)
app.get('/jwks.json', (req, res) => {
  res.json(client.jwks)
})
```

## Quick Start — Flow 1 (hand-rolled)

Flow 1 requires hand-rolled PAR and token exchange because the library
cannot pass a raw email as `login_hint`. See
[references/flows.md](references/flows.md) for the full walkthrough and
[references/dpop-pkce.md](references/dpop-pkce.md) for the helper
functions.

The abbreviated version:

1. Generate DPoP key pair and PKCE verifier
2. POST to `/oauth/par` (with DPoP nonce retry)
3. Redirect browser to `/oauth/authorize?...&login_hint=<email>`
4. Handle callback: verify state, exchange code for tokens (with DPoP nonce retry)

## Common Pitfalls

| Pitfall                            | Fix                                                                                           |
| ---------------------------------- | --------------------------------------------------------------------------------------------- |
| Consent screen on every login      | Switch to `private_key_jwt` — public clients force consent unless in the PDS trusted list     |
| Flash of email form (Flow 1)       | Include `login_hint` on the **auth redirect URL only** (never in the PAR body)                |
| `Invalid login_hint` from PAR      | Remove `login_hint` from the PAR body — PDS core only accepts handles/DIDs, not emails        |
| `auth_failed` immediately          | Check Caddy logs — likely a DNS/upstream name mismatch                                        |
| DPoP rejected (hand-rolled only)   | Always implement the nonce retry loop (ePDS always demands a nonce)                           |
| Token exchange fails (hand-rolled) | Restore the DPoP key pair from the session cookie, don't generate a new one                   |
| `Cannot find package` in tests     | Run `pnpm build` before `pnpm test` — vitest needs `dist/`                                    |
| `NodeOAuthClient` callback 401     | Ensure `stateStore` and `sessionStore` persist across requests (not in-memory for serverless) |

## Handles

New users choose their own handle during signup (e.g. `alice.pds.example.com`).
The local part must be 5–20 characters, alphanumeric with hyphens. Handles are
not derived from the user's email address, for privacy.

## ePDS Endpoints (defaults)

```
PAR:   https://<pds-hostname>/oauth/par
Auth:  https://auth.<pds-hostname>/oauth/authorize
Token: https://<pds-hostname>/oauth/token
```

## Reference Files

- [Client metadata fields](references/client-metadata.md) — confidential vs public, JWKS, all fields, email branding
- [Full flow walkthrough](references/flows.md) — sequence diagrams, Flow 1 hand-rolled code, Flow 2 library code
- [PKCE and DPoP helpers](references/dpop-pkce.md) — Flow 1 only; Flow 2 should use `NodeOAuthClient` instead
