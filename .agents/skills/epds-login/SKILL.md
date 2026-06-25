---
name: epds-login
description: Implement AT Protocol OAuth login against an ePDS instance. Covers email-first OTP with @atproto/oauth-client-browser or @atproto/oauth-client-node by appending login_hint to the returned authorize URL, plus hand-rolled PAR/DPoP only as a fallback. Use when building passwordless OTP login, configuring client metadata (confidential vs public), or integrating BrowserOAuthClient/NodeOAuthClient.
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

## Recommended Login Paths

| Path                 | App type                          | App provides                                               | Implementation                                                                                                                                                      |
| -------------------- | --------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Browser OAuth client | Browser-only SPA or public client | PDS URL for email-first/no-identifier login, or handle/DID | `BrowserOAuthClient.authorize()`, append email `login_hint` and `prompt=login` to the returned authorize URL, then `init()` consumes the callback                   |
| Node OAuth client    | Server app or confidential client | PDS URL for email-first/no-identifier login, or handle/DID | `NodeOAuthClient.authorize()`, append email `login_hint` and `prompt=login` to the returned authorize URL, then `callback()` consumes the callback                  |
| Hand-rolled fallback | Any runtime                       | Email address                                              | Implement PAR, PKCE, DPoP, nonce retry, and token exchange yourself only if the OAuth client cannot expose the authorize URL or ePDS stops honoring URL-level hints |

`@atproto/oauth-client-browser` and `@atproto/oauth-client-node` both create the
PAR request, PKCE verifier, DPoP key, nonce retry, state, token exchange, and
session storage path for you. For email-first ePDS login, call `authorize()`
with the PDS URL and append the raw email to the returned `/oauth/authorize`
URL as `login_hint`. Do **not** put an email in the PAR body.

Use these input variants with the same OAuth client code:

- **Email-first OTP** — pass the PDS URL to `authorize()`, then append `login_hint=<email>` and `prompt=login` to the returned URL.
- **No identifier** — pass the PDS URL; auth server shows its own email form.
- **Handle** — pass an AT Protocol handle (e.g. `alice.pds.example.com`); this fork shows the stock PDS handle/password page.
- **DID** — pass a DID (e.g. `did:plc:abc123...`); same behaviour as handle.

> **Important:** `login_hint` must **never** go in the PAR body when the value
> is an email address. The PDS core validates PAR `login_hint` as an ATProto
> identity (handle or DID) and rejects emails with `Invalid login_hint`. Put
> email `login_hint` only on the **auth redirect URL** — that request goes to
> the ePDS auth service (Better Auth layer), which accepts emails.

## Quick Start — BrowserOAuthClient

Use `@atproto/oauth-client-browser` for browser-only apps. It supports the
ePDS email-first pattern as long as you call `authorize()` yourself and redirect
after appending query parameters. Do not use `signInRedirect()` when you need to
add email `login_hint`, because it redirects before you can patch the URL.

### 1. Client Metadata (public browser client)

Host at your `client_id` URL. Browser-only apps normally use a public client:

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App",
  "redirect_uris": ["https://yourapp.example.com/"],
  "scope": "atproto transition:generic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "dpop_bound_access_tokens": true
}
```

Public clients usually show consent on each login unless the PDS trusts the
client. For server apps, prefer the confidential `NodeOAuthClient` setup below.

### 2. Create the browser OAuth client

```typescript
import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

const client = await BrowserOAuthClient.load({
  clientId: 'https://yourapp.example.com/client-metadata.json',
})
```

### 3. Login handler with optional email-first OTP

```typescript
async function startLogin(input: {
  pdsUrl: string
  email?: string
  forceLogin?: boolean
}) {
  const url = await client.authorize(input.pdsUrl, {
    scope: 'atproto transition:generic',
    ...(input.forceLogin ? { prompt: 'login' } : {}),
  })

  if (input.email?.trim()) {
    url.searchParams.set('login_hint', input.email.trim())
  }
  if (input.forceLogin || input.email?.trim()) {
    url.searchParams.set('prompt', 'login')
  }

  window.location.assign(url.toString())
}
```

### 4. Restore or consume the callback

```typescript
const result = await client.init()
const session = result?.session
// session?.did — the user's DID
// session?.fetchHandler() — authenticated fetch for AT Protocol API calls
```

## Quick Start — NodeOAuthClient

Use `@atproto/oauth-client-node` for server apps, confidential clients, and
frameworks that handle the OAuth callback on the server.

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
// Email-first OTP — pass the PDS URL, then patch the authorize URL
const emailUrl = await client.authorize('https://pds.example.com', {
  prompt: 'login',
})
emailUrl.searchParams.set('login_hint', email)
emailUrl.searchParams.set('prompt', 'login')

// No identifier — auth server shows email form
const pdsUrl = await client.authorize('https://pds.example.com')

// With a handle — stock PDS handle/password page
const handleUrl = await client.authorize('alice.pds.example.com')

// With a DID — same behaviour as handle
const didUrl = await client.authorize('did:plc:abc123...')
```

Redirect the user's browser to the returned URL for the path they chose.

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

## Fallback — Hand-rolled PAR/DPoP

Hand-rolled PAR and token exchange are no longer the default recommendation
for email-first ePDS login. Use the Browser or Node OAuth client first and
append email `login_hint` to the returned authorize URL. Only hand-roll when
your OAuth client cannot expose that URL before redirecting, when you need a
custom OAuth behavior the library cannot represent, or when you are debugging
PAR/DPoP itself. See [references/flows.md](references/flows.md) for the full
walkthrough and [references/dpop-pkce.md](references/dpop-pkce.md) for the
helper functions.

The abbreviated fallback version:

1. Generate DPoP key pair and PKCE verifier.
2. POST to `/oauth/par` without email `login_hint` (with DPoP nonce retry).
3. Redirect browser to `/oauth/authorize?...&login_hint=<email>`.
4. Handle callback: verify state, exchange code for tokens (with DPoP nonce retry).

## Forcing a Fresh Sign-In (`prompt=login`)

When a previous sign-in's cookies are present in the browser, ePDS skips
the email code form and lands the user on the account chooser to confirm
which identity to reuse. To force the email code form instead, use the
standard OIDC `prompt=login` parameter.

**Important — where to put it:** ePDS's auth service decides whether to
engage session reuse by inspecting the **query string** of the
`/oauth/authorize` redirect. PAR-body `prompt=login` is ignored.

Even when you pass `prompt` to `authorize()` options, also append
`&prompt=login` to the authorization URL the library returns before redirecting
the user.

**Hand-rolled fallback:**

```typescript
const authUrl =
  `${authEndpoint}?client_id=${encodeURIComponent(clientId)}` +
  `&request_uri=${encodeURIComponent(parData.request_uri)}` +
  (forceLogin ? '&prompt=login' : '')
```

**With `BrowserOAuthClient` or `NodeOAuthClient`:**

```typescript
const url = await client.authorize(input, { prompt: 'login' })
// The library puts prompt in PAR; also append it to the URL query string
// so ePDS's session-reuse short-circuit fires.
url.searchParams.set('prompt', 'login')

// For email-first OTP, append the email to the returned authorize URL too.
url.searchParams.set('login_hint', email)
```

## Common Pitfalls

| Pitfall                                     | Fix                                                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Consent screen on every login               | Switch server apps to `private_key_jwt`; public browser clients force consent unless in the PDS trusted list        |
| Flash of email form                         | Use `authorize()` instead of immediate redirect helpers, then append `login_hint` on the **auth redirect URL only** |
| `Invalid login_hint` from PAR               | Remove email `login_hint` from the PAR body — PDS core only accepts handles/DIDs there                              |
| `auth_failed` immediately                   | Check Caddy logs — likely a DNS/upstream name mismatch                                                              |
| DPoP rejected (hand-rolled fallback only)   | Always implement the nonce retry loop (ePDS always demands a nonce)                                                 |
| Token exchange fails (hand-rolled fallback) | Restore the DPoP key pair from the session cookie, don't generate a new one                                         |
| `Cannot find package` in tests              | Run `pnpm build` before `pnpm test` — vitest needs `dist/`                                                          |
| `NodeOAuthClient` callback 401              | Ensure `stateStore` and `sessionStore` persist across requests (not in-memory for serverless)                       |
| `prompt=login` ignored, chooser still shown | Append `&prompt=login` to the **authorize URL** query string — PAR body alone doesn't engage ePDS's short-circuit   |

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
- [Full flow walkthrough](references/flows.md) — sequence diagrams, BrowserOAuthClient/NodeOAuthClient examples, and hand-rolled fallback code
- [PKCE and DPoP helpers](references/dpop-pkce.md) — fallback only; prefer BrowserOAuthClient or NodeOAuthClient for normal app login
