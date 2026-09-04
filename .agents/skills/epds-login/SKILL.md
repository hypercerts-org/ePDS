---
name: epds-login
description: Implement AT Protocol OAuth login against an ePDS instance with @atproto/oauth-client-node. Covers email-first OTP, hosted email entry, handle/DID login, client metadata, callbacks, and debugging. Use when building passwordless login against ePDS, configuring confidential/public OAuth clients, or integrating NodeOAuthClient.
---

# Implementing ePDS Login

ePDS lets users sign in to AT Protocol apps using email OTP. New users receive
a DID, handle, and data repository automatically.

Earlier versions of this skill recommended a hand-rolled OAuth flow. That
guidance is deprecated in favor of `@atproto/oauth-client-node`, which handles
PAR, PKCE, DPoP, token exchange, and OAuth state. The repository's
`packages/demo` client still contains the earlier implementation and is not the
current integration reference.

For protocol-level guidance beyond ePDS specifics—granular scope design,
identity verification after token exchange, session storage, and refresh-token
race handling—read the `atproto-oauth` skill.

## Choose the Login Input

All variants use one `NodeOAuthClient` and converge on the same callback and
`session.did`.

| App provides | Call                                               | User experience                         |
| ------------ | -------------------------------------------------- | --------------------------------------- |
| Email        | `authorize(epdsUrl)`, then append URL `login_hint` | OTP step immediately                    |
| Nothing      | `authorize(epdsUrl)`                               | Hosted ePDS login form                  |
| Handle       | `authorize(handle)`                                | SDK resolves account; ePDS starts login |
| DID          | `authorize(did)`                                   | SDK resolves account; ePDS starts login |

`NodeOAuthClient.authorize()` deliberately does not accept `login_hint` in its
options. For email-first login, call `authorize(epdsUrl)` first, then append the
email to the returned authorization URL. This preserves SDK ownership of PAR,
PKCE, DPoP, state, nonce retry, token exchange, and OAuth session storage.

> **ePDS-specific behavior:** Put an email `login_hint` only on the returned
> authorization URL. Never put it in the PAR body. PDS core validates a PAR
> `login_hint` as an AT Protocol handle or DID and rejects an email with
> `Invalid login_hint`; ePDS auth-service accepts email hints from the browser
> authorization request.
>
> Email in a URL may appear in browser history, infrastructure logs, and error
> reports. Do not log authorization URLs. Prefer hosted email entry when that
> exposure is unacceptable, and configure query-string redaction where possible.

## Quick Start

### 1. Client Metadata

Host metadata at the HTTPS URL used as `client_id`. A confidential client is
recommended for server-rendered web applications:

```json
{
  "client_id": "https://yourapp.example.com/client-metadata.json",
  "client_name": "Your App",
  "redirect_uris": ["https://yourapp.example.com/api/oauth/callback"],
  "scope": "atproto include:org.hypercerts.authWrite include:app.certified.authWrite",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks_uri": "https://yourapp.example.com/jwks.json",
  "dpop_bound_access_tokens": true
}
```

`atproto` is mandatory and must come first. Replace example Hypercerts
permission sets with only those your app needs. A permission set containing
`rpc:` service calls also needs `?aud=<service-did>`; percent-encode `#` as
`%23`. Avoid legacy `transition:generic`.

You may replace `jwks_uri` with inline `jwks`; never publish the private `d`
parameter. Read [client-metadata.md](references/client-metadata.md) for public
clients, JWKS generation and rotation, consent behavior, branding, and email
templates.

### 2. Create One OAuth Client

Create a singleton. Its state and session stores must persist across requests;
in-memory stores are unsafe for serverless or multi-instance deployments.
Multi-instance deployments also need a distributed `requestLock` so concurrent
token refreshes for one DID cannot revoke each other.

```typescript
import { NodeOAuthClient } from '@atproto/oauth-client-node'
import { JoseKey } from '@atproto/jwk-jose'

const privateJwk = JSON.parse(process.env.OAUTH_PRIVATE_KEY!)

const client = new NodeOAuthClient({
  // Required across multiple processes. Use a distributed lock implementation.
  requestLock,
  clientMetadata: {
    client_id: 'https://yourapp.example.com/client-metadata.json',
    client_name: 'Your App',
    redirect_uris: ['https://yourapp.example.com/api/oauth/callback'],
    scope:
      'atproto include:org.hypercerts.authWrite include:app.certified.authWrite',
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
      /* persist in DB/Redis */
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
      /* persist in DB/Redis */
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

A single-process deployment may omit `requestLock`; the SDK then uses only a
process-local fallback and warns that credentials might be revoked. A public
client omits `OAUTH_PRIVATE_KEY`, `keyset`, and confidential-client metadata
fields; read [client-metadata.md](references/client-metadata.md).

For local HTTP-only ePDS development, pass `allowHttp: true`. Never enable it in
production.

### 3. Login Handler

```typescript
const EPDS_URL = process.env.EPDS_URL!

export async function beginLogin(input?: {
  email?: string
  identifier?: string
  forceLogin?: boolean
}): Promise<URL> {
  // identifier may be a handle or DID. Without one, use the configured ePDS.
  // Keep prompt in PAR for pds-core, then duplicate it on the returned URL for
  // auth-service's browser-session decision.
  const authorizationUrl = await client.authorize(
    input?.identifier ?? EPDS_URL,
    input?.forceLogin ? { prompt: 'login' } : undefined,
  )

  // Email hints belong on the browser authorization URL, not in PAR.
  if (input?.email) {
    authorizationUrl.searchParams.set('login_hint', input.email)
  }

  // ePDS reads this URL parameter when deciding whether to reuse a browser
  // session. A prompt stored only in PAR does not engage that behavior.
  if (input?.forceLogin) {
    authorizationUrl.searchParams.set('prompt', 'login')
  }

  return authorizationUrl
}
```

Validate and normalize user input before calling this helper. Redirect the
browser to the returned URL.

### 4. Use One Shared Callback

Email, hosted-form, handle, and DID login should normally use one callback:

```text
/api/oauth/callback
```

`client.callback()` matches `state` to context created by `authorize()`, then
restores issuer, redirect URI, PKCE verifier, and DPoP key before exchanging the
code. Login method does not require a separate callback.

```typescript
const { session, state } = await client.callback(
  new URLSearchParams(callbackQueryString),
)

const userDid = session.did
```

Use a separate callback only when application behavior genuinely differs. In
that case, register both URIs in client metadata and pass the selected URI to
`authorize()` explicitly:

```typescript
const epdsCallbackUri = 'https://yourapp.example.com/api/oauth/epds/callback'

await client.authorize(EPDS_URL, {
  redirect_uri: epdsCallbackUri,
})

// Pass the same non-default URI during code exchange.
await client.callback(callbackParams, {
  redirect_uri: epdsCallbackUri,
})
```

Application-session management is a generic AT Protocol OAuth concern; follow
the `atproto-oauth` skill for that guidance.

### 5. Serve Metadata and JWKS

```typescript
app.get('/client-metadata.json', (_request, response) => {
  response.json(publishedClientMetadata)
})

// Only needed when metadata uses jwks_uri instead of inline jwks.
app.get('/jwks.json', (_request, response) => {
  response.json(client.jwks)
})
```

Serve the original `publishedClientMetadata` object when using ePDS extension
fields such as `branding` or `epds_handle_mode`. SDK validation may omit unknown
extension fields from `client.clientMetadata`.

The ePDS must be able to reach discoverable client metadata and remote JWKS. A
remote ePDS cannot fetch an endpoint bound only to your local machine; use an
HTTPS tunnel or deployed development URL. Loopback clients follow separate AT
Protocol metadata rules and are not confidential clients.

## Forcing Fresh Sign-In

Existing ePDS cookies may lead to account reuse or an account chooser. Put
`prompt=login` in both PAR and the returned authorization URL:

```typescript
const url = await client.authorize(EPDS_URL, { prompt: 'login' })
url.searchParams.set('prompt', 'login')
```

For email-first login, append the email too:

```typescript
const url = await client.authorize(EPDS_URL, { prompt: 'login' })
url.searchParams.set('login_hint', email)
url.searchParams.set('prompt', 'login')
```

The PAR value informs pds-core's authentication guard. ePDS auth-service also
inspects the browser authorization URL when deciding whether to reuse a browser
session, so the URL value is required too.

## Verification

Check authorization-server discovery:

```bash
curl -fsS "$EPDS_URL/.well-known/oauth-authorization-server" \
  | python3 -m json.tool
```

Confirm metadata contains exact callback URI and expected scope:

```bash
curl -fsS "https://yourapp.example.com/client-metadata.json" \
  | python3 -m json.tool
```

When metadata uses `jwks_uri`, confirm that endpoint exposes no private `d`
value:

```bash
curl -fsS "https://yourapp.example.com/jwks.json" \
  | python3 -m json.tool
```

Skip this endpoint check when metadata contains inline `jwks`; inspect those
inline keys instead.

Test login endpoint without following redirects. Expect a `3xx` response whose
`Location` points to ePDS authorization endpoint and contains `request_uri`:

```bash
curl -sS -o /dev/null -D - \
  "https://yourapp.example.com/api/oauth/login?email=user%40example.com"
```

For email-first login, confirm `Location` also contains encoded `login_hint`.
Never print OAuth tokens, private JWKs, cookies, or store contents while
debugging.

## Common Failures

| Failure                                 | Likely cause                                              | Fix                                                                    |
| --------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| `Invalid login_hint` during PAR         | Email included in PAR body                                | Append email only after `authorize()` returns                          |
| Fresh-login request still shows chooser | `prompt=login` exists only in PAR                         | Append it to returned authorization URL                                |
| `Invalid redirect_uri`                  | Callback missing from metadata, or wrong URI selected     | Register exact URI; pass `redirect_uri` when not using first entry     |
| `client_id not found`                   | ePDS cannot fetch metadata URL                            | Use reachable HTTPS metadata URL or supported loopback client metadata |
| Callback returns 401 or loses state     | In-memory store lost or request reached another instance  | Use shared persistent state and session stores                         |
| Consent appears every login             | Public untrusted client                                   | Use `private_key_jwt` or operator trust configuration                  |
| New account has no profile              | Profile record has not been created                       | Use DID as display fallback; resolve handle separately when needed     |
| OTP never arrives                       | Unknown email, delivery delay, or ePDS mail configuration | Verify address and inspect ePDS operator logs without exposing secrets |

## Handles

New users receive a handle during signup. With `epds_handle_mode` set to
`picker` or `picker-with-random`, they can choose a local part of 5–20
characters using letters, numbers, and hyphens. With `random`, ePDS assigns the
handle without showing a picker. Handles are not derived from email addresses.

Do not expect `OAuthSession` to expose `session.handle`; its stable identity is
`session.did`. Resolve current handle through an AT Protocol identity resolver
when needed.

## ePDS Endpoint Discovery

Do not hard-code PAR, authorization, or token endpoints. `NodeOAuthClient`
discovers them through OAuth authorization-server metadata. ePDS commonly uses
separate PDS and auth-service hostnames; that is normal.

## Reference Files

- [Client metadata](references/client-metadata.md): confidential/public clients, JWKS, branding, email templates
- [Flow walkthrough](references/flows.md): hosted-form and email-first login examples
- [PKCE and DPoP](references/dpop-pkce.md): responsibilities handled by `NodeOAuthClient`
