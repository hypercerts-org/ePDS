# PKCE and DPoP Helper Implementations

> **Flow 2 does not need these helpers.** If your app uses
> `@atproto/oauth-client-node` (recommended for any flow that does not pass
> a raw email as `login_hint`), the library handles PKCE, DPoP, and nonce
> retry internally. These helpers are only needed for **Flow 1** (hand-rolled
> PAR/DPoP with email `login_hint`).

Copy these into your project. They have no dependencies beyond Node's built-in
`node:crypto` module.

```typescript
import * as crypto from 'node:crypto'

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/** Generate a random code verifier for PKCE. Store this in your session. */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url')
}

/** Derive the code challenge to send to the auth server. */
export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url')
}

/** Generate a random state value. Store this in your session. */
export function generateState(): string {
  return crypto.randomBytes(16).toString('base64url')
}

// ---------------------------------------------------------------------------
// DPoP helpers
// ---------------------------------------------------------------------------

/**
 * Generate a fresh DPoP key pair.
 *
 * Call this once per login attempt. Store `privateJwk` in your session cookie
 * so the callback handler can restore the key pair for token exchange.
 * Never reuse a key pair across different login flows.
 */
export function generateDpopKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  })
  return {
    privateKey,
    publicJwk: publicKey.export({ format: 'jwk' }),
    privateJwk: privateKey.export({ format: 'jwk' }),
  }
}

/**
 * Restore a DPoP key pair from a serialized private JWK.
 *
 * Use this in the callback handler to recover the key pair from the session
 * cookie that was set during the login handler.
 */
export function restoreDpopKeyPair(privateJwk: crypto.JsonWebKey) {
  const privateKey = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' })
  const publicKey = crypto.createPublicKey(privateKey)
  return {
    privateKey,
    publicJwk: publicKey.export({ format: 'jwk' }),
  }
}

/**
 * Create a DPoP proof JWT for a single HTTP request.
 *
 * Create a new proof for every request — they are single-use by design.
 *
 * @param opts.nonce - Include when the server returned a `dpop-nonce` header.
 * @param opts.accessToken - Include when making API calls with an access token.
 */
export function createDpopProof(opts: {
  privateKey: crypto.KeyObject
  jwk: object
  method: string
  url: string
  nonce?: string
  accessToken?: string
}): string {
  const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: opts.jwk }

  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: opts.method,
    htu: opts.url,
    iat: Math.floor(Date.now() / 1000),
  }
  if (opts.nonce) payload.nonce = opts.nonce
  if (opts.accessToken) {
    payload.ath = crypto
      .createHash('sha256')
      .update(opts.accessToken)
      .digest('base64url')
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const sig = crypto.sign('sha256', Buffer.from(signingInput), opts.privateKey)
  return `${signingInput}.${derToRaw(sig).toString('base64url')}`
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Convert a DER-encoded ECDSA signature to raw r||s format.
 * Required because Node's crypto.sign() outputs DER, but JWTs expect raw.
 */
function derToRaw(der: Buffer): Buffer {
  // DER: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  let offset = 2
  if (der[1]! > 0x80) offset += der[1]! - 0x80 // long-form length

  offset++ // skip 0x02 tag
  const rLen = der[offset++]!
  let r = der.subarray(offset, offset + rLen)
  offset += rLen

  offset++ // skip 0x02 tag
  const sLen = der[offset++]!
  let s = der.subarray(offset, offset + sLen)

  // DER may pad with a leading zero byte to indicate positive — strip it
  if (r.length > 32) r = r.subarray(r.length - 32)
  if (s.length > 32) s = s.subarray(s.length - 32)

  const raw = Buffer.alloc(64)
  r.copy(raw, 32 - r.length)
  s.copy(raw, 64 - s.length)
  return raw
}
```

## Nonce retry pattern (Flow 1 only)

ePDS always rejects the first DPoP proof with a `400` and a `dpop-nonce`
header. This is standard behaviour. For Flow 1 (hand-rolled), wrap every
PAR and token request in this retry loop. Flow 2 does not need this —
`NodeOAuthClient` handles nonce retry internally.

```typescript
async function fetchWithDpopRetry(
  url: string,
  body: URLSearchParams,
  privateKey: crypto.KeyObject,
  publicJwk: object,
): Promise<Response> {
  const makeProof = (nonce?: string) =>
    createDpopProof({ privateKey, jwk: publicJwk, method: 'POST', url, nonce })

  let res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      DPoP: makeProof(),
    },
    body: body.toString(),
  })

  if (!res.ok) {
    const nonce = res.headers.get('dpop-nonce')
    if (nonce && res.status === 400) {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          DPoP: makeProof(nonce),
        },
        body: body.toString(),
      })
    }
  }

  return res
}
```
