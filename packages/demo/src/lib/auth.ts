/**
 * AT Protocol OAuth helpers: PKCE, DPoP, PAR, handle/DID resolution.
 *
 * Adapted from maearth-demo. Default PDS endpoints match the ePDS
 * docker-compose defaults (PDS_HOSTNAME=pds.example via Caddy).
 */

import * as crypto from 'crypto'

export function getBaseUrl(): string {
  return (process.env.PUBLIC_URL || 'http://localhost:3002')
    .trim()
    .replace(/\/+$/, '')
}

// PKCE helpers
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url')
}

export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url')
}

export function generateState(): string {
  return crypto.randomBytes(16).toString('base64url')
}

// Generate a fresh DPoP key pair (call per OAuth flow, not cached)
export function generateDpopKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  })

  const publicJwk = publicKey.export({ format: 'jwk' })
  const privateJwk = privateKey.export({ format: 'jwk' })

  return { publicKey, privateKey, publicJwk, privateJwk }
}

// Restore a DPoP key pair from a serialized private JWK
export function restoreDpopKeyPair(privateJwk: crypto.JsonWebKey) {
  const privateKey = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' })
  const publicKey = crypto.createPublicKey(privateKey)
  const publicJwk = publicKey.export({ format: 'jwk' })

  return { publicKey, privateKey, publicJwk, privateJwk }
}

export function createDpopProof(opts: {
  privateKey: crypto.KeyObject
  jwk: object
  method: string
  url: string
  nonce?: string
  accessToken?: string
}): string {
  const header = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: opts.jwk,
  }

  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: opts.method,
    htu: opts.url,
    iat: Math.floor(Date.now() / 1000),
  }

  if (opts.nonce) {
    payload.nonce = opts.nonce
  }

  if (opts.accessToken) {
    payload.ath = crypto
      .createHash('sha256')
      .update(opts.accessToken)
      .digest('base64url')
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`

  const signature = crypto.sign(
    'sha256',
    Buffer.from(signingInput),
    opts.privateKey,
  )
  // Convert DER signature to raw r||s format for ES256
  const sigB64 = derToRaw(signature).toString('base64url')

  return `${signingInput}.${sigB64}`
}

// Convert DER-encoded ECDSA signature to raw r||s format
function derToRaw(der: Buffer): Buffer {
  // DER: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  let offset = 2 // skip 0x30 and total length
  if (der[1] > 0x80) offset += der[1] - 0x80 // long form length

  // Read r
  offset++ // skip 0x02
  const rLen = der[offset]
  offset++
  let r = der.subarray(offset, offset + rLen)
  offset += rLen

  // Read s
  offset++ // skip 0x02
  const sLen = der[offset]
  offset++
  let s = der.subarray(offset, offset + sLen)

  // Trim leading zeros and pad to 32 bytes
  if (r.length > 32) r = r.subarray(r.length - 32)
  if (s.length > 32) s = s.subarray(s.length - 32)

  const raw = Buffer.alloc(64)
  r.copy(raw, 32 - r.length)
  s.copy(raw, 64 - s.length)
  return raw
}

// PDS endpoints (defaults match docker-compose PDS_HOSTNAME=pds.example)
export const PDS_URL = process.env.PDS_URL || 'https://pds.example'
export const AUTH_ENDPOINT =
  process.env.AUTH_ENDPOINT || 'https://auth.pds.example/oauth/authorize'

/**
 * URL to the auth-service's /preview index, pre-populated with this
 * demo's own client_id so devs land on the preview pages with the
 * right branding already selected. Derived from AUTH_ENDPOINT so it
 * tracks whatever auth-service the demo is configured against.
 */
export function getAuthPreviewUrl(): string {
  const origin = new URL(AUTH_ENDPOINT).origin
  const clientId = `${getBaseUrl()}/client-metadata.json`
  return `${origin}/preview?client_id=${encodeURIComponent(clientId)}`
}

export const PLC_DIRECTORY_URL =
  process.env.PLC_DIRECTORY_URL || 'https://plc.directory'

// ATProto handle discovery

const RESOLVE_TIMEOUT = 5000

export async function resolveHandleToDid(handle: string): Promise<string> {
  // Try public XRPC endpoint first (works for all handles including *.bsky.social)
  try {
    const res = await fetch(
      `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`,
      { signal: AbortSignal.timeout(RESOLVE_TIMEOUT) },
    )
    if (res.ok) {
      const data = (await res.json()) as { did: string }
      if (data.did) return data.did
    }
  } catch {
    /* fall through to well-known */
  }

  // Fallback: HTTP well-known (works for custom domain handles)
  try {
    const res = await fetch(`https://${handle}/.well-known/atproto-did`, {
      signal: AbortSignal.timeout(RESOLVE_TIMEOUT),
    })
    if (res.ok) {
      const text = await res.text()
      const did = text.trim().split('\n')[0]?.trim()
      if (did?.startsWith('did:')) return did // eslint-disable-line @typescript-eslint/no-unnecessary-condition -- [0] may be undefined
    }
  } catch {
    /* fall through */
  }

  throw new Error(`Could not resolve handle: ${handle}`)
}

export async function resolveDidToPds(did: string): Promise<string> {
  let doc: {
    service?: Array<{ id: string; type: string; serviceEndpoint: string }>
  }

  if (did.startsWith('did:plc:')) {
    const res = await fetch(`${PLC_DIRECTORY_URL}/${did}`, {
      signal: AbortSignal.timeout(RESOLVE_TIMEOUT),
    })
    if (!res.ok) throw new Error(`PLC directory lookup failed for ${did}`)
    doc = await res.json()
  } else if (did.startsWith('did:web:')) {
    const host = did.replace('did:web:', '').replaceAll(':', '/')
    const res = await fetch(`https://${host}/.well-known/did.json`, {
      signal: AbortSignal.timeout(RESOLVE_TIMEOUT),
    })
    if (!res.ok) throw new Error(`DID web lookup failed for ${did}`)
    doc = await res.json()
  } else {
    throw new Error(`Unsupported DID method: ${did}`)
  }

  const pdsService = doc.service?.find(
    (s) =>
      s.type === 'AtprotoPersonalDataServer' && s.id.endsWith('#atproto_pds'),
  )
  if (!pdsService?.serviceEndpoint) {
    throw new Error(`No PDS found in DID document for ${did}`)
  }
  return pdsService.serviceEndpoint
}

export async function discoverOAuthEndpoints(pdsUrl: string): Promise<{
  issuer: string
  parEndpoint: string
  authEndpoint: string
  tokenEndpoint: string
}> {
  // Step 1: Get authorization server from protected resource metadata
  const prRes = await fetch(`${pdsUrl}/.well-known/oauth-protected-resource`, {
    signal: AbortSignal.timeout(RESOLVE_TIMEOUT),
  })
  if (!prRes.ok)
    throw new Error(
      `Failed to fetch protected resource metadata from ${pdsUrl}`,
    )
  const prData = (await prRes.json()) as { authorization_servers?: string[] }
  const asUrl = prData.authorization_servers?.[0]
  if (!asUrl) throw new Error(`No authorization server found for ${pdsUrl}`)

  // Step 2: Get OAuth endpoints from authorization server metadata
  const asRes = await fetch(`${asUrl}/.well-known/oauth-authorization-server`, {
    signal: AbortSignal.timeout(RESOLVE_TIMEOUT),
  })
  if (!asRes.ok)
    throw new Error(
      `Failed to fetch authorization server metadata from ${asUrl}`,
    )
  const asMeta = (await asRes.json()) as {
    issuer?: string
    pushed_authorization_request_endpoint?: string
    authorization_endpoint?: string
    token_endpoint?: string
  }

  if (
    !asMeta.issuer ||
    !asMeta.pushed_authorization_request_endpoint ||
    !asMeta.authorization_endpoint ||
    !asMeta.token_endpoint
  ) {
    throw new Error(`Incomplete OAuth metadata from ${asUrl}`)
  }

  return {
    issuer: asMeta.issuer,
    parEndpoint: asMeta.pushed_authorization_request_endpoint,
    authEndpoint: asMeta.authorization_endpoint,
    tokenEndpoint: asMeta.token_endpoint,
  }
}
