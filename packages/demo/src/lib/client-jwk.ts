/**
 * OAuth confidential-client keypair handling.
 *
 * Reads EPDS_CLIENT_PRIVATE_JWK (an ES256 private JWK as a JSON string)
 * from the environment and exposes helpers that use it for:
 *   - Deriving the public JWK (for /jwks.json)
 *   - Signing a client_assertion JWT (for PAR and token endpoints)
 *
 * If the env var is absent, every helper returns null — the demo then
 * falls back to public-client mode (token_endpoint_auth_method=none)
 * and no client_assertion is included in requests. This is the
 * expected behaviour for local dev without a keypair.
 *
 * Signing is done by `jose` rather than by hand, because getting JWS
 * ES256 right (DER → raw r||s conversion, curve point padding) is
 * easy to get wrong and not something to reinvent. The private JWK
 * is parsed lazily on first use and cached for the process lifetime.
 */

import { type JWK, SignJWT, calculateJwkThumbprint, importJWK } from 'jose'

interface LoadedKey {
  privateJwk: JWK
  publicJwk: JWK
  // Inferred from `importJWK` rather than typed explicitly — jose's v6
  // type defs removed the `KeyLike` alias, and the actual return type
  // is a union of CryptoKey | Uint8Array that varies by input.
  signingKey: Awaited<ReturnType<typeof importJWK>>
  kid: string
}

let cached: LoadedKey | null | undefined

async function load(): Promise<LoadedKey | null> {
  if (cached !== undefined) return cached

  const raw = process.env.EPDS_CLIENT_PRIVATE_JWK
  if (!raw || raw.trim() === '') {
    cached = null
    return null
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new Error(
      `EPDS_CLIENT_PRIVATE_JWK is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    )
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>).kty !== 'EC' ||
    (parsed as Record<string, unknown>).crv !== 'P-256' ||
    typeof (parsed as Record<string, unknown>).d !== 'string' ||
    typeof (parsed as Record<string, unknown>).x !== 'string' ||
    typeof (parsed as Record<string, unknown>).y !== 'string'
  ) {
    throw new Error(
      'EPDS_CLIENT_PRIVATE_JWK must be an ES256 private JWK with kty=EC, crv=P-256, and d/x/y string fields',
    )
  }

  const privateJwk = parsed as JWK

  // Strip the private scalar to produce the public JWK.
  const { d: _d, ...publicRaw } = privateJwk
  // Prefer an explicit kid on the private JWK; otherwise derive an RFC
  // 7638 thumbprint so that the same key material always yields the
  // same kid (the signer and the JWKS endpoint must agree on which
  // key is being used).
  const kid =
    typeof privateJwk.kid === 'string' && privateJwk.kid
      ? privateJwk.kid
      : await calculateJwkThumbprint(publicRaw, 'sha256')

  const publicJwk: JWK = { ...publicRaw, kid, alg: 'ES256', use: 'sig' }
  const signingKey = await importJWK(privateJwk, 'ES256')

  cached = {
    privateJwk: { ...privateJwk, kid },
    publicJwk,
    signingKey,
    kid,
  }
  return cached
}

/**
 * Returns the public JWK (with kid, alg, use) for this demo's OAuth
 * client keypair, or null if EPDS_CLIENT_PRIVATE_JWK is not set.
 *
 * Asynchronous because the JWK thumbprint calculation and key import
 * that back it are asynchronous on first load. Results are cached for
 * the process lifetime, so callers after the first hit see zero
 * latency.
 */
export async function getClientPublicJwk(): Promise<JWK | null> {
  return (await load())?.publicJwk ?? null
}

/**
 * Returns true iff this demo is running as a confidential OAuth client
 * (i.e. EPDS_CLIENT_PRIVATE_JWK is set).
 */
export async function isConfidentialClient(): Promise<boolean> {
  return (await load()) !== null
}

/**
 * Signs a client_assertion JWT for the given (client_id, audience) pair,
 * per RFC 7523 §2.2. Returns null if no keypair is configured.
 *
 * The JWT has `iss`/`sub` set to client_id, `aud` to the target
 * endpoint URL, a freshly-generated `jti` (so retries don't collide
 * with the upstream replay store), and a short 60-second lifetime.
 * The header's `kid` matches the public JWK's kid, so the PDS's JWKS
 * fetch will find the right verification key.
 */
export async function signClientAssertion(opts: {
  clientId: string
  audience: string
  lifetimeSeconds?: number
}): Promise<string | null> {
  const loaded = await load()
  if (!loaded) return null

  const lifetime = opts.lifetimeSeconds ?? 60

  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: loaded.kid })
    .setIssuer(opts.clientId)
    .setSubject(opts.clientId)
    .setAudience(opts.audience)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${lifetime}s`)
    .sign(loaded.signingKey)
}
