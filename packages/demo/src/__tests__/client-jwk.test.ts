/**
 * Tests for the OAuth confidential-client JWK helper.
 *
 * Covers the parse-and-cache path, the public-JWK derivation, and the
 * end-to-end client_assertion sign-then-verify round-trip using jose's
 * own verifier against the derived public JWK. If this passes, the
 * PDS's JWKS-fetch-then-verify path should succeed against the same
 * keypair.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as crypto from 'node:crypto'
import { importJWK, jwtVerify } from 'jose'

// The module caches its parse of EPDS_CLIENT_PRIVATE_JWK at module load
// time, so each test needs a fresh import with the env var set before
// require-time. Use dynamic import + vi.resetModules for isolation.

function makeTestJwk(): string {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  })
  const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>
  return JSON.stringify(jwk)
}

describe('client-jwk', () => {
  const originalEnv = process.env.EPDS_CLIENT_PRIVATE_JWK

  beforeEach(() => {
    vi.resetModules()
  })

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.EPDS_CLIENT_PRIVATE_JWK
    } else {
      process.env.EPDS_CLIENT_PRIVATE_JWK = originalEnv
    }
  })

  describe('getClientPublicJwk', () => {
    it('returns null when EPDS_CLIENT_PRIVATE_JWK is unset', async () => {
      delete process.env.EPDS_CLIENT_PRIVATE_JWK
      const { getClientPublicJwk, isConfidentialClient } =
        await import('../lib/client-jwk.js')
      expect(await getClientPublicJwk()).toBeNull()
      expect(await isConfidentialClient()).toBe(false)
    })

    it('returns null when EPDS_CLIENT_PRIVATE_JWK is an empty string', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = ''
      const { getClientPublicJwk } = await import('../lib/client-jwk.js')
      expect(await getClientPublicJwk()).toBeNull()
    })

    it('throws a descriptive error on invalid JSON', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = 'not-json'
      const { getClientPublicJwk } = await import('../lib/client-jwk.js')
      await expect(getClientPublicJwk()).rejects.toThrow(/not valid JSON/)
    })

    it('throws on a JWK missing required fields', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = JSON.stringify({
        kty: 'EC',
        crv: 'P-256',
        // d/x/y intentionally missing
      })
      const { getClientPublicJwk } = await import('../lib/client-jwk.js')
      await expect(getClientPublicJwk()).rejects.toThrow(/ES256 private JWK/)
    })

    it('returns a public JWK stripped of the private scalar', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = makeTestJwk()
      const { getClientPublicJwk, isConfidentialClient } =
        await import('../lib/client-jwk.js')
      const pub = await getClientPublicJwk()
      expect(pub).not.toBeNull()
      expect(pub?.kty).toBe('EC')
      expect(pub?.crv).toBe('P-256')
      expect(pub).toHaveProperty('x')
      expect(pub).toHaveProperty('y')
      expect(pub).not.toHaveProperty('d')
      expect(pub?.alg).toBe('ES256')
      expect(pub?.use).toBe('sig')
      expect(pub?.kid).toBeTruthy()
      expect(await isConfidentialClient()).toBe(true)
    })

    it('derives the same kid deterministically from the same keypair', async () => {
      const jwk = makeTestJwk()
      process.env.EPDS_CLIENT_PRIVATE_JWK = jwk
      const { getClientPublicJwk } = await import('../lib/client-jwk.js')
      const kid1 = (await getClientPublicJwk())?.kid
      vi.resetModules()
      const { getClientPublicJwk: getAgain } =
        await import('../lib/client-jwk.js')
      const kid2 = (await getAgain())?.kid
      expect(kid1).toBe(kid2)
      expect(kid1).toBeTruthy()
    })
  })

  describe('signClientAssertion', () => {
    it('returns null when no keypair is configured', async () => {
      delete process.env.EPDS_CLIENT_PRIVATE_JWK
      const { signClientAssertion } = await import('../lib/client-jwk.js')
      const jwt = await signClientAssertion({
        clientId: 'https://demo.example/client-metadata.json',
        audience: 'https://pds.example/oauth/token',
      })
      expect(jwt).toBeNull()
    })

    it('produces a JWT whose header and payload match the spec', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = makeTestJwk()
      const { signClientAssertion, getClientPublicJwk } =
        await import('../lib/client-jwk.js')
      const clientId = 'https://demo.example/client-metadata.json'
      const audience = 'https://pds.example/oauth/token'
      const jwt = await signClientAssertion({ clientId, audience })
      expect(jwt).not.toBeNull()

      const [headerB64, payloadB64] = jwt!.split('.')
      const header = JSON.parse(
        Buffer.from(headerB64, 'base64url').toString('utf8'),
      )
      const payload = JSON.parse(
        Buffer.from(payloadB64, 'base64url').toString('utf8'),
      )

      const pub = await getClientPublicJwk()
      expect(header.alg).toBe('ES256')
      expect(header.typ).toBe('JWT')
      expect(header.kid).toBe(pub?.kid)

      expect(payload.iss).toBe(clientId)
      expect(payload.sub).toBe(clientId)
      expect(payload.aud).toBe(audience)
      expect(typeof payload.jti).toBe('string')
      expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/)
      expect(typeof payload.iat).toBe('number')
      expect(typeof payload.exp).toBe('number')
      expect(payload.exp).toBeGreaterThan(payload.iat)
    })

    it('produces a signature that verifies against the public JWK', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = makeTestJwk()
      const { signClientAssertion, getClientPublicJwk } =
        await import('../lib/client-jwk.js')
      const clientId = 'https://demo.example/client-metadata.json'
      const audience = 'https://pds.example/oauth/token'
      const jwt = (await signClientAssertion({ clientId, audience }))!

      const pub = (await getClientPublicJwk())!
      const publicKey = await importJWK(pub, 'ES256')

      // jwtVerify throws on bad signature / wrong iss / wrong aud /
      // expired, so asserting that it resolves is a full end-to-end
      // validity check. Require iss+aud to match the client_id and
      // target URL we signed with, so we catch any accidental swap
      // between payload fields.
      const { payload } = await jwtVerify(jwt, publicKey, {
        issuer: clientId,
        audience,
      })
      expect(payload.sub).toBe(clientId)
      expect(payload.jti).toBeTruthy()
    })

    it('produces a fresh jti on every call', async () => {
      process.env.EPDS_CLIENT_PRIVATE_JWK = makeTestJwk()
      const { signClientAssertion } = await import('../lib/client-jwk.js')
      const args = {
        clientId: 'https://demo.example/client-metadata.json',
        audience: 'https://pds.example/oauth/token',
      }
      const jwt1 = (await signClientAssertion(args))!
      const jwt2 = (await signClientAssertion(args))!
      const jti1 = JSON.parse(
        Buffer.from(jwt1.split('.')[1], 'base64url').toString('utf8'),
      ).jti
      const jti2 = JSON.parse(
        Buffer.from(jwt2.split('.')[1], 'base64url').toString('utf8'),
      ).jti
      expect(jti1).not.toBe(jti2)
    })
  })
})
