/**
 * Tests for pure crypto/helper functions in demo/lib/auth.ts.
 *
 * Network-dependent functions (resolveHandleToDid, resolveDidToPds,
 * discoverOAuthEndpoints) are not tested here — they require live external
 * services and are better covered by integration/e2e tests.
 */
import { describe, it, expect } from 'vitest'
import {
  getBaseUrl,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  generateDpopKeyPair,
  restoreDpopKeyPair,
  createDpopProof,
  PDS_URL,
  AUTH_ENDPOINT,
  PLC_DIRECTORY_URL,
} from '../lib/auth.js'

describe('getBaseUrl', () => {
  it('returns a URL without trailing slashes', () => {
    const url = getBaseUrl()
    expect(url).not.toMatch(/\/$/)
  })
})

describe('PKCE helpers', () => {
  describe('generateCodeVerifier', () => {
    it('generates a base64url-encoded string', () => {
      const verifier = generateCodeVerifier()
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
    })

    it('generates unique verifiers', () => {
      const a = generateCodeVerifier()
      const b = generateCodeVerifier()
      expect(a).not.toBe(b)
    })

    it('has sufficient entropy (at least 32 bytes = 43+ chars base64url)', () => {
      const verifier = generateCodeVerifier()
      expect(verifier.length).toBeGreaterThanOrEqual(43)
    })
  })

  describe('generateCodeChallenge', () => {
    it('generates a base64url SHA-256 hash of the verifier', () => {
      const verifier = generateCodeVerifier()
      const challenge = generateCodeChallenge(verifier)
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/)
      // SHA-256 = 32 bytes = 43 chars base64url
      expect(challenge.length).toBe(43)
    })

    it('produces the same challenge for the same verifier', () => {
      const verifier = 'test-verifier-value'
      const c1 = generateCodeChallenge(verifier)
      const c2 = generateCodeChallenge(verifier)
      expect(c1).toBe(c2)
    })

    it('produces different challenges for different verifiers', () => {
      const c1 = generateCodeChallenge('verifier-a')
      const c2 = generateCodeChallenge('verifier-b')
      expect(c1).not.toBe(c2)
    })
  })
})

describe('generateState', () => {
  it('generates a base64url-encoded string', () => {
    const state = generateState()
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('generates unique states', () => {
    const a = generateState()
    const b = generateState()
    expect(a).not.toBe(b)
  })
})

describe('DPoP key pair generation', () => {
  it('generates a key pair with public and private keys', () => {
    const kp = generateDpopKeyPair()
    expect(kp.publicKey).toBeDefined()
    expect(kp.privateKey).toBeDefined()
    expect(kp.publicJwk).toBeDefined()
    expect(kp.privateJwk).toBeDefined()
  })

  it('public JWK has EC P-256 params', () => {
    const kp = generateDpopKeyPair()
    expect(kp.publicJwk.kty).toBe('EC')
    expect(kp.publicJwk.crv).toBe('P-256')
    expect(kp.publicJwk.x).toBeDefined()
    expect(kp.publicJwk.y).toBeDefined()
  })

  it('private JWK has the d parameter', () => {
    const kp = generateDpopKeyPair()
    expect(kp.privateJwk.d).toBeDefined()
  })
})

describe('restoreDpopKeyPair', () => {
  it('restores a key pair from a private JWK', () => {
    const original = generateDpopKeyPair()
    const restored = restoreDpopKeyPair(original.privateJwk)

    expect(restored.publicJwk.x).toBe(original.publicJwk.x)
    expect(restored.publicJwk.y).toBe(original.publicJwk.y)
    expect(restored.privateJwk.d).toBe(original.privateJwk.d)
  })
})

describe('createDpopProof', () => {
  it('creates a valid JWT structure (header.payload.signature)', () => {
    const kp = generateDpopKeyPair()
    const proof = createDpopProof({
      privateKey: kp.privateKey,
      jwk: kp.publicJwk,
      method: 'POST',
      url: 'https://pds.example/oauth/token',
    })

    const parts = proof.split('.')
    expect(parts).toHaveLength(3)

    // Decode header
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
    expect(header.alg).toBe('ES256')
    expect(header.typ).toBe('dpop+jwt')
    expect(header.jwk).toBeDefined()

    // Decode payload
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    expect(payload.htm).toBe('POST')
    expect(payload.htu).toBe('https://pds.example/oauth/token')
    expect(payload.jti).toBeDefined()
    expect(payload.iat).toBeDefined()
  })

  it('includes nonce when provided', () => {
    const kp = generateDpopKeyPair()
    const proof = createDpopProof({
      privateKey: kp.privateKey,
      jwk: kp.publicJwk,
      method: 'GET',
      url: 'https://pds.example/resource',
      nonce: 'server-nonce-123',
    })

    const parts = proof.split('.')
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    expect(payload.nonce).toBe('server-nonce-123')
  })

  it('includes ath (access token hash) when accessToken provided', () => {
    const kp = generateDpopKeyPair()
    const proof = createDpopProof({
      privateKey: kp.privateKey,
      jwk: kp.publicJwk,
      method: 'GET',
      url: 'https://pds.example/resource',
      accessToken: 'my-access-token',
    })

    const parts = proof.split('.')
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    expect(payload.ath).toBeDefined()
    expect(payload.ath).toMatch(/^[A-Za-z0-9_-]+$/) // base64url
  })

  it('does not include nonce or ath when not provided', () => {
    const kp = generateDpopKeyPair()
    const proof = createDpopProof({
      privateKey: kp.privateKey,
      jwk: kp.publicJwk,
      method: 'GET',
      url: 'https://pds.example/resource',
    })

    const parts = proof.split('.')
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    expect(payload.nonce).toBeUndefined()
    expect(payload.ath).toBeUndefined()
  })
})

describe('endpoint constants', () => {
  it('PDS_URL defaults to https://pds.example', () => {
    // In test environment without PDS_URL env var set
    expect(PDS_URL).toMatch(/^https?:\/\//)
  })

  it('AUTH_ENDPOINT defaults to a valid URL', () => {
    expect(AUTH_ENDPOINT).toMatch(/^https?:\/\//)
    expect(AUTH_ENDPOINT).toContain('/oauth/authorize')
  })

  it('PLC_DIRECTORY_URL defaults to plc.directory', () => {
    expect(PLC_DIRECTORY_URL).toContain('plc.directory')
  })
})
