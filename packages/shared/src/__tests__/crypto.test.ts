import { describe, it, expect } from 'vitest'
import {
  generateVerificationToken,
  hashToken,
  timingSafeEqual,
  generateCsrfToken,
  generateRandomHandle,
  signCallback,
  verifyCallback,
  type CallbackParams,
  type VerifyCallbackResult,
} from '../crypto.js'

describe('generateVerificationToken', () => {
  it('returns a token and its hash', () => {
    const { token, tokenHash } = generateVerificationToken()
    expect(token).toBeDefined()
    expect(tokenHash).toBeDefined()
    expect(token).not.toBe(tokenHash)
  })

  it('generates unique tokens each time', () => {
    const a = generateVerificationToken()
    const b = generateVerificationToken()
    expect(a.token).not.toBe(b.token)
    expect(a.tokenHash).not.toBe(b.tokenHash)
  })

  it('hash matches when computed independently', () => {
    const { token, tokenHash } = generateVerificationToken()
    expect(hashToken(token)).toBe(tokenHash)
  })
})

describe('hashToken', () => {
  it('produces consistent SHA-256 hex hashes', () => {
    const hash1 = hashToken('test-token')
    const hash2 = hashToken('test-token')
    expect(hash1).toBe(hash2)
    expect(hash1).toHaveLength(64) // SHA-256 hex = 64 chars
  })

  it('produces different hashes for different inputs', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'))
  })
})

describe('timingSafeEqual', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeEqual('hello', 'hello')).toBe(true)
  })

  it('returns false for different strings', () => {
    expect(timingSafeEqual('hello', 'world')).toBe(false)
  })

  it('returns false for different lengths', () => {
    expect(timingSafeEqual('short', 'longer-string')).toBe(false)
  })
})

describe('generateCsrfToken', () => {
  it('returns a hex string', () => {
    const token = generateCsrfToken()
    expect(token).toMatch(/^[0-9a-f]+$/)
  })

  it('generates unique tokens', () => {
    const a = generateCsrfToken()
    const b = generateCsrfToken()
    expect(a).not.toBe(b)
  })
})

describe('generateRandomHandle', () => {
  it('returns a handle with the given domain', () => {
    const handle = generateRandomHandle('example.com')
    expect(handle).toMatch(/^[a-z0-9]+\.example\.com$/)
  })

  it('generates different handles each time', () => {
    const a = generateRandomHandle('test.com')
    const b = generateRandomHandle('test.com')
    expect(a).not.toBe(b)
  })
})

describe('signCallback / verifyCallback', () => {
  const secret = 'test-secret-32bytes-padding-here'
  const params: CallbackParams = {
    request_uri: 'urn:ietf:params:oauth:request_uri:abc123',
    email: 'user@example.com',
    approved: '1',
    new_account: '0',
  }

  it('produces a hex signature and numeric timestamp string', () => {
    const { sig, ts } = signCallback(params, secret)
    expect(sig).toMatch(/^[0-9a-f]{64}$/) // HMAC-SHA256 hex = 64 chars
    expect(ts).toMatch(/^\d+$/)
  })

  it('round-trips: sign then verify returns valid=true', () => {
    const { sig, ts } = signCallback(params, secret)
    expect(verifyCallback(params, ts, sig, secret).valid).toBe(true)
  })

  it('rejects wrong secret', () => {
    const { sig, ts } = signCallback(params, secret)
    expect(verifyCallback(params, ts, sig, 'wrong-secret').valid).toBe(false)
  })

  it('rejects tampered email', () => {
    const { sig, ts } = signCallback(params, secret)
    const tampered = { ...params, email: 'attacker@evil.com' }
    expect(verifyCallback(tampered, ts, sig, secret).valid).toBe(false)
  })

  it('rejects tampered request_uri', () => {
    const { sig, ts } = signCallback(params, secret)
    const tampered = {
      ...params,
      request_uri: 'urn:ietf:params:oauth:request_uri:evil',
    }
    expect(verifyCallback(tampered, ts, sig, secret).valid).toBe(false)
  })

  it('rejects expired timestamp (>5 min old)', async () => {
    // Set ts to 6 minutes ago
    const staleTs = (Math.floor(Date.now() / 1000) - 6 * 60).toString()
    // Recompute sig with the stale ts so the signature itself is valid
    const payload = [
      params.request_uri,
      params.email,
      params.approved,
      params.new_account,
      '', // handle sentinel (absent)
      staleTs,
    ].join('\n')
    const { createHmac } = await import('node:crypto')
    const staleSig = createHmac('sha256', secret).update(payload).digest('hex')
    expect(verifyCallback(params, staleTs, staleSig, secret).valid).toBe(false)
  })

  it('rejects future timestamp', async () => {
    const futureTs = (Math.floor(Date.now() / 1000) + 60).toString()
    const payload = [
      params.request_uri,
      params.email,
      params.approved,
      params.new_account,
      '', // handle sentinel (absent)
      futureTs,
    ].join('\n')
    const { createHmac } = await import('node:crypto')
    const futureSig = createHmac('sha256', secret).update(payload).digest('hex')
    expect(verifyCallback(params, futureTs, futureSig, secret).valid).toBe(
      false,
    )
  })

  it('rejects non-numeric timestamp', () => {
    const { sig } = signCallback(params, secret)
    expect(verifyCallback(params, 'not-a-number', sig, secret).valid).toBe(
      false,
    )
  })

  it('rejects wrong-length sig', () => {
    const { ts } = signCallback(params, secret)
    expect(verifyCallback(params, ts, 'tooshort', secret).valid).toBe(false)
  })
})

describe('signCallback / verifyCallback with handle', () => {
  it('signs and verifies callback with handle param', () => {
    const secret = 'test-secret'
    const params: CallbackParams = {
      request_uri: 'urn:ietf:params:oauth:request_uri:test',
      email: 'alice@example.com',
      approved: '1',
      new_account: '1',
      handle: 'alice.pds.example.com',
    }
    const { sig, ts } = signCallback(params, secret)
    const result = verifyCallback(params, ts, sig, secret)
    expect(result.valid).toBe(true)
    expect(result.handle).toBe('alice.pds.example.com')
  })

  it('signs and verifies callback WITHOUT handle (backward compat)', () => {
    const secret = 'test-secret'
    const params: CallbackParams = {
      request_uri: 'urn:ietf:params:oauth:request_uri:test',
      email: 'alice@example.com',
      approved: '1',
      new_account: '1',
    }
    const { sig, ts } = signCallback(params, secret)
    const result = verifyCallback(params, ts, sig, secret)
    expect(result.valid).toBe(true)
    expect(result.handle).toBeUndefined()
  })

  it('produces different signatures with vs without handle', () => {
    const secret = 'test-secret'
    const baseParams: CallbackParams = {
      request_uri: 'urn:ietf:params:oauth:request_uri:test',
      email: 'alice@example.com',
      approved: '1',
      new_account: '1',
    }
    const { sig: sig1 } = signCallback(baseParams, secret)
    const { sig: sig2 } = signCallback(
      { ...baseParams, handle: 'alice.pds.example.com' },
      secret,
    )
    expect(sig1).not.toBe(sig2)
  })

  it('rejects tampered handle', () => {
    const secret = 'test-secret'
    const params: CallbackParams = {
      request_uri: 'urn:ietf:params:oauth:request_uri:test',
      email: 'alice@example.com',
      approved: '1',
      new_account: '1',
      handle: 'alice.pds.example.com',
    }
    const { sig, ts } = signCallback(params, secret)
    // Tamper: verify with a different handle than what was signed
    const tamperedParams: CallbackParams = {
      ...params,
      handle: 'evil.pds.example.com',
    }
    const result = verifyCallback(tamperedParams, ts, sig, secret)
    expect(result.valid).toBe(false)
  })
})
