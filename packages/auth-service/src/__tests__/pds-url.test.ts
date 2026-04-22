/**
 * Tests for ensurePdsUrl() and requireInternalEnv().
 *
 * Both are pure startup-validation helpers — no I/O, no mocks needed
 * beyond temporarily mutating process.env.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { ensurePdsUrl } from '../lib/pds-url.js'
import { requireInternalEnv } from '../lib/require-internal-env.js'

// ---------------------------------------------------------------------------
// ensurePdsUrl
// ---------------------------------------------------------------------------

describe('ensurePdsUrl', () => {
  describe('valid URLs', () => {
    it('accepts http:// URL', () => {
      expect(ensurePdsUrl('http://example.com')).toBe('http://example.com')
    })

    it('accepts https:// URL', () => {
      expect(ensurePdsUrl('https://example.com')).toBe('https://example.com')
    })

    it('accepts HTTPS:// with uppercase scheme', () => {
      expect(ensurePdsUrl('HTTPS://example.com')).toBe('HTTPS://example.com')
    })

    it('strips a single trailing slash', () => {
      expect(ensurePdsUrl('https://example.com/')).toBe('https://example.com')
    })

    it('strips multiple trailing slashes', () => {
      expect(ensurePdsUrl('https://example.com///')).toBe('https://example.com')
    })

    it('preserves path segments that are not trailing slashes', () => {
      expect(ensurePdsUrl('https://example.com/foo/bar')).toBe(
        'https://example.com/foo/bar',
      )
    })
  })

  describe('fallback', () => {
    it('uses fallback when raw is undefined', () => {
      expect(ensurePdsUrl(undefined, 'https://fallback.com')).toBe(
        'https://fallback.com',
      )
    })

    it('uses fallback when raw is empty string', () => {
      expect(ensurePdsUrl('', 'https://fallback.com')).toBe(
        'https://fallback.com',
      )
    })

    it('prefers raw over fallback when raw is valid', () => {
      expect(ensurePdsUrl('https://primary.com', 'https://fallback.com')).toBe(
        'https://primary.com',
      )
    })
  })

  describe('missing URL', () => {
    it('throws when raw is undefined and no fallback given', () => {
      expect(() => ensurePdsUrl(undefined)).toThrow(
        'PDS_INTERNAL_URL is not set and no fallback URL was provided',
      )
    })

    it('throws when raw is empty string and no fallback given', () => {
      expect(() => ensurePdsUrl('')).toThrow(
        'PDS_INTERNAL_URL is not set and no fallback URL was provided',
      )
    })
  })

  describe('missing scheme', () => {
    it('throws for bare hostname', () => {
      expect(() => ensurePdsUrl('core.railway.internal')).toThrow(
        'PDS_INTERNAL_URL is missing the http:// or https:// scheme: "core.railway.internal"',
      )
    })

    it('throws for hostname with path but no scheme', () => {
      expect(() => ensurePdsUrl('example.com/foo')).toThrow(
        'PDS_INTERNAL_URL is missing the http:// or https:// scheme',
      )
    })

    it('throws for ftp:// scheme', () => {
      expect(() => ensurePdsUrl('ftp://example.com')).toThrow(
        'PDS_INTERNAL_URL is missing the http:// or https:// scheme',
      )
    })

    it('throws when fallback also lacks a scheme', () => {
      expect(() => ensurePdsUrl(undefined, 'core.railway.internal')).toThrow(
        'PDS_INTERNAL_URL is missing the http:// or https:// scheme',
      )
    })
  })
})

// ---------------------------------------------------------------------------
// requireInternalEnv
// ---------------------------------------------------------------------------

describe('requireInternalEnv', () => {
  const ORIGINAL_ENV = process.env

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV }
  })

  function setEnv(vars: Record<string, string | undefined>) {
    process.env = { ...ORIGINAL_ENV, ...vars }
  }

  it('returns pdsUrl and internalSecret when both are valid', () => {
    setEnv({
      PDS_INTERNAL_URL: 'https://core.internal',
      EPDS_INTERNAL_SECRET: 'secret123',
    })
    expect(requireInternalEnv()).toEqual({
      pdsUrl: 'https://core.internal',
      internalSecret: 'secret123',
    })
  })

  it('strips trailing slash from PDS_INTERNAL_URL', () => {
    setEnv({
      PDS_INTERNAL_URL: 'https://core.internal/',
      EPDS_INTERNAL_SECRET: 'secret123',
    })
    expect(requireInternalEnv().pdsUrl).toBe('https://core.internal')
  })

  it('throws when EPDS_INTERNAL_SECRET is missing', () => {
    setEnv({
      PDS_INTERNAL_URL: 'https://core.internal',
      EPDS_INTERNAL_SECRET: undefined,
    })
    expect(() => requireInternalEnv()).toThrow(
      'EPDS_INTERNAL_SECRET must be set',
    )
  })

  it('throws when PDS_INTERNAL_URL is missing', () => {
    setEnv({
      PDS_INTERNAL_URL: undefined,
      EPDS_INTERNAL_SECRET: 'secret123',
    })
    expect(() => requireInternalEnv()).toThrow(
      'PDS_INTERNAL_URL is not set and no fallback URL was provided',
    )
  })

  it('throws when PDS_INTERNAL_URL lacks a scheme', () => {
    setEnv({
      PDS_INTERNAL_URL: 'core.railway.internal',
      EPDS_INTERNAL_SECRET: 'secret123',
    })
    expect(() => requireInternalEnv()).toThrow(
      'PDS_INTERNAL_URL is missing the http:// or https:// scheme: "core.railway.internal"',
    )
  })
})
