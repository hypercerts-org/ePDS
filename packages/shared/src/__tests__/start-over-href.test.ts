/**
 * Tests for the shared `resolveStartOverHref` and `sanitiseHttpUrl`
 * helpers — the single source of truth used by both auth-service's
 * `lib/clean-exit.ts` and pds-core's `lib/epds-callback-error.ts`
 * to populate the "Return to sign in" button on their HTML
 * fallbacks.
 *
 * The auth-service / pds-core tests mock `resolveStartOverHref` at
 * the package boundary and trust whatever it returns; the shape
 * tested here (client_uri preference, clientId-origin fallback,
 * scheme sanitisation, null on metadata throw) is the contract
 * that justifies that trust.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const resolveClientMetadataMock = vi.hoisted(() => vi.fn())
vi.mock('../client-metadata.js', () => ({
  resolveClientMetadata: resolveClientMetadataMock,
}))

import { resolveStartOverHref, sanitiseHttpUrl } from '../start-over-href.js'

const CLIENT_ID = 'https://demo.example/client-metadata.json'

const silentLogger = {
  warn: () => {},
  error: () => {},
}

beforeEach(() => {
  resolveClientMetadataMock.mockReset()
})

describe('sanitiseHttpUrl', () => {
  it('returns the canonical URL for an https URL', () => {
    expect(sanitiseHttpUrl('https://demo.example/sign-in')).toBe(
      'https://demo.example/sign-in',
    )
  })

  it('returns the canonical URL for an http URL (dev loops)', () => {
    expect(sanitiseHttpUrl('http://localhost:3002/')).toBe(
      'http://localhost:3002/',
    )
  })

  it('returns null for null', () => {
    expect(sanitiseHttpUrl(null)).toBeNull()
  })

  it('returns null for undefined', () => {
    expect(sanitiseHttpUrl(undefined)).toBeNull()
  })

  it('returns null for empty string', () => {
    expect(sanitiseHttpUrl('')).toBeNull()
  })

  it('returns null for unparseable strings', () => {
    expect(sanitiseHttpUrl('not a url')).toBeNull()
    expect(sanitiseHttpUrl('://broken')).toBeNull()
  })

  it('rejects javascript: scheme', () => {
    // The whole reason this helper exists — escapeHtml does NOT
    // neutralise `javascript:` URLs because they contain no
    // escape-sensitive characters.
    expect(sanitiseHttpUrl('javascript:alert(1)')).toBeNull()
  })

  it('rejects data: scheme', () => {
    expect(
      sanitiseHttpUrl('data:text/html,<script>alert(1)</script>'),
    ).toBeNull()
  })

  it('rejects file: scheme', () => {
    expect(sanitiseHttpUrl('file:///etc/passwd')).toBeNull()
  })

  it('rejects ftp: scheme', () => {
    expect(sanitiseHttpUrl('ftp://demo.example/')).toBeNull()
  })
})

describe('resolveStartOverHref', () => {
  it('returns metadata.client_uri when present and safe', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      client_uri: 'https://demo.example/sign-in',
    })
    const got = await resolveStartOverHref(CLIENT_ID, silentLogger)
    expect(got).toBe('https://demo.example/sign-in')
  })

  it('falls back to the clientId origin when client_uri is absent', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({})
    const got = await resolveStartOverHref(CLIENT_ID, silentLogger)
    // URL.toString() on a bare-origin URL adds a trailing slash.
    expect(got).toBe('https://demo.example/')
  })

  it('falls back to the clientId origin when client_uri is missing entirely', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      client_name: 'Demo',
    })
    const got = await resolveStartOverHref(CLIENT_ID, silentLogger)
    expect(got).toBe('https://demo.example/')
  })

  it('rejects a javascript: client_uri and falls back to clientId origin', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      client_uri: 'javascript:alert(1)',
    })
    const got = await resolveStartOverHref(CLIENT_ID, silentLogger)
    expect(got).toBe('https://demo.example/')
  })

  it('rejects an unparseable client_uri and falls back to clientId origin', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      client_uri: 'not a url',
    })
    const got = await resolveStartOverHref(CLIENT_ID, silentLogger)
    expect(got).toBe('https://demo.example/')
  })

  it('returns null when metadata lookup throws', async () => {
    resolveClientMetadataMock.mockRejectedValueOnce(new Error('network blip'))
    const warns: unknown[][] = []
    const logger = {
      warn: (...a: unknown[]) => warns.push(a),
      error: () => {},
    }
    const got = await resolveStartOverHref(CLIENT_ID, logger)
    expect(got).toBeNull()
    // Failure must be visible in operational logs.
    expect(warns).toHaveLength(1)
  })

  it('returns null when both client_uri and clientId origin are unsafe', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({})
    // Use a non-URL clientId so safeOrigin throws and the fallback
    // sanitises to null. (atproto's upstream wouldn't allow this in
    // production, but defence in depth.)
    const got = await resolveStartOverHref('not-a-url', silentLogger)
    expect(got).toBeNull()
  })
})
