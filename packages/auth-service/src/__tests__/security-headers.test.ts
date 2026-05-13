import { describe, expect, it, vi } from 'vitest'
import {
  buildAuthServiceCsp,
  buildImgSrcDirective,
  createSecurityHeadersMiddleware,
  extractClientIdFromRequest,
  resolveClientIdForCsp,
} from '../lib/security-headers.js'

describe('buildImgSrcDirective', () => {
  it('returns the baseline when no client_id is supplied', () => {
    expect(buildImgSrcDirective()).toBe("'self' data:")
    expect(buildImgSrcDirective(null)).toBe("'self' data:")
    expect(buildImgSrcDirective(undefined)).toBe("'self' data:")
    expect(buildImgSrcDirective('')).toBe("'self' data:")
  })

  it('appends the client origin when client_id is a valid URL', () => {
    expect(
      buildImgSrcDirective('https://app.example.com/client-metadata.json'),
    ).toBe("'self' data: https://app.example.com")
  })

  it('returns the baseline when client_id is not a valid URL', () => {
    expect(buildImgSrcDirective('not a url')).toBe("'self' data:")
  })

  it('returns the baseline when the parsed URL has a null origin', () => {
    // Some URL schemes (e.g. data: URIs, file: URIs) yield 'null' origin.
    expect(buildImgSrcDirective('data:text/plain,foo')).toBe("'self' data:")
  })

  it('coerces non-string client_id to baseline', () => {
    // Caller may pass anything; defensive guard returns baseline.
    // @ts-expect-error — testing the runtime guard against non-string input
    expect(buildImgSrcDirective(42)).toBe("'self' data:")
  })
})

describe('buildAuthServiceCsp', () => {
  it('builds a complete CSP with the dynamic img-src baked in', () => {
    expect(buildAuthServiceCsp()).toBe(
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    )
  })

  it('widens img-src when a client_id is provided', () => {
    const csp = buildAuthServiceCsp('https://app.example.com/cm.json')
    expect(csp).toContain("img-src 'self' data: https://app.example.com")
    // Other directives stay intact.
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("script-src 'self' 'unsafe-inline'")
    expect(csp).toContain("style-src 'self' 'unsafe-inline'")
    expect(csp).toContain("connect-src 'self'")
  })
})

describe('extractClientIdFromRequest', () => {
  it('reads client_id from query string', () => {
    expect(
      extractClientIdFromRequest({
        query: { client_id: 'https://app.example/cm.json' },
      }),
    ).toBe('https://app.example/cm.json')
  })

  it('reads client_id from request body when query is empty', () => {
    expect(
      extractClientIdFromRequest({
        query: {},
        body: { client_id: 'https://other.example/cm.json' },
      }),
    ).toBe('https://other.example/cm.json')
  })

  it('prefers query over body', () => {
    expect(
      extractClientIdFromRequest({
        query: { client_id: 'https://from-query.example/cm.json' },
        body: { client_id: 'https://from-body.example/cm.json' },
      }),
    ).toBe('https://from-query.example/cm.json')
  })

  it('returns null when client_id is missing entirely', () => {
    expect(extractClientIdFromRequest({ query: {} })).toBeNull()
    expect(
      extractClientIdFromRequest({ query: {}, body: undefined }),
    ).toBeNull()
    expect(extractClientIdFromRequest({ query: {}, body: null })).toBeNull()
  })

  it('returns null when client_id is not a string', () => {
    expect(
      extractClientIdFromRequest({ query: { client_id: ['x'] } }),
    ).toBeNull()
    expect(
      extractClientIdFromRequest({ query: {}, body: { client_id: 42 } }),
    ).toBeNull()
  })
})

describe('createSecurityHeadersMiddleware', () => {
  function makeRes() {
    const calls: Array<[string, string]> = []
    const res = {
      setHeader: vi.fn((name: string, value: string) => {
        calls.push([name, value])
      }),
    }
    return { res, calls }
  }

  it('sets the standard hardening headers', () => {
    const mw = createSecurityHeadersMiddleware()
    const { res, calls } = makeRes()
    mw({ query: {} }, res, () => {})
    const names = calls.map(([n]) => n)
    expect(names).toContain('X-Frame-Options')
    expect(names).toContain('X-Content-Type-Options')
    expect(names).toContain('Referrer-Policy')
    expect(names).toContain('Content-Security-Policy')
    expect(names).toContain('Strict-Transport-Security')
  })

  it('sets the dynamic CSP based on client_id from query', () => {
    const mw = createSecurityHeadersMiddleware()
    const { res, calls } = makeRes()
    mw(
      { query: { client_id: 'https://app.example.com/cm.json' } },
      res,
      () => {},
    )
    const csp = calls.find(([name]) => name === 'Content-Security-Policy')?.[1]
    expect(csp).toContain("img-src 'self' data: https://app.example.com")
  })

  it('sets the baseline CSP when no client_id is supplied', () => {
    const mw = createSecurityHeadersMiddleware()
    const { res, calls } = makeRes()
    mw({ query: {} }, res, () => {})
    const csp = calls.find(([name]) => name === 'Content-Security-Policy')?.[1]
    expect(csp).toContain("img-src 'self' data:")
    expect(csp).not.toContain('https://')
  })

  it('calls next() exactly once', () => {
    const mw = createSecurityHeadersMiddleware()
    const { res } = makeRes()
    const next = vi.fn()
    mw({ query: {} }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('falls back to authFlowLookup when client_id is absent', () => {
    const mw = createSecurityHeadersMiddleware({
      authFlowLookup: (uri) =>
        uri === 'urn:req:abc' ? 'https://app.example.com/cm.json' : null,
    })
    const { res, calls } = makeRes()
    mw({ query: { request_uri: 'urn:req:abc' } }, res, () => {})
    const csp = calls.find(([name]) => name === 'Content-Security-Policy')?.[1]
    expect(csp).toContain("img-src 'self' data: https://app.example.com")
  })

  it('prefers direct client_id over authFlowLookup', () => {
    const lookup = vi.fn(() => 'https://from-lookup.example/cm.json')
    const mw = createSecurityHeadersMiddleware({ authFlowLookup: lookup })
    const { res, calls } = makeRes()
    mw(
      {
        query: {
          client_id: 'https://from-query.example/cm.json',
          request_uri: 'urn:req:abc',
        },
      },
      res,
      () => {},
    )
    const csp = calls.find(([name]) => name === 'Content-Security-Policy')?.[1]
    expect(csp).toContain("img-src 'self' data: https://from-query.example")
    expect(lookup).not.toHaveBeenCalled()
  })
})

describe('resolveClientIdForCsp', () => {
  it('returns the direct client_id when present', () => {
    expect(
      resolveClientIdForCsp({ query: { client_id: 'https://a.example/cm' } }),
    ).toBe('https://a.example/cm')
  })

  it('returns null when no client_id and no lookup', () => {
    expect(
      resolveClientIdForCsp({ query: { request_uri: 'urn:req:abc' } }),
    ).toBeNull()
  })

  it('consults lookup when only request_uri is present', () => {
    expect(
      resolveClientIdForCsp({ query: { request_uri: 'urn:req:abc' } }, (uri) =>
        uri === 'urn:req:abc' ? 'https://b.example/cm' : null,
      ),
    ).toBe('https://b.example/cm')
  })

  it('returns null when request_uri is not a string', () => {
    const lookup = vi.fn(() => 'https://b.example/cm')
    expect(
      resolveClientIdForCsp({ query: { request_uri: ['x'] } }, lookup),
    ).toBeNull()
    expect(lookup).not.toHaveBeenCalled()
  })

  it('returns null when lookup returns null', () => {
    expect(
      resolveClientIdForCsp(
        { query: { request_uri: 'urn:req:abc' } },
        () => null,
      ),
    ).toBeNull()
  })
})
