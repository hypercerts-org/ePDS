import { describe, expect, it, vi } from 'vitest'
import {
  createCookieDomainMiddleware,
  DEVICE_COOKIE_NAMES,
  deriveCookieDomain,
  rewriteSetCookie,
  rewriteSetCookieHeader,
} from '../cookie-domain.js'

describe('deriveCookieDomain (HYPER-268)', () => {
  it('returns the PDS hostname when auth is a direct subdomain', () => {
    expect(deriveCookieDomain('auth.pds.example', 'pds.example')).toBe(
      'pds.example',
    )
  })

  it('returns the PDS hostname when auth is a nested subdomain', () => {
    expect(deriveCookieDomain('api.auth.pds.example', 'pds.example')).toBe(
      'pds.example',
    )
  })

  it('returns null when auth and pds are unrelated hosts', () => {
    expect(deriveCookieDomain('auth.other.example', 'pds.example')).toBeNull()
    expect(
      deriveCookieDomain(
        'certified-appauth-service-xxx.up.railway.app',
        'certified-apppds-core-xxx.up.railway.app',
      ),
    ).toBeNull()
  })

  it('returns null when auth and pds are the same host', () => {
    // Same host → no Domain attribute needed, middleware is a no-op.
    expect(deriveCookieDomain('pds.example', 'pds.example')).toBeNull()
  })

  it('returns null when either hostname is empty', () => {
    expect(deriveCookieDomain('', 'pds.example')).toBeNull()
    expect(deriveCookieDomain('auth.pds.example', '')).toBeNull()
    expect(deriveCookieDomain('', '')).toBeNull()
  })

  it('is not fooled by a hostname that contains the PDS name as a substring', () => {
    // "notpds.example" does NOT end with ".pds.example" so it is not
    // a subdomain of pds.example.
    expect(deriveCookieDomain('notpds.example', 'pds.example')).toBeNull()
    // "auth.pds.example.com" has a different TLD — not under pds.example.
    expect(deriveCookieDomain('auth.pds.example.com', 'pds.example')).toBeNull()
  })
})

describe('rewriteSetCookie (HYPER-268)', () => {
  const domain = 'pds.example'

  it('injects Domain= on dev-id cookies', () => {
    const out = rewriteSetCookie(
      'dev-id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax',
      domain,
    )
    expect(out).toBe(
      'dev-id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=pds.example',
    )
  })

  it('injects Domain= on ses-id cookies', () => {
    const out = rewriteSetCookie('ses-id=xyz; Path=/', domain)
    expect(out).toBe('ses-id=xyz; Path=/; Domain=pds.example')
  })

  it('injects Domain= on :hash sidecar cookies', () => {
    expect(rewriteSetCookie('dev-id:hash=deadbeef', domain)).toBe(
      'dev-id:hash=deadbeef; Domain=pds.example',
    )
    expect(rewriteSetCookie('ses-id:hash=deadbeef', domain)).toBe(
      'ses-id:hash=deadbeef; Domain=pds.example',
    )
  })

  it('leaves non-device cookies untouched', () => {
    const otherCookies = [
      'epds_auth_flow=1234; Path=/',
      'csrf-token=xxxx; HttpOnly',
      '_ga=GA1.1.1; Path=/; Domain=.google.com',
      'random=value',
    ]
    for (const c of otherCookies) {
      expect(rewriteSetCookie(c, domain)).toBe(c)
    }
  })

  it('does not double-inject if the cookie already has a Domain attribute', () => {
    const already = 'dev-id=abc; Path=/; Domain=other.example'
    expect(rewriteSetCookie(already, domain)).toBe(already)
  })

  it('is case-insensitive when detecting existing Domain attribute', () => {
    const upper = 'dev-id=abc; Path=/; DOMAIN=other.example'
    expect(rewriteSetCookie(upper, domain)).toBe(upper)
  })

  it('handles malformed cookie (no equals) by passing through', () => {
    expect(rewriteSetCookie('just-a-name', domain)).toBe('just-a-name')
  })

  it('exports the set of device cookie names', () => {
    expect(DEVICE_COOKIE_NAMES.size).toBe(4)
    expect(DEVICE_COOKIE_NAMES.has('dev-id')).toBe(true)
    expect(DEVICE_COOKIE_NAMES.has('ses-id')).toBe(true)
    expect(DEVICE_COOKIE_NAMES.has('dev-id:hash')).toBe(true)
    expect(DEVICE_COOKIE_NAMES.has('ses-id:hash')).toBe(true)
  })
})

describe('rewriteSetCookieHeader (HYPER-268)', () => {
  const domain = 'pds.example'

  it('rewrites a single string value', () => {
    expect(rewriteSetCookieHeader('dev-id=abc; Path=/', domain)).toBe(
      'dev-id=abc; Path=/; Domain=pds.example',
    )
  })

  it('rewrites an array of values, keeping non-device cookies intact', () => {
    const input = [
      'dev-id=abc; Path=/',
      'epds_auth_flow=1234; Path=/',
      'ses-id=xyz; Path=/',
    ]
    const out = rewriteSetCookieHeader(input, domain)
    expect(out).toEqual([
      'dev-id=abc; Path=/; Domain=pds.example',
      'epds_auth_flow=1234; Path=/',
      'ses-id=xyz; Path=/; Domain=pds.example',
    ])
  })

  it('passes through numeric header values untouched', () => {
    // Node's setHeader accepts number for Content-Length etc.; we should
    // never receive one for Set-Cookie but be defensive anyway.
    expect(rewriteSetCookieHeader(42, domain)).toBe(42)
  })

  it('leaves non-string array entries untouched', () => {
    // @ts-expect-error — intentionally passing a number in an array to
    // test the defensive fallback.
    expect(rewriteSetCookieHeader([99, 'dev-id=abc'], domain)).toEqual([
      99,
      'dev-id=abc; Domain=pds.example',
    ])
  })
})

describe('createCookieDomainMiddleware (HYPER-268)', () => {
  function makeRes() {
    const calls: { setHeader: unknown[][]; appendHeader: unknown[][] } = {
      setHeader: [],
      appendHeader: [],
    }
    const res = {
      setHeader: vi.fn((name: string, value: unknown) => {
        calls.setHeader.push([name, value])
      }),
      appendHeader: vi.fn((name: string, value: unknown) => {
        calls.appendHeader.push([name, value])
      }),
    }
    return { res, calls }
  }

  it('calls next() exactly once', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res } = makeRes()
    const next = vi.fn()
    mw({}, res, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('rewrites Set-Cookie via setHeader for device cookies', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.setHeader('Set-Cookie', 'dev-id=abc; Path=/')
    expect(calls.setHeader[0]).toEqual([
      'Set-Cookie',
      'dev-id=abc; Path=/; Domain=pds.example',
    ])
  })

  it('rewrites Set-Cookie via setHeader for an array of cookies', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.setHeader('Set-Cookie', ['dev-id=abc', 'csrf-token=xyz'])
    expect(calls.setHeader[0]).toEqual([
      'Set-Cookie',
      ['dev-id=abc; Domain=pds.example', 'csrf-token=xyz'],
    ])
  })

  it('matches the Set-Cookie header name case-insensitively', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.setHeader('set-cookie', 'dev-id=abc')
    expect(calls.setHeader[0]).toEqual([
      'set-cookie',
      'dev-id=abc; Domain=pds.example',
    ])
  })

  it('does not rewrite non-cookie headers', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.setHeader('Cache-Control', 'no-store')
    expect(calls.setHeader[0]).toEqual(['Cache-Control', 'no-store'])
  })

  it('rewrites Set-Cookie via appendHeader for device cookies', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.appendHeader('Set-Cookie', 'ses-id=xyz; HttpOnly')
    expect(calls.appendHeader[0]).toEqual([
      'Set-Cookie',
      'ses-id=xyz; HttpOnly; Domain=pds.example',
    ])
  })

  it('does not rewrite non-cookie headers via appendHeader', () => {
    const mw = createCookieDomainMiddleware('pds.example')
    const { res, calls } = makeRes()
    mw({}, res, () => {})
    res.appendHeader('Vary', 'Cookie')
    expect(calls.appendHeader[0]).toEqual(['Vary', 'Cookie'])
  })

  it('skips appendHeader wrapping when the response does not expose it', () => {
    // Older Express / test mocks may not have appendHeader at all.
    const mw = createCookieDomainMiddleware('pds.example')
    const setHeader = vi.fn()
    const res = { setHeader }
    const next = vi.fn()
    expect(() => {
      mw({}, res as Parameters<typeof mw>[1], next)
    }).not.toThrow()
    expect(next).toHaveBeenCalledTimes(1)
  })
})
