import { describe, expect, it } from 'vitest'
import {
  appendOrphanDeviceCookieClearHeaders,
  buildPdsAuthorizeRedirect,
  deriveSharedCookieDomain,
  hasDeviceSessionCookie,
  hasOrphanDeviceCookie,
  isForceLoginPrompt,
  readDeviceSessionCookies,
  shouldReuseSession,
  type SessionReuseRequest,
} from '../lib/session-reuse.js'

function makeReq(
  opts: {
    cookies?: Record<string, string>
    cookieHeader?: string
    query?: Record<string, unknown>
  } = {},
): SessionReuseRequest {
  return {
    cookies: opts.cookies,
    headers: { cookie: opts.cookieHeader },
    query: opts.query ?? {},
  }
}

describe('hasDeviceSessionCookie (HYPER-268)', () => {
  it('returns true only when BOTH dev-id and ses-id are present in the cookie bag', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookies: { 'dev-id': 'abc', 'ses-id': 'xyz' } }),
      ),
    ).toBe(true)
  })

  it('returns true when both cookies are present in the raw Cookie header', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookieHeader: 'dev-id=xyz; ses-id=abc' }),
      ),
    ).toBe(true)
  })

  it('returns true when the pair is not the first set of cookies', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({
          cookieHeader: 'foo=1; dev-id=xyz; bar=2; ses-id=abc; baz=3',
        }),
      ),
    ).toBe(true)
  })

  it('returns false when only dev-id is present (half-pair)', () => {
    // Half-pair is the Layer 1 regression scenario: upstream's
    // DeviceManager can't hydrate a session from it and would render
    // the stock welcome page if we redirected upstream.
    expect(
      hasDeviceSessionCookie(makeReq({ cookies: { 'dev-id': 'abc' } })),
    ).toBe(false)
    expect(
      hasDeviceSessionCookie(makeReq({ cookieHeader: 'dev-id=xyz' })),
    ).toBe(false)
  })

  it('returns false when only ses-id is present (half-pair)', () => {
    expect(
      hasDeviceSessionCookie(makeReq({ cookies: { 'ses-id': 'xyz' } })),
    ).toBe(false)
    expect(
      hasDeviceSessionCookie(makeReq({ cookieHeader: 'ses-id=abc' })),
    ).toBe(false)
  })

  it('returns false when no cookies are present', () => {
    expect(hasDeviceSessionCookie(makeReq())).toBe(false)
  })

  it('returns false when the cookie header only has unrelated cookies', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookieHeader: 'csrf=1; epds_auth_flow=2' }),
      ),
    ).toBe(false)
  })

  it('is not fooled by substring matches in other cookie names', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookieHeader: 'not-dev-id=abc; not-ses-id=xyz' }),
      ),
    ).toBe(false)
  })

  it('prefers the parsed cookie bag over the raw header', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({
          cookies: { 'dev-id': 'abc', 'ses-id': 'xyz' },
          cookieHeader: 'nothing-here=1',
        }),
      ),
    ).toBe(true)
  })

  it('accepts pair across bag + raw header (one source each)', () => {
    // Guarding against a regression where either source alone had to
    // carry both cookies. As long as dev-id and ses-id are BOTH visible
    // via any source, we treat the device session as usable.
    expect(
      hasDeviceSessionCookie(
        makeReq({
          cookies: { 'dev-id': 'abc' },
          cookieHeader: 'ses-id=xyz',
        }),
      ),
    ).toBe(true)
  })
})

describe('hasOrphanDeviceCookie (HYPER-268)', () => {
  it('reports neither cookie present for a fresh visitor', () => {
    const r = hasOrphanDeviceCookie(makeReq())
    expect(r).toEqual({ devId: false, sesId: false, isOrphan: false })
  })

  it('reports both cookies present and no orphan when the pair is complete', () => {
    const r = hasOrphanDeviceCookie(
      makeReq({ cookies: { 'dev-id': 'a', 'ses-id': 'b' } }),
    )
    expect(r).toEqual({ devId: true, sesId: true, isOrphan: false })
  })

  it('reports orphan when only dev-id is present', () => {
    const r = hasOrphanDeviceCookie(makeReq({ cookies: { 'dev-id': 'a' } }))
    expect(r).toEqual({ devId: true, sesId: false, isOrphan: true })
  })

  it('reports orphan when only ses-id is present', () => {
    const r = hasOrphanDeviceCookie(makeReq({ cookies: { 'ses-id': 'b' } }))
    expect(r).toEqual({ devId: false, sesId: true, isOrphan: true })
  })

  it('falls back to the raw header when the cookie bag is absent', () => {
    expect(
      hasOrphanDeviceCookie(makeReq({ cookieHeader: 'dev-id=a' })),
    ).toEqual({
      devId: true,
      sesId: false,
      isOrphan: true,
    })
    expect(
      hasOrphanDeviceCookie(makeReq({ cookieHeader: 'ses-id=b' })),
    ).toEqual({
      devId: false,
      sesId: true,
      isOrphan: true,
    })
  })
})

describe('isForceLoginPrompt (HYPER-268)', () => {
  it('returns true when prompt=login', () => {
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'login' } }))).toBe(
      true,
    )
  })

  it('returns false for other prompt values', () => {
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'none' } }))).toBe(
      false,
    )
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'consent' } }))).toBe(
      false,
    )
  })

  it('returns false when prompt is absent', () => {
    expect(isForceLoginPrompt(makeReq())).toBe(false)
  })

  // OIDC Core 1.0 §3.1.2.1: `prompt` is a space-delimited list. The
  // single-token cases above must continue to work, AND multi-token /
  // repeated-key forms that include `login` must also be honoured —
  // otherwise a client passing `prompt=login consent` (or two `prompt=`
  // query keys) would re-trigger #138 even after the per-step gate
  // landed.
  it('returns true when prompt is a space-delimited list containing login', () => {
    expect(
      isForceLoginPrompt(makeReq({ query: { prompt: 'login consent' } })),
    ).toBe(true)
    expect(
      isForceLoginPrompt(makeReq({ query: { prompt: 'consent login' } })),
    ).toBe(true)
  })

  it('returns true when prompt is an array containing login', () => {
    // Express's req.query parser surfaces repeated query keys as arrays:
    // `?prompt=login&prompt=consent` becomes `['login', 'consent']`.
    expect(isForceLoginPrompt(makeReq({ query: { prompt: ['login'] } }))).toBe(
      true,
    )
    expect(
      isForceLoginPrompt(makeReq({ query: { prompt: ['consent', 'login'] } })),
    ).toBe(true)
  })

  it('returns false when prompt is a list of other tokens', () => {
    expect(
      isForceLoginPrompt(makeReq({ query: { prompt: 'consent none' } })),
    ).toBe(false)
    expect(
      isForceLoginPrompt(makeReq({ query: { prompt: ['consent', 'none'] } })),
    ).toBe(false)
  })
})

describe('shouldReuseSession (HYPER-268)', () => {
  it('returns true when the full dev-id/ses-id pair is present and prompt is absent', () => {
    expect(
      shouldReuseSession(
        makeReq({ cookies: { 'dev-id': 'a', 'ses-id': 'b' } }),
      ),
    ).toBe(true)
  })

  it('returns false when only dev-id is present (half-pair)', () => {
    expect(shouldReuseSession(makeReq({ cookies: { 'dev-id': 'a' } }))).toBe(
      false,
    )
  })

  it('returns false when only ses-id is present (half-pair)', () => {
    expect(shouldReuseSession(makeReq({ cookies: { 'ses-id': 'b' } }))).toBe(
      false,
    )
  })

  it('returns false when the full pair is present but prompt=login', () => {
    expect(
      shouldReuseSession(
        makeReq({
          cookies: { 'dev-id': 'a', 'ses-id': 'b' },
          query: { prompt: 'login' },
        }),
      ),
    ).toBe(false)
  })

  it('returns false when no cookies are present', () => {
    expect(shouldReuseSession(makeReq())).toBe(false)
  })
})

describe('shouldReuseSession with login_hint context (Flow 1)', () => {
  const cookies = { 'dev-id': 'a', 'ses-id': 'b' }

  it('returns true when the hinted email matches a device-bound email', () => {
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'alice@example.com',
        deviceBoundEmails: ['alice@example.com', 'bob@example.com'],
      }),
    ).toBe(true)
  })

  it('returns true when the hinted email matches case-insensitively', () => {
    // resolveLoginHint may return mixed-case emails; the bindings list is
    // lowercased upstream, so the comparison must lowercase the hint too.
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'Alice@Example.COM',
        deviceBoundEmails: ['alice@example.com'],
      }),
    ).toBe(true)
  })

  it('returns false when the hinted email is not in the bindings', () => {
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'carol@example.com',
        deviceBoundEmails: ['alice@example.com', 'bob@example.com'],
      }),
    ).toBe(false)
  })

  it('returns false when bindings list is empty (device has no bound accounts)', () => {
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'alice@example.com',
        deviceBoundEmails: [],
      }),
    ).toBe(false)
  })

  it('returns false when bindings is null (cookie pair stale or unknown)', () => {
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'alice@example.com',
        deviceBoundEmails: null,
      }),
    ).toBe(false)
  })

  it('falls back to cookie-only logic when no hint is supplied', () => {
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: null,
        deviceBoundEmails: ['alice@example.com'],
      }),
    ).toBe(true)
  })

  it('preserves legacy cookie-only behaviour when caller omits bindings', () => {
    // A hint without a bindings field means the caller hasn't opted into
    // the Flow 1 gate; we must not silently disable session reuse.
    expect(
      shouldReuseSession(makeReq({ cookies }), {
        resolvedEmail: 'alice@example.com',
      }),
    ).toBe(true)
  })

  it('honours prompt=login over any hint match', () => {
    expect(
      shouldReuseSession(makeReq({ cookies, query: { prompt: 'login' } }), {
        resolvedEmail: 'alice@example.com',
        deviceBoundEmails: ['alice@example.com'],
      }),
    ).toBe(false)
  })

  it('returns false when cookies are missing irrespective of hint', () => {
    expect(
      shouldReuseSession(makeReq(), {
        resolvedEmail: 'alice@example.com',
        deviceBoundEmails: ['alice@example.com'],
      }),
    ).toBe(false)
  })
})

describe('readDeviceSessionCookies', () => {
  it('returns parsed values from the cookie bag', () => {
    const got = readDeviceSessionCookies(
      makeReq({ cookies: { 'dev-id': 'dev-x', 'ses-id': 'ses-y' } }),
    )
    expect(got).toEqual({ devId: 'dev-x', sesId: 'ses-y' })
  })

  it('falls back to the raw Cookie header', () => {
    const got = readDeviceSessionCookies(
      makeReq({ cookieHeader: 'foo=1; dev-id=dev-x; ses-id=ses-y; bar=2' }),
    )
    expect(got).toEqual({ devId: 'dev-x', sesId: 'ses-y' })
  })

  it('decodes percent-encoded values', () => {
    const got = readDeviceSessionCookies(
      makeReq({ cookieHeader: 'dev-id=dev%2Dx; ses-id=ses%2Dy' }),
    )
    expect(got).toEqual({ devId: 'dev-x', sesId: 'ses-y' })
  })

  it('returns null on a malformed percent-escape', () => {
    expect(
      readDeviceSessionCookies(
        makeReq({ cookieHeader: 'dev-id=%GG; ses-id=ok' }),
      ),
    ).toBeNull()
  })

  it('returns null when only one cookie is present', () => {
    expect(
      readDeviceSessionCookies(makeReq({ cookies: { 'dev-id': 'x' } })),
    ).toBeNull()
    expect(
      readDeviceSessionCookies(makeReq({ cookies: { 'ses-id': 'y' } })),
    ).toBeNull()
  })

  it('returns null when neither cookie is present', () => {
    expect(readDeviceSessionCookies(makeReq())).toBeNull()
  })
})

describe('deriveSharedCookieDomain (HYPER-268)', () => {
  it('returns the parent for a direct subdomain', () => {
    expect(deriveSharedCookieDomain('auth.pds.example', 'pds.example')).toBe(
      'pds.example',
    )
  })

  it('returns the parent for a nested subdomain', () => {
    expect(
      deriveSharedCookieDomain('api.auth.pds.example', 'pds.example'),
    ).toBe('pds.example')
  })

  it('returns null when the hosts are unrelated', () => {
    expect(
      deriveSharedCookieDomain('auth.other.example', 'pds.example'),
    ).toBeNull()
  })

  it('returns null when the hosts are identical', () => {
    expect(deriveSharedCookieDomain('pds.example', 'pds.example')).toBeNull()
  })

  it('returns null for empty inputs', () => {
    expect(deriveSharedCookieDomain('', 'pds.example')).toBeNull()
    expect(deriveSharedCookieDomain('auth.pds.example', '')).toBeNull()
  })

  it('rejects suffix-only matches (not a real subdomain)', () => {
    // "notpds.example" ends with "pds.example" but is not a
    // subdomain of "pds.example" — only the ".<parent>" boundary counts.
    expect(deriveSharedCookieDomain('notpds.example', 'pds.example')).toBeNull()
  })
})

function makeRes(): {
  append: (n: string, v: string) => void
  calls: Array<[string, string]>
} {
  const calls: Array<[string, string]> = []
  return {
    calls,
    append(name: string, value: string) {
      calls.push([name, value])
    },
  }
}

describe('appendOrphanDeviceCookieClearHeaders', () => {
  it('emits host-only clears only when cookieDomain is null', () => {
    const res = makeRes()
    appendOrphanDeviceCookieClearHeaders(res, null)
    expect(res.calls).toEqual([
      ['Set-Cookie', 'dev-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'dev-id:hash=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id:hash=; Max-Age=0; Path=/'],
    ])
  })

  it('emits both host-only and domain-scoped clears when a cookieDomain is given', () => {
    const res = makeRes()
    appendOrphanDeviceCookieClearHeaders(res, 'pds.example')
    expect(res.calls).toEqual([
      ['Set-Cookie', 'dev-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'dev-id=; Max-Age=0; Path=/; Domain=pds.example'],
      ['Set-Cookie', 'dev-id:hash=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'dev-id:hash=; Max-Age=0; Path=/; Domain=pds.example'],
      ['Set-Cookie', 'ses-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id=; Max-Age=0; Path=/; Domain=pds.example'],
      ['Set-Cookie', 'ses-id:hash=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id:hash=; Max-Age=0; Path=/; Domain=pds.example'],
    ])
  })
})

describe('buildPdsAuthorizeRedirect', () => {
  const pds = 'https://pds.example'

  it('preserves a simple query string', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      request_uri: 'urn:x:1',
      client_id: 'https://trusted.example/client',
    })
    const parsed = new URL(url)
    expect(parsed.origin + parsed.pathname).toBe(
      'https://pds.example/oauth/authorize',
    )
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
    expect(parsed.searchParams.get('client_id')).toBe(
      'https://trusted.example/client',
    )
  })

  it('preserves repeated query parameters via array values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      scope: ['atproto', 'transition:generic'],
    })
    const parsed = new URL(url)
    expect(parsed.searchParams.getAll('scope')).toEqual([
      'atproto',
      'transition:generic',
    ])
  })

  it('skips non-string query values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      request_uri: 'urn:x:1',
      bogus: undefined,
      numeric: 42,
    })
    const parsed = new URL(url)
    expect(parsed.searchParams.has('bogus')).toBe(false)
    expect(parsed.searchParams.has('numeric')).toBe(false)
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
  })

  it('url-encodes special characters in values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      redirect_uri: 'https://app.example/cb?foo=bar&baz=1',
    })
    expect(url).toContain('redirect_uri=https%3A%2F%2Fapp.example%2Fcb')
  })
})
