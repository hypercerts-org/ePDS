import type { Request, Response } from 'express'
import { describe, expect, it, vi } from 'vitest'
import {
  appendCookieClearHeaders,
  buildBounceUrl,
  createAuthUiGuard,
  isGuardedPath,
  parseDeviceCookies,
  parsePromptTokens,
  promptHasLogin,
} from '../auth-ui-guard.js'

const VALID_DEV = 'dev-0123456789abcdef0123456789abcdef'
const VALID_SES = 'ses-fedcba9876543210fedcba9876543210'

describe('isGuardedPath', () => {
  it('matches /oauth/authorize exactly', () => {
    expect(isGuardedPath('/oauth/authorize')).toBe(true)
  })

  it('matches /account and its subpaths', () => {
    expect(isGuardedPath('/account')).toBe(true)
    expect(isGuardedPath('/account/')).toBe(true)
    expect(isGuardedPath('/account/settings')).toBe(true)
    expect(isGuardedPath('/account/reset-password')).toBe(true)
  })

  it('does not match unrelated paths', () => {
    expect(isGuardedPath('/')).toBe(false)
    expect(isGuardedPath('/oauth/token')).toBe(false)
    expect(isGuardedPath('/accounts')).toBe(false)
    expect(isGuardedPath('/oauth/authorize/accept')).toBe(false)
  })
})

describe('parseDeviceCookies', () => {
  it('returns both ids when both cookies are valid', () => {
    expect(
      parseDeviceCookies(`dev-id=${VALID_DEV}; ses-id=${VALID_SES}`),
    ).toEqual({ deviceId: VALID_DEV, sessionId: VALID_SES })
  })

  it('returns null when the Cookie header is missing', () => {
    expect(parseDeviceCookies(undefined)).toBeNull()
    expect(parseDeviceCookies('')).toBeNull()
  })

  it('returns null when only dev-id is present', () => {
    expect(parseDeviceCookies(`dev-id=${VALID_DEV}`)).toBeNull()
  })

  it('returns null when only ses-id is present', () => {
    expect(parseDeviceCookies(`ses-id=${VALID_SES}`)).toBeNull()
  })

  it('returns null when dev-id fails the schema (bad prefix)', () => {
    expect(
      parseDeviceCookies(
        `dev-id=xxx-${VALID_DEV.slice(4)}; ses-id=${VALID_SES}`,
      ),
    ).toBeNull()
  })

  it('returns null when dev-id fails the schema (wrong length)', () => {
    expect(
      parseDeviceCookies(`dev-id=dev-short; ses-id=${VALID_SES}`),
    ).toBeNull()
  })

  it('returns null when ses-id fails the schema', () => {
    expect(parseDeviceCookies(`dev-id=${VALID_DEV}; ses-id=bogus`)).toBeNull()
  })

  it('ignores unrelated cookies', () => {
    expect(
      parseDeviceCookies(
        `csrf=abc; dev-id=${VALID_DEV}; junk=1; ses-id=${VALID_SES}`,
      ),
    ).toEqual({ deviceId: VALID_DEV, sessionId: VALID_SES })
  })

  it('uses the first occurrence of a repeated cookie name', () => {
    const other = 'dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    expect(
      parseDeviceCookies(
        `dev-id=${VALID_DEV}; dev-id=${other}; ses-id=${VALID_SES}`,
      ),
    ).toEqual({ deviceId: VALID_DEV, sessionId: VALID_SES })
  })

  it('survives a sibling cookie with a malformed percent-escape', () => {
    // Analytics SDKs (or any app on the shared parent domain) are free
    // to set cookies with literal `%` characters. An unguarded
    // decodeURIComponent would throw URIError and crash the guard for
    // every request. The valid dev-id/ses-id pair must still parse.
    expect(
      parseDeviceCookies(
        `tracking=%GG; dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      ),
    ).toEqual({ deviceId: VALID_DEV, sessionId: VALID_SES })
  })

  it('returns null when the dev-id cookie itself has a malformed percent-escape', () => {
    expect(parseDeviceCookies(`dev-id=%GG; ses-id=${VALID_SES}`)).toBeNull()
  })
})

describe('buildBounceUrl', () => {
  it('preserves the original query string and appends prompt=login', () => {
    const url = buildBounceUrl(
      'auth.pds.example',
      '/oauth/authorize?request_uri=urn:x:1&client_id=https://c.example/m.json',
    )
    const parsed = new URL(url)
    expect(parsed.origin + parsed.pathname).toBe(
      'https://auth.pds.example/oauth/authorize',
    )
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
    expect(parsed.searchParams.get('client_id')).toBe(
      'https://c.example/m.json',
    )
    expect(parsed.searchParams.get('prompt')).toBe('login')
  })

  it('uses http for localhost hosts', () => {
    expect(buildBounceUrl('auth.localhost', '/oauth/authorize')).toContain(
      'http://auth.localhost/',
    )
    expect(buildBounceUrl('localhost', '/oauth/authorize')).toContain(
      'http://localhost/',
    )
  })

  it('uses https for real hostnames', () => {
    expect(buildBounceUrl('auth.pds.example', '/oauth/authorize')).toContain(
      'https://auth.pds.example/',
    )
  })

  it('overrides any existing prompt param with login', () => {
    const url = buildBounceUrl(
      'auth.pds.example',
      '/oauth/authorize?prompt=consent&request_uri=urn:x:1',
    )
    expect(new URL(url).searchParams.get('prompt')).toBe('login')
  })

  it('preserves repeated query params verbatim', () => {
    // OAuth scope commonly appears as scope=atproto&scope=transition:generic.
    // A forEach+set() copy would collapse it to the last value; we need both.
    const url = buildBounceUrl(
      'auth.pds.example',
      '/oauth/authorize?scope=atproto&scope=transition:generic&request_uri=urn:x:1',
    )
    const parsed = new URL(url)
    expect(parsed.searchParams.getAll('scope')).toEqual([
      'atproto',
      'transition:generic',
    ])
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
    expect(parsed.searchParams.get('prompt')).toBe('login')
  })

  it("falls back to prompt=login alone when origUrl can't be parsed", () => {
    // Node's URL parser is forgiving but not bulletproof — e.g. a bare
    // `//` throws ERR_INVALID_URL (empty authority). Without the guard
    // this used to 500 the request; the bounce must still succeed with
    // just prompt=login and let auth-service render its own error.
    const url = buildBounceUrl('auth.pds.example', '//')
    const parsed = new URL(url)
    expect(parsed.origin + parsed.pathname).toBe(
      'https://auth.pds.example/oauth/authorize',
    )
    expect(parsed.searchParams.get('prompt')).toBe('login')
    expect(parsed.searchParams.has('request_uri')).toBe(false)
  })
})

function makeResStub(): Response & { _calls: string[][] } {
  const calls: string[][] = []
  const res = {
    _calls: calls,
    append(name: string, value: string) {
      calls.push([name, value])
      return this
    },
    status(_: number) {
      return this
    },
    setHeader() {
      return this
    },
    end() {
      return this
    },
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- stub typing
  return res as any
}

describe('parsePromptTokens', () => {
  it('returns an empty Set for non-string input', () => {
    expect(parsePromptTokens(undefined).size).toBe(0)
    expect(parsePromptTokens(null).size).toBe(0)
    expect(parsePromptTokens(123).size).toBe(0)
    expect(parsePromptTokens({}).size).toBe(0)
  })

  it('returns an empty Set for an empty / whitespace-only string', () => {
    expect(parsePromptTokens('').size).toBe(0)
    expect(parsePromptTokens('   ').size).toBe(0)
  })

  it('splits a single-token value', () => {
    expect([...parsePromptTokens('login')]).toEqual(['login'])
  })

  it('splits a space-delimited multi-token value', () => {
    // Per OIDC Core 1.0 §3.1.2.1, prompt is space-delimited. The order of
    // tokens within a Set is insertion order, so an array roundtrip is
    // stable.
    expect([...parsePromptTokens('login consent')]).toEqual([
      'login',
      'consent',
    ])
  })

  it('collapses repeated whitespace and ignores empty segments', () => {
    expect([...parsePromptTokens('  login   consent  ')]).toEqual([
      'login',
      'consent',
    ])
  })
})

describe('promptHasLogin', () => {
  it('is false for absent / non-string / unrelated prompt values', () => {
    expect(promptHasLogin(undefined)).toBe(false)
    expect(promptHasLogin(null)).toBe(false)
    expect(promptHasLogin('')).toBe(false)
    expect(promptHasLogin('consent')).toBe(false)
    expect(promptHasLogin('select_account')).toBe(false)
  })

  it('is true when login is the only token', () => {
    expect(promptHasLogin('login')).toBe(true)
  })

  it('is true when login appears alongside other tokens (in any order)', () => {
    expect(promptHasLogin('login consent')).toBe(true)
    expect(promptHasLogin('consent login')).toBe(true)
    expect(promptHasLogin('login select_account consent')).toBe(true)
  })

  it('is false for substrings that do not match the login token exactly', () => {
    // Defence against "login" appearing inside a longer token. OIDC has no
    // such tokens defined today, but the matcher should still be exact —
    // future spec extensions could add e.g. `login_required` and we want
    // to be wrong-by-design rather than wrong-by-coincidence.
    expect(promptHasLogin('logincreate')).toBe(false)
    expect(promptHasLogin('relogin')).toBe(false)
  })
})

describe('appendCookieClearHeaders', () => {
  it('clears dev-id and ses-id (plus :hash sidecars) host-only when no cookie domain given', () => {
    const res = makeResStub()
    appendCookieClearHeaders(res, null)
    expect(res._calls).toEqual([
      ['Set-Cookie', 'dev-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'dev-id:hash=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id=; Max-Age=0; Path=/'],
      ['Set-Cookie', 'ses-id:hash=; Max-Age=0; Path=/'],
    ])
  })

  it('also clears the domain-scoped variants when a cookie domain is given', () => {
    const res = makeResStub()
    appendCookieClearHeaders(res, 'pds.example')
    expect(res._calls).toEqual([
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

type FakeProvider = {
  accountManager: {
    listDeviceAccounts: (id: string) => Promise<unknown[]>
  }
  deviceManager: {
    store: {
      readDevice: (id: string) => Promise<{ sessionId: string } | null>
    }
  }
  requestManager: {
    store: {
      readRequest: (
        id: string,
      ) => Promise<{ parameters?: Record<string, unknown> } | null>
    }
  }
  checkLoginRequired: (binding: unknown) => boolean
}

/** Build a FakeProvider whose deviceStore returns a row matching the
 *  given sessionId by default — the common-case fixture used by every
 *  test that doesn't specifically exercise the stale-session branch. */
function makeProvider(opts: {
  bindings?: () => Promise<unknown[]>
  sessionId?: string | null
  readDevice?: () => Promise<{ sessionId: string } | null>
  // Stored PAR for the request_uri on the test URL. Returned shape mirrors
  // what `(provider.requestManager as any).store.readRequest(id)` produces:
  // a `{ parameters: { prompt?, login_hint?, ... } }` envelope.
  readRequest?: (
    id: string,
  ) => Promise<{ parameters?: Record<string, unknown> } | null>
  // Per-binding loginRequired predicate. Default: false (everything fresh).
  // Sign-in-view leak tests supply a custom predicate to mark specific
  // bindings stale.
  checkLoginRequired?: (binding: unknown) => boolean
}): FakeProvider {
  const ses = opts.sessionId === undefined ? VALID_SES : opts.sessionId
  return {
    accountManager: {
      listDeviceAccounts: vi.fn(opts.bindings ?? (() => Promise.resolve([]))),
    },
    deviceManager: {
      store: {
        readDevice: vi.fn(
          opts.readDevice ??
            (() => Promise.resolve(ses === null ? null : { sessionId: ses })),
        ),
      },
    },
    requestManager: {
      store: {
        readRequest: vi.fn(opts.readRequest ?? (() => Promise.resolve(null))),
      },
    },
    checkLoginRequired: vi.fn(opts.checkLoginRequired ?? (() => false)),
  }
}

function makeReq(opts: {
  method?: string
  path?: string
  cookieHeader?: string
  url?: string
}): Request {
  return {
    method: opts.method ?? 'GET',
    path: opts.path ?? '/oauth/authorize',
    url: opts.url ?? opts.path ?? '/oauth/authorize',
    headers: { cookie: opts.cookieHeader },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any
}

function makeRes(): Response & {
  status: ReturnType<typeof vi.fn>
  setHeader: ReturnType<typeof vi.fn>
  append: ReturnType<typeof vi.fn>
  end: ReturnType<typeof vi.fn>
} {
  const r = {
    status: vi.fn(function (this: unknown) {
      return r
    }),
    setHeader: vi.fn(function (this: unknown) {
      return r
    }),
    append: vi.fn(function (this: unknown) {
      return r
    }),
    end: vi.fn(function (this: unknown) {
      return r
    }),
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return r as any
}

describe('createAuthUiGuard', () => {
  const AUTH = 'auth.pds.example'

  it('passes non-GET requests through', async () => {
    const provider = makeProvider({})
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const next = vi.fn()
    await mw(
      makeReq({ method: 'POST', path: '/oauth/authorize' }),
      makeRes(),
      next,
    )
    expect(next).toHaveBeenCalledOnce()
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('passes unguarded paths through', async () => {
    const provider = makeProvider({})
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const next = vi.fn()
    await mw(makeReq({ path: '/health' }), makeRes(), next)
    expect(next).toHaveBeenCalledOnce()
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('passes through when provider is null (OAuth disabled)', async () => {
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      provider: null,
      cookieDomain: null,
    })
    const next = vi.fn()
    await mw(
      makeReq({ cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}` }),
      makeRes(),
      next,
    )
    expect(next).toHaveBeenCalledOnce()
  })

  it('bounces with cookie clears when cookies are missing', async () => {
    const provider = makeProvider({ bindings: () => Promise.resolve([]) })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: 'pds.example',
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({ url: '/oauth/authorize?request_uri=urn:x:1' }),
      res,
      next,
    )
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(303)
    const locationCall = res.setHeader.mock.calls.find(
      ([n]) => n === 'Location',
    )
    expect(locationCall?.[1]).toContain(
      'https://auth.pds.example/oauth/authorize',
    )
    expect(locationCall?.[1]).toContain('prompt=login')
    expect(locationCall?.[1]).toContain('request_uri=urn%3Ax%3A1')
    // Eight Set-Cookie entries: each of dev-id, dev-id:hash, ses-id,
    // ses-id:hash in both host-only and domain-scoped variants.
    expect(res.append).toHaveBeenCalledTimes(8)
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('passes /account* through when the URL carries no request_uri (direct nav)', async () => {
    // A bookmark or typed URL to /account has no OAuth context. Bouncing
    // to auth-service /oauth/authorize would just produce a 400
    // "Missing request_uri" — worse than letting upstream render. The
    // guard explicitly opts out of this case.
    const provider = makeProvider({})
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: 'pds.example',
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(makeReq({ path: '/account', url: '/account' }), res, next)
    expect(next).toHaveBeenCalledOnce()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.append).not.toHaveBeenCalled()
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('passes /account* through when bindings are zero but there is no request_uri', async () => {
    const provider = makeProvider({ bindings: () => Promise.resolve([]) })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        path: '/account/settings',
        url: '/account/settings',
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      res,
      next,
    )
    expect(next).toHaveBeenCalledOnce()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('bounces when cookies parse but bindings are empty', async () => {
    const provider = makeProvider({ bindings: () => Promise.resolve([]) })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
        url: '/oauth/authorize?request_uri=urn:x:1',
      }),
      res,
      next,
    )
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(303)
    expect(provider.accountManager.listDeviceAccounts).toHaveBeenCalledWith(
      VALID_DEV,
    )
  })

  it('calls next() when cookies parse and bindings exist', async () => {
    const provider = makeProvider({
      bindings: () => Promise.resolve([{ some: 'binding' }]),
    })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      res,
      next,
    )
    expect(next).toHaveBeenCalledOnce()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('bounces when listDeviceAccounts throws', async () => {
    const provider = makeProvider({
      bindings: () => Promise.reject(new Error('db down')),
    })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        url: '/oauth/authorize?request_uri=urn:x:1',
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      res,
      next,
    )
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(303)
  })

  it('logs the listDeviceAccounts rejection so real DB faults stay visible', async () => {
    // Silent fail-closed was hiding DB/provider faults as a surge of 303s
    // with no correlated log line — verify the structured error log fires
    // before the fail-closed bounce.
    const err = new Error('db down')
    const provider = makeProvider({ bindings: () => Promise.reject(err) })
    const logger = { error: vi.fn() }
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
      logger,
    })
    await mw(
      makeReq({
        url: '/oauth/authorize?request_uri=urn:x:1',
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      makeRes(),
      vi.fn(),
    )
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ err, deviceId: VALID_DEV }),
      expect.stringContaining('listDeviceAccounts failed'),
    )
  })

  it("degrades to fall-through instead of 500ing when req.url can't be parsed", async () => {
    // Node's URL parser is forgiving but not bulletproof (a bare `//`
    // triggers ERR_INVALID_URL). The guard must treat an unparseable URL
    // as "no OAuth context" and call next() rather than crash the request.
    const provider = makeProvider({})
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        path: '/oauth/authorize',
        url: '//',
        cookieHeader: undefined,
      }),
      res,
      next,
    )
    expect(next).toHaveBeenCalledTimes(1)
    expect(res.status).not.toHaveBeenCalled()
  })

  it('bounces when the cookie ses-id no longer matches the device row', async () => {
    // Cookie pair is well-formed and the device has bindings (so the
    // bindings check would let it through), but the persisted device
    // row's sessionId has been rotated/replaced — exactly the case that
    // would otherwise leak a stock-welcome render. Bounces with a full
    // cookie clear so the user gets a clean slate at auth-service.
    const STALE_SES = 'ses-1111111111111111111111111111111111111111'
    const ACTIVE_SES = 'ses-2222222222222222222222222222222222222222'
    const provider = makeProvider({
      bindings: () => Promise.resolve([{ some: 'binding' }]),
      sessionId: ACTIVE_SES,
    })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: 'pds.example',
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${STALE_SES}`,
        url: '/oauth/authorize?request_uri=urn:x:1',
      }),
      res,
      next,
    )
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(303)
    // The mismatch short-circuits the request before bindings are read.
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
    expect(res.append).toHaveBeenCalledTimes(8)
  })

  it('bounces when the device row is missing entirely', async () => {
    // A valid-looking cookie pair whose dev-id has no row at all
    // (manual server-side cleanup, dropped DB, expired purge) is the
    // mirror image of the stale-ses-id case: same risk of falling
    // through to upstream's welcome page if we trust the cookie alone.
    const provider = makeProvider({
      bindings: () => Promise.resolve([{ some: 'binding' }]),
      sessionId: null,
    })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
        url: '/oauth/authorize?request_uri=urn:x:1',
      }),
      res,
      next,
    )
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(303)
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('passes /account* through on a ses-id mismatch when there is no request_uri', async () => {
    // Mirrors the existing "/account* without request_uri" carve-out
    // for the bindings branch: bouncing direct /account* navigation to
    // auth-service /oauth/authorize would just produce a 400 "Missing
    // request_uri", which is worse than letting upstream render.
    const STALE_SES = 'ses-1111111111111111111111111111111111111111'
    const ACTIVE_SES = 'ses-2222222222222222222222222222222222222222'
    const provider = makeProvider({
      bindings: () => Promise.resolve([{ some: 'binding' }]),
      sessionId: ACTIVE_SES,
    })
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        path: '/account/settings',
        url: '/account/settings',
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${STALE_SES}`,
      }),
      res,
      next,
    )
    expect(next).toHaveBeenCalledOnce()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('bounces and logs when readDevice throws', async () => {
    // Same fail-closed posture as the listDeviceAccounts branch: an
    // unobservable surge of 303s with no correlated log line is a
    // worse failure than a noisy one.
    const err = new Error('readDevice down')
    const provider = makeProvider({
      bindings: () => Promise.resolve([{ some: 'binding' }]),
      readDevice: () => Promise.reject(err),
    })
    const logger = { error: vi.fn() }
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
      logger,
    })
    const res = makeRes()
    await mw(
      makeReq({
        url: '/oauth/authorize?request_uri=urn:x:1',
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      res,
      vi.fn(),
    )
    expect(res.status).toHaveBeenCalledWith(303)
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ err, deviceId: VALID_DEV }),
      expect.stringContaining('readDevice failed'),
    )
  })

  // ---------------------------------------------------------------------------
  // Sign-in-view leak coverage. Every test below shares the same wiring —
  // fresh cookies + non-empty bindings + a request_uri-bearing URL — and
  // varies only in the stored PAR `prompt` / `login_hint` values and which
  // bindings have loginRequired=true. The signinViewCase helper captures
  // that wiring; each test just supplies the inputs and assertion.
  // ---------------------------------------------------------------------------

  // Helper: build a binding fixture good enough for the guard's matchesHint
  // logic. Only `account.sub` and `account.preferred_username` are read.
  function binding(sub: string, pu: string) {
    return {
      account: { sub, preferred_username: pu },
    } as unknown as { account: { sub: string; preferred_username: string } }
  }

  // urn-prefixed request_uri so loadStoredPar actually attempts the read
  // (anything else makes it short-circuit and skip the prompt/hint logic).
  const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-abc'

  type SigninViewCaseOpts = Parameters<typeof makeProvider>[0] & {
    loggerError?: (...args: unknown[]) => void
  }
  /** Run the guard against the standard sign-in-view scenario fixture and
   *  return the (provider, res, next) trio for assertions. Centralises the
   *  repetitive setup that Sonar flagged as duplication. */
  async function signinViewCase(opts: SigninViewCaseOpts): Promise<{
    provider: FakeProvider
    res: ReturnType<typeof makeRes>
    next: ReturnType<typeof vi.fn>
  }> {
    const { loggerError, ...providerOpts } = opts
    const provider = makeProvider(providerOpts)
    const logger = loggerError ? { error: loggerError } : undefined
    const mw = createAuthUiGuard({
      authHostname: AUTH,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provider: provider as any,
      cookieDomain: null,
      logger,
    })
    const res = makeRes()
    const next = vi.fn()
    await mw(
      makeReq({
        url: `/oauth/authorize?request_uri=${encodeURIComponent(REQUEST_URI)}`,
        cookieHeader: `dev-id=${VALID_DEV}; ses-id=${VALID_SES}`,
      }),
      res,
      next,
    )
    return { provider, res, next }
  }

  /** Asserts the guard responded 303 (bounce). */
  function expectBounce(res: ReturnType<typeof makeRes>): void {
    expect(res.status).toHaveBeenCalledWith(303)
  }

  /** Asserts the guard called next() and didn't touch res.status. */
  function expectPassThrough(
    res: ReturnType<typeof makeRes>,
    next: ReturnType<typeof vi.fn>,
  ): void {
    expect(next).toHaveBeenCalledOnce()
    expect(res.status).not.toHaveBeenCalled()
  }

  it('bounces when the stored PAR forces re-authentication via prompt=login', async () => {
    const { provider, res } = await signinViewCase({
      bindings: () => Promise.resolve([binding('did:plc:a', 'a.example')]),
      // Even though the binding itself is fresh (checkLoginRequired
      // defaults to false), the prompt=login branch must bounce first —
      // and short-circuit ahead of the per-binding check.
      readRequest: () => Promise.resolve({ parameters: { prompt: 'login' } }),
    })
    expectBounce(res)
    expect(provider.checkLoginRequired).not.toHaveBeenCalled()
  })

  it('bounces when login appears alongside other prompt tokens', async () => {
    // Per OIDC Core §3.1.2.1, prompt is space-delimited. A third-party
    // client sending prompt="login consent" must trip the same bounce as
    // a bare prompt="login" — the earlier exact-string check missed this.
    const { res } = await signinViewCase({
      bindings: () => Promise.resolve([binding('did:plc:a', 'a.example')]),
      readRequest: () =>
        Promise.resolve({ parameters: { prompt: 'login consent' } }),
    })
    expectBounce(res)
  })

  it('bounces when every binding is loginRequired and there is no hint', async () => {
    const { res } = await signinViewCase({
      bindings: () =>
        Promise.resolve([
          binding('did:plc:a', 'a.example'),
          binding('did:plc:b', 'b.example'),
        ]),
      readRequest: () => Promise.resolve({ parameters: {} }),
      checkLoginRequired: () => true,
    })
    expectBounce(res)
  })

  // Fixture for the hint-narrowed cases: a device with two bindings,
  // one stale and one fresh. The checkLoginRequired predicate marks
  // only `did:plc:stale` as loginRequired.
  const onlyStaleIsLoginRequired = (b: unknown): boolean =>
    (b as { account: { sub: string } }).account.sub === 'did:plc:stale'
  const TWO_BINDINGS = [
    binding('did:plc:stale', 'stale.example'),
    binding('did:plc:fresh', 'fresh.example'),
  ]

  it('bounces when login_hint narrows to a stale binding among otherwise-fresh bindings', async () => {
    const { res } = await signinViewCase({
      bindings: () => Promise.resolve(TWO_BINDINGS),
      readRequest: () =>
        Promise.resolve({ parameters: { login_hint: 'stale.example' } }),
      checkLoginRequired: onlyStaleIsLoginRequired,
    })
    expectBounce(res)
  })

  it('passes through when login_hint matches a fresh binding', async () => {
    // Hint resolves to a single fresh binding → SSO/chooser path is
    // reachable; the guard must NOT bounce.
    const { res, next } = await signinViewCase({
      bindings: () => Promise.resolve(TWO_BINDINGS),
      readRequest: () =>
        Promise.resolve({ parameters: { login_hint: 'fresh.example' } }),
      checkLoginRequired: onlyStaleIsLoginRequired,
    })
    expectPassThrough(res, next)
  })

  it('passes through when at least one binding is fresh and there is no hint', async () => {
    // Mixed freshness, no hint → chooser reaches a usable session.
    const { res, next } = await signinViewCase({
      bindings: () => Promise.resolve(TWO_BINDINGS),
      readRequest: () => Promise.resolve({ parameters: {} }),
      checkLoginRequired: onlyStaleIsLoginRequired,
    })
    expectPassThrough(res, next)
  })

  it('falls back to all bindings when login_hint matches none of them', async () => {
    // matchesHint → empty set → upstream treats all bindings as candidates;
    // with at least one fresh, the guard passes through.
    const { next } = await signinViewCase({
      bindings: () =>
        Promise.resolve([binding('did:plc:fresh', 'fresh.example')]),
      readRequest: () =>
        Promise.resolve({ parameters: { login_hint: 'unknown.example' } }),
      checkLoginRequired: () => false,
    })
    expect(next).toHaveBeenCalledOnce()
  })

  it('passes through when readRequest fails — fail-open on the PAR-read path', async () => {
    // store.readRequest throwing means we don't know whether prompt=login
    // is set, but bindings exist and none are loginRequired by default.
    // Failing closed here would 303 every flow whose PAR happens to be
    // unreachable; pass through and let upstream handle it.
    const errSpy = vi.fn()
    const { res, next } = await signinViewCase({
      bindings: () => Promise.resolve([binding('did:plc:a', 'a.example')]),
      readRequest: () => Promise.reject(new Error('store down')),
      loggerError: errSpy,
    })
    expectPassThrough(res, next)
    expect(errSpy).toHaveBeenCalledWith(
      expect.any(Object),
      expect.stringContaining('store.readRequest failed'),
    )
  })
})
