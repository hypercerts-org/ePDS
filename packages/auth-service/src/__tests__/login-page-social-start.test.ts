/**
 * Route-level coverage for GET /oauth/authorize?epds_social_provider=<id>:
 * a client starting a social sign-in from its own page (for example a
 * "Sign in with Google" button next to its email field). The browser is
 * redirected straight to the provider, with no login page in between and
 * no email code sent; a hinted email address goes to Google as its login
 * hint.
 *
 * The parameter only counts for a provider this client's page offers, and
 * never on a social error return, which carries the same parameter to
 * name the provider that failed: a refused sign-in must not restart
 * itself. better-auth is a stand-in here; create-better-auth.test.ts runs
 * the same start against the real instance.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import {
  startLoginPageApp,
  type LoginPageApp,
  type LoginPageAuth,
} from './__helpers__/login-page-app.js'
import { jsonResponse, runPageScript } from './__helpers__/login-page-script.js'

const mocks = vi.hoisted(() => ({
  fetchParLoginHint: vi.fn<() => Promise<string | null>>(),
  resolveLoginHint: vi.fn<() => Promise<string | null>>(),
  fetchDeviceAccountEmails: vi.fn<() => Promise<string[] | null>>(),
  signInSocial: vi.fn<(opts: unknown) => Promise<unknown>>(),
}))

vi.mock('../lib/resolve-login-hint.js', () => ({
  fetchParLoginHint: mocks.fetchParLoginHint,
  resolveLoginHint: mocks.resolveLoginHint,
}))

vi.mock('../lib/fetch-device-accounts.js', () => ({
  fetchDeviceAccountEmails: mocks.fetchDeviceAccountEmails,
}))

vi.mock('../better-auth.js', () => ({
  socialProviders: {
    google: { clientId: 'google-id', clientSecret: 'google-secret' },
  },
}))

const CLIENT_ID = 'https://app.example.com'
const GOOGLE_URL =
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s1'
const STATE_COOKIE =
  '__Secure-better-auth.state=s1.sig; Max-Age=300; Path=/; HttpOnly; Secure; SameSite=Lax'
const START_FAILED = 'Could not start sign-in. Please try again.'

/** better-auth's answer to signInSocial({ returnHeaders: true }). */
function started(url: unknown = GOOGLE_URL) {
  return Promise.resolve({
    headers: new Headers([['set-cookie', STATE_COOKIE]]),
    response: { url, redirect: false },
  })
}

const auth = {
  api: { signInSocial: mocks.signInSocial },
} as unknown as LoginPageAuth

describe('GET /oauth/authorize with epds_social_provider', () => {
  let app: LoginPageApp
  let requestCount = 0

  beforeEach(async () => {
    mocks.fetchParLoginHint.mockResolvedValue(null)
    mocks.resolveLoginHint.mockResolvedValue(null)
    mocks.fetchDeviceAccountEmails.mockResolvedValue(null)
    mocks.signInSocial.mockImplementation(() => started())
    app = await startLoginPageApp('social-start', auth)
    offerProviders(['google'])
  })

  afterEach(async () => {
    vi.clearAllMocks()
    await app.close()
  })

  function offerProviders(providers: string[]): void {
    _seedClientMetadataCacheForTest(CLIENT_ID, {
      client_name: 'Test App',
      epds_social_providers: providers,
    })
  }

  function requestUriFor(n: number): string {
    return `urn:ietf:params:oauth:request_uri:start-${n}`
  }

  /**
   * GET /oauth/authorize for a fresh flow with `query` appended, without
   * following redirects.
   */
  function authorize(
    query: string,
    headers: Record<string, string> = {},
  ): Promise<globalThis.Response> {
    requestCount += 1
    return fetch(
      `${app.baseUrl}/oauth/authorize?request_uri=${requestUriFor(requestCount)}` +
        `&client_id=${encodeURIComponent(CLIENT_ID)}${query}`,
      { headers, redirect: 'manual' },
    )
  }

  async function loginPage(
    query: string,
    headers: Record<string, string> = {},
  ): Promise<string> {
    const res = await authorize(query, headers)
    expect(res.status).toBe(200)
    return res.text()
  }

  /** The body better-auth was asked to start the sign-in with. */
  function startBody(): Record<string, unknown> {
    expect(mocks.signInSocial).toHaveBeenCalledTimes(1)
    const [opts] = mocks.signInSocial.mock.calls[0] as [
      { body: Record<string, unknown>; returnHeaders: boolean },
    ]
    expect(opts.returnHeaders).toBe(true)
    return opts.body
  }

  /** The URLs of the requests the page script makes on load. */
  async function requestsOnLoad(html: string): Promise<string[]> {
    const { fetchSpy } = runPageScript(html, () => jsonResponse(200, {}))
    await new Promise((resolve) => setTimeout(resolve, 0))
    return fetchSpy.mock.calls.map(([url]) => url)
  }

  function withHint(hint: string, resolved: string = hint): string {
    mocks.resolveLoginHint.mockResolvedValue(resolved)
    return `&login_hint=${encodeURIComponent(hint)}`
  }

  it('redirects straight to Google with the hinted address', async () => {
    const res = await authorize(
      `${withHint('alice@gmail.com')}&epds_social_provider=google`,
    )

    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(GOOGLE_URL)
    expect(startBody()).toEqual({
      provider: 'google',
      callbackURL: '/auth/complete',
      errorCallbackURL: '/auth/complete?epds_social_provider=google',
      disableRedirect: true,
      loginHint: 'alice@gmail.com',
    })
  })

  it('sends both the auth_flow cookie and the OAuth state cookie', async () => {
    const res = await authorize('&epds_social_provider=google')

    const cookies = res.headers.getSetCookie()
    expect(cookies).toContain(STATE_COOKIE)
    const flowCookie = cookies.find((c) => c.startsWith('epds_auth_flow='))
    expect(flowCookie).toBeDefined()
    const flowId = /^epds_auth_flow=([^;]+)/.exec(flowCookie ?? '')?.[1]
    expect(
      app.ctx.db.getAuthFlowByRequestUri(requestUriFor(requestCount)),
    ).toMatchObject({ flowId, clientId: CLIENT_ID })
  })

  it('redirects without a login hint when there is none', async () => {
    const res = await authorize('&epds_social_provider=google')
    expect(res.status).toBe(302)
    expect(startBody()).not.toHaveProperty('loginHint')
  })

  it('never gives Google an address resolved from a handle', async () => {
    const res = await authorize(
      withHint('alice.example.com', 'alice.private@example.com') +
        '&epds_social_provider=google',
    )

    expect(res.status).toBe(302)
    expect(startBody()).not.toHaveProperty('loginHint')
    expect(res.headers.get('location')).not.toContain('private')
  })

  it('keeps the orphan device-cookie clears on the redirect', async () => {
    const res = await authorize('&epds_social_provider=google', {
      cookie: 'dev-id=dev-1',
    })

    expect(res.status).toBe(302)
    const cookies = res.headers.getSetCookie()
    expect(
      cookies.some((c) => c.startsWith('dev-id=') && /Max-Age=0/i.test(c)),
    ).toBe(true)
    expect(cookies).toContain(STATE_COOKIE)
    expect(cookies.some((c) => c.startsWith('epds_auth_flow='))).toBe(true)
  })

  it.each([
    ['better-auth throws', () => Promise.reject(new Error('db down'))],
    ['the URL is not Google', () => started('https://evil.example/auth')],
    ['there is no URL', () => started(null)],
  ])(
    'shows the login page with the reason, sending no code, when %s',
    async (_label, answer) => {
      mocks.signInSocial.mockImplementation(answer)
      const html = await loginPage(
        `${withHint('alice@gmail.com')}&epds_social_provider=google`,
      )

      expect(html).toContain('var initialStep = "email";')
      expect(html).toContain(`var initialError = "${START_FAILED}";`)
      expect(await requestsOnLoad(html)).toEqual([])
    },
  )

  it('sends a code for a login_hint without the parameter (control)', async () => {
    const html = await loginPage(withHint('alice@gmail.com'))
    expect(html).toContain('var initialStep = "otp";')
    expect(await requestsOnLoad(html)).toEqual([
      '/api/auth/email-otp/send-verification-otp',
    ])
    expect(mocks.signInSocial).not.toHaveBeenCalled()
  })

  it.each([
    ['a removed provider', 'github'],
    ['an unknown provider', 'facebook'],
    ['an empty value', ''],
  ])('ignores %s and sends the code as usual', async (_label, provider) => {
    const html = await loginPage(
      `${withHint('alice@gmail.com')}&epds_social_provider=${provider}`,
    )
    expect(html).toContain('var initialStep = "otp";')
    expect(await requestsOnLoad(html)).toEqual([
      '/api/auth/email-otp/send-verification-otp',
    ])
    expect(mocks.signInSocial).not.toHaveBeenCalled()
  })

  it('ignores Google when the client does not list it', async () => {
    offerProviders([])
    const html = await loginPage('&epds_social_provider=google')
    expect(html).toContain('var initialError = "";')
    expect(mocks.signInSocial).not.toHaveBeenCalled()
  })

  it('never starts a provider on a social error return', async () => {
    const html = await loginPage(
      '&epds_social_error=cancelled&epds_social_provider=google',
    )
    expect(mocks.signInSocial).not.toHaveBeenCalled()
    const { flash } = runPageScript(html, () => jsonResponse(200, {}))
    expect(flash.text).toContain('Sign-in was cancelled.')
  })

  describe('with a device session in the browser', () => {
    const deviceSession = { cookie: 'dev-id=dev-1; ses-id=ses-1' }

    function goesToPdsCore(res: globalThis.Response): void {
      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toMatch(
        /^https:\/\/test\.local\/oauth\/authorize\?/,
      )
      expect(mocks.signInSocial).not.toHaveBeenCalled()
    }

    it('is handed to pds-core without the parameter (control)', async () => {
      goesToPdsCore(await authorize('', deviceSession))
    })

    it('goes to Google instead of pds-core', async () => {
      const res = await authorize('&epds_social_provider=google', deviceSession)
      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toBe(GOOGLE_URL)
    })

    it.each([
      ['a removed provider', 'github'],
      ['an unknown provider', 'facebook'],
    ])('is still handed to pds-core for %s', async (_label, provider) => {
      goesToPdsCore(
        await authorize(`&epds_social_provider=${provider}`, deviceSession),
      )
    })

    it('is still handed to pds-core when the client does not list Google', async () => {
      offerProviders([])
      goesToPdsCore(
        await authorize('&epds_social_provider=google', deviceSession),
      )
    })
  })
})
