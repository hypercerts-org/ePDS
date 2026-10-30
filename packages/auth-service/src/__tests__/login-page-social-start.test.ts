/**
 * Route-level coverage for GET /oauth/authorize?epds_social_provider=<id>:
 * a client starting a social sign-in from its own page (for example a
 * "Sign in with Google" button next to its email field). The login page
 * hands off to the provider on load, as if its button had been pressed,
 * and sends no email code, even when the request carries a login_hint;
 * the hinted address goes to Google as its login hint instead.
 *
 * The parameter only counts for a provider this client's page offers, and
 * never on a social error return, which carries the same parameter to
 * name the provider that failed: a refused sign-in must not restart
 * itself. The served page's own script is run (see
 * __helpers__/login-page-script) to show what it does on load.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import {
  startLoginPageApp,
  type LoginPageApp,
} from './__helpers__/login-page-app.js'
import { jsonResponse, runPageScript } from './__helpers__/login-page-script.js'

const mocks = vi.hoisted(() => ({
  fetchParLoginHint: vi.fn<() => Promise<string | null>>(),
  resolveLoginHint: vi.fn<() => Promise<string | null>>(),
  fetchDeviceAccountEmails: vi.fn<() => Promise<string[] | null>>(),
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
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s'

describe('GET /oauth/authorize with epds_social_provider', () => {
  let app: LoginPageApp
  let requestCount = 0

  beforeEach(async () => {
    mocks.fetchParLoginHint.mockResolvedValue(null)
    mocks.resolveLoginHint.mockResolvedValue(null)
    mocks.fetchDeviceAccountEmails.mockResolvedValue(null)
    app = await startLoginPageApp('social-start')
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
      `${app.baseUrl}/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:start-${requestCount}` +
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

  /** Run the page script and let the requests it starts on load settle. */
  async function runOnLoad(html: string) {
    const page = runPageScript(html, () =>
      jsonResponse(200, { url: GOOGLE_URL, redirect: true }),
    )
    await new Promise((resolve) => setTimeout(resolve, 0))
    return page
  }

  function withHint(email: string): string {
    mocks.resolveLoginHint.mockResolvedValue(email)
    return `&login_hint=${encodeURIComponent(email)}`
  }

  it('starts Google on load with the hinted address, sending no code', async () => {
    const html = await loginPage(
      `${withHint('alice@gmail.com')}&epds_social_provider=google`,
    )
    expect(html).toContain('var initialStep = "email";')

    const { fetchSpy, assign } = await runOnLoad(html)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/auth/sign-in/social')
    expect(JSON.parse(init.body as string)).toEqual({
      provider: 'google',
      callbackURL: '/auth/complete',
      errorCallbackURL: '/auth/complete?epds_social_provider=google',
      loginHint: 'alice@gmail.com',
    })
    expect(assign).toHaveBeenCalledWith(GOOGLE_URL)
  })

  it('starts Google on load without a hint', async () => {
    const { fetchSpy } = await runOnLoad(
      await loginPage('&epds_social_provider=google'),
    )
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(
      JSON.parse(fetchSpy.mock.calls[0][1].body as string),
    ).not.toHaveProperty('loginHint')
  })

  it('sends a code for a login_hint without the parameter (control)', async () => {
    const html = await loginPage(withHint('alice@gmail.com'))
    expect(html).toContain('var initialStep = "otp";')
    expect(html).toContain('var startSocialProvider = "";')
  })

  it.each([
    ['a provider this client does not offer', 'github'],
    ['an unknown provider', 'facebook'],
    ['an empty value', ''],
  ])('ignores %s and sends the code as usual', async (_label, provider) => {
    const html = await loginPage(
      `${withHint('alice@gmail.com')}&epds_social_provider=${provider}`,
    )
    expect(html).toContain('var initialStep = "otp";')
    expect(html).toContain('var startSocialProvider = "";')
  })

  it('ignores Google when the client does not list it', async () => {
    offerProviders([])
    const html = await loginPage('&epds_social_provider=google')
    expect(html).toContain('var startSocialProvider = "";')
    const { fetchSpy } = await runOnLoad(html)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('never starts a provider on a social error return', async () => {
    const html = await loginPage(
      '&epds_social_error=cancelled&epds_social_provider=google',
    )
    expect(html).toContain('var startSocialProvider = "";')
    const { fetchSpy, flash } = await runOnLoad(html)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(flash.text).toContain('Sign-in was cancelled.')
  })

  it('starts Google instead of handing a device session to pds-core', async () => {
    const deviceSession = { cookie: 'dev-id=dev-1; ses-id=ses-1' }
    expect((await authorize('', deviceSession)).status).toBe(302)

    const html = await loginPage('&epds_social_provider=google', deviceSession)
    expect(html).toContain('var startSocialProvider = "google";')
  })
})
