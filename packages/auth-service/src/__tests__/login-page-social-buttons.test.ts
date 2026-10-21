/**
 * The social sign-in buttons must POST to better-auth's /sign-in/social.
 *
 * better-auth registers that endpoint as POST-only, so the plain
 * `<a href=".../sign-in/social?provider=google...">` link the page used to
 * render sent a GET and got a 404: the Google and GitHub buttons could never
 * start a sign-in.
 *
 * The behavioural tests run the page's real inline script (see
 * __helpers__/login-page-script) and click a button.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  jsonResponse,
  LOGIN_PAGE_OPTIONS,
  runPageScript,
} from './__helpers__/login-page-script.js'

vi.mock('../better-auth.js', () => ({
  socialProviders: {
    google: { clientId: 'google-id', clientSecret: 'google-secret' },
    github: { clientId: 'github-id', clientSecret: 'github-secret' },
  },
}))

const { renderLoginPage } = await import('../routes/login-page.js')

function render(
  overrides: Partial<Parameters<typeof renderLoginPage>[0]> = {},
): string {
  return renderLoginPage({ ...LOGIN_PAGE_OPTIONS, ...overrides })
}

/** Run the page script of `html` (by default the plain login page). */
function runPage(
  fetchImpl: (url: string, init: RequestInit) => unknown,
  html: string = render(),
) {
  return runPageScript(html, fetchImpl)
}

/** Authorization URLs of the shape better-auth returns for each provider. */
const PROVIDER_URLS = {
  google:
    'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s',
  github:
    'https://github.com/login/oauth/authorize?client_id=github-id&state=s',
} as const

describe('renderLoginPage social sign-in buttons', () => {
  it('never links to /sign-in/social with a GET', () => {
    expect(render()).not.toContain('/sign-in/social?provider=')
  })

  it.each(['google', 'github'])('renders %s as a button, not a link', (p) => {
    expect(render()).toContain(
      `<button type="button" class="btn-social btn-${p}" data-social-provider="${p}">`,
    )
  })

  it.each(['google', 'github'] as const)(
    'clicking %s POSTs the provider and follows the returned URL',
    async (provider) => {
      const providerUrl = PROVIDER_URLS[provider]
      const { buttons, assign, fetchSpy } = runPage(() =>
        jsonResponse(200, { url: providerUrl, redirect: true }),
      )

      await buttons[provider].click()

      expect(fetchSpy).toHaveBeenCalledTimes(1)
      const [url, init] = fetchSpy.mock.calls[0]
      expect(url).toBe('/api/auth/sign-in/social')
      expect(init.method).toBe('POST')
      expect(JSON.parse(init.body as string)).toEqual({
        provider,
        callbackURL: '/auth/complete',
        errorCallbackURL: `/auth/complete?epds_social_provider=${provider}`,
      })
      expect(assign).toHaveBeenCalledWith(providerUrl)
    },
  )

  it('ignores a second click while the first POST is in flight', async () => {
    let resolveFetch: (v: unknown) => void = () => undefined
    const { buttons, fetchSpy } = runPage(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve
        }),
    )

    const first = buttons.google.click()
    await buttons.google.click()
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    resolveFetch(await jsonResponse(200, { url: PROVIDER_URLS.google }))
    await first
  })

  it.each([
    ['an error status', () => jsonResponse(404, {})],
    ['a response without a URL', () => jsonResponse(200, {})],
    ['a network failure', () => Promise.reject(new Error('offline'))],
  ])(
    'shows an error and re-enables the button after %s',
    async (_label, impl) => {
      const { buttons, assign, fetchSpy, flash } = runPage(impl)

      await buttons.github.click()

      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(assign).not.toHaveBeenCalled()
      expect(flash.text).toBe('Could not start sign-in. Please try again.')
      expect(buttons.github.disabled).toBe(false)
    },
  )

  it.each([
    ['an http URL', 'google', 'http://accounts.google.com/o/oauth2/v2/auth'],
    ['another host', 'google', 'https://evil.example/o/oauth2/v2/auth'],
    [
      'a look-alike host',
      'google',
      'https://accounts.google.com.evil.example/o/oauth2/v2/auth',
    ],
    ['a Google URL for GitHub', 'github', PROVIDER_URLS.google],
    ['a GitHub URL for Google', 'google', PROVIDER_URLS.github],
    ['an explicit port', 'github', 'https://github.com:8443/login/oauth'],
    ['a javascript: URL', 'google', 'javascript:alert(1)'],
    ['a relative URL', 'github', '/login/oauth/authorize'],
    ['a protocol-relative URL', 'github', '//github.com/login/oauth/authorize'],
    ['a non-string URL', 'google', { href: PROVIDER_URLS.google }],
  ] as const)(
    'refuses to follow %s and shows the error',
    async (_label, provider, url) => {
      const { buttons, assign, flash } = runPage(() =>
        jsonResponse(200, { url, redirect: true }),
      )

      await buttons[provider].click()

      expect(assign).not.toHaveBeenCalled()
      expect(flash.text).toBe('Could not start sign-in. Please try again.')
      expect(buttons[provider].disabled).toBe(false)
    },
  )

  it('shows the error for a JSON null body', async () => {
    const { buttons, assign, flash } = runPage(() => jsonResponse(200, null))

    await buttons.google.click()

    expect(assign).not.toHaveBeenCalled()
    expect(flash.text).toBe('Could not start sign-in. Please try again.')
  })

  it('re-enables the buttons when the page is restored from the back/forward cache', async () => {
    const { buttons, windowListeners } = runPage(() =>
      jsonResponse(200, { url: PROVIDER_URLS.google }),
    )
    await buttons.google.click()
    expect(buttons.google.disabled).toBe(true)

    for (const fn of windowListeners.pageshow ?? []) fn({ persisted: true })

    expect(buttons.google.disabled).toBe(false)
  })

  it('shows the initial error from a returned social sign-in on load', () => {
    const message = 'Sign-in was cancelled. You can try again.'
    const { flash } = runPage(
      () => jsonResponse(200, {}),
      render({ initialError: message }),
    )
    expect(flash.text).toBe(message)
  })

  it('shows nothing on load without an initial error', () => {
    const { flash } = runPage(() => jsonResponse(200, {}))
    expect(flash.text).toBe('')
  })
})

describe('renderLoginPage social sign-in opt-in', () => {
  it('renders no social buttons when the client does not ask for any', () => {
    const html = render({ branding: {} })
    expect(html).not.toContain('data-social-provider="')
    expect(html).not.toContain('or continue with')
  })

  it('renders only the providers the client lists', () => {
    const html = render({ branding: { epds_social_providers: ['google'] } })
    expect(html).toContain('data-social-provider="google"')
    expect(html).not.toContain('data-social-provider="github"')
  })

  it('ignores unknown providers and a non-array value', () => {
    expect(
      render({ branding: { epds_social_providers: ['facebook'] } }),
    ).not.toContain('data-social-provider="')
    expect(
      render({
        branding: { epds_social_providers: 'google' as unknown as string[] },
      }),
    ).not.toContain('data-social-provider="')
  })
})
