/**
 * The Google sign-in button must POST to better-auth's /sign-in/social.
 *
 * better-auth registers that endpoint as POST-only, so the plain
 * `<a href=".../sign-in/social?provider=google...">` link the page used to
 * render sent a GET and got a 404: the button could never start a sign-in.
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

/** The Google button plus the Atmosphere hand-off button. */
const LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN = {
  epds_social_providers: ['google'],
  epds_handle_login_url: 'https://app.example.com/login',
}

/** An authorization URL of the shape better-auth returns for Google. */
const GOOGLE_URL =
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s'

describe('renderLoginPage social sign-in buttons', () => {
  it('never links to /sign-in/social with a GET', () => {
    expect(render()).not.toContain('/sign-in/social?provider=')
  })

  it('renders Google as a button, not a link', () => {
    expect(render()).toContain(
      '<button type="button" class="btn-social btn-google" data-social-provider="google">',
    )
  })

  it('clicking Google POSTs the provider and follows the returned URL', async () => {
    const { buttons, assign, fetchSpy } = runPage(() =>
      jsonResponse(200, { url: GOOGLE_URL, redirect: true }),
    )

    await buttons.google.click()

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/auth/sign-in/social')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      provider: 'google',
      callbackURL: '/auth/complete',
      errorCallbackURL: '/auth/complete?epds_social_provider=google',
    })
    expect(assign).toHaveBeenCalledWith(GOOGLE_URL)
  })

  it('sends Google the email address the user entered as its login hint', async () => {
    const { buttons, elements, fetchSpy } = runPage(() =>
      jsonResponse(200, { url: GOOGLE_URL }),
    )
    elements.emailInput.value = ' alice@gmail.com '

    await buttons.google.click()

    expect(JSON.parse(fetchSpy.mock.calls[0][1].body as string)).toMatchObject({
      provider: 'google',
      loginHint: 'alice@gmail.com',
    })
  })

  it.each([
    ['an incomplete address', 'alice@'],
    ['an empty field', ''],
  ])('sends no login hint for %s', async (_label, typed) => {
    const { buttons, elements, fetchSpy } = runPage(() =>
      jsonResponse(200, { url: GOOGLE_URL }),
    )
    elements.emailInput.value = typed

    await buttons.google.click()

    expect(
      JSON.parse(fetchSpy.mock.calls[0][1].body as string),
    ).not.toHaveProperty('loginHint')
  })

  it('sends no login hint while the field holds an ATProto handle', async () => {
    const { buttons, elements, fetchSpy } = runPage(
      () => jsonResponse(200, { url: GOOGLE_URL }),
      render({ branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN }),
    )
    await elements.atprotoButton.click()
    elements.emailInput.value = 'alice@gmail.com'

    await buttons.google.click()

    expect(
      JSON.parse(fetchSpy.mock.calls[0][1].body as string),
    ).not.toHaveProperty('loginHint')
  })

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

    resolveFetch(await jsonResponse(200, { url: GOOGLE_URL }))
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

      await buttons.google.click()

      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(assign).not.toHaveBeenCalled()
      expect(flash.text).toBe('Could not start sign-in. Please try again.')
      expect(buttons.google.disabled).toBe(false)
    },
  )

  it.each([
    ['an http URL', 'http://accounts.google.com/o/oauth2/v2/auth'],
    ['another host', 'https://evil.example/o/oauth2/v2/auth'],
    [
      'a look-alike host',
      'https://accounts.google.com.evil.example/o/oauth2/v2/auth',
    ],
    ['an explicit port', 'https://accounts.google.com:8443/o/oauth2/v2/auth'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a relative URL', '/o/oauth2/v2/auth'],
    ['a protocol-relative URL', '//accounts.google.com/o/oauth2/v2/auth'],
    ['a non-string URL', { href: GOOGLE_URL }],
  ] as const)(
    'refuses to follow %s and shows the error',
    async (_label, url) => {
      const { buttons, assign, flash } = runPage(() =>
        jsonResponse(200, { url, redirect: true }),
      )

      await buttons.google.click()

      expect(assign).not.toHaveBeenCalled()
      expect(flash.text).toBe('Could not start sign-in. Please try again.')
      expect(buttons.google.disabled).toBe(false)
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
      jsonResponse(200, { url: GOOGLE_URL }),
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
  it('renders no social buttons or "or" divider when the client offers no alternative', () => {
    const html = render({ branding: {} })
    expect(html).not.toContain('data-social-provider="')
    expect(html).not.toContain('class="divider"')
  })

  it('renders the Google button when the client lists it', () => {
    const html = render({ branding: { epds_social_providers: ['google'] } })
    expect(html).toContain('data-social-provider="google"')
  })

  it('ignores unknown and removed providers and a non-array value', () => {
    expect(
      render({ branding: { epds_social_providers: ['github', 'facebook'] } }),
    ).not.toContain('data-social-provider="')
    expect(
      render({
        branding: { epds_social_providers: 'google' as unknown as string[] },
      }),
    ).not.toContain('data-social-provider="')
  })
})

describe('renderLoginPage sign-in option order', () => {
  it('stacks the email form, one "or" divider, Atmosphere, then Google', () => {
    const html = render({ branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN })

    const positions = [
      'id="form-send-otp"',
      '<div class="divider"><span>or</span></div>',
      '<span class="btn-atproto-label">Sign in with Atmosphere</span>',
      'data-social-provider="google"',
    ].map((marker) => html.indexOf(marker))

    expect(positions.every((p) => p !== -1)).toBe(true)
    expect(positions).toEqual([...positions].sort((a, b) => a - b))
    expect(html.match(/class="divider"/g)).toHaveLength(1)
  })

  it.each([
    ['Atmosphere only', { epds_handle_login_url: 'https://app.example.com/l' }],
    ['Google only', { epds_social_providers: ['google'] }],
  ])('shows a single "or" divider for %s', (_label, branding) => {
    expect(render({ branding }).match(/class="divider"/g)).toHaveLength(1)
  })

  // The OTP step hides #step-email, so keeping the alternatives inside it is
  // what hides them on the code screen (initial render and after sending).
  it('keeps Atmosphere and Google inside the email step', () => {
    const html = render({
      branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN,
      initialStep: 'otp',
    })
    const emailStep = html.indexOf(
      '<div id="step-email" class="step-email hidden">',
    )
    const otpStep = html.indexOf('<div id="step-otp"')

    expect(emailStep).not.toBe(-1)
    for (const marker of [
      'btn-social btn-atproto"',
      'data-social-provider="google"',
    ]) {
      const pos = html.indexOf(marker)
      expect(pos).toBeGreaterThan(emailStep)
      expect(pos).toBeLessThan(otpStep)
    }
  })

  it('puts the @ icon before the Atmosphere label', () => {
    const html = render({ branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN })
    const icon = html.indexOf('class="btn-atproto-icon"')
    const label = html.indexOf('<span class="btn-atproto-label">')

    expect(icon).toBeGreaterThan(html.indexOf('btn-social btn-atproto"'))
    expect(label).toBeGreaterThan(icon)
  })

  it('ships a currentColor envelope icon that only shows in handle mode', () => {
    const html = render({ branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN })

    expect(html).toMatch(
      /<svg class="btn-atproto-email-icon"[^>]*stroke="currentColor"[^>]*aria-hidden="true"/,
    )
    expect(html).toContain('.btn-atproto-email-icon { display: none; }')
    expect(html).toContain(
      '.btn-atproto.handle-mode .btn-atproto-email-icon { display: block; }',
    )
  })

  it('relabels the Atmosphere button while in handle entry and restores it', async () => {
    const { elements } = runPage(
      () => jsonResponse(200, {}),
      render({ branding: LOGIN_PAGE_BRANDING_WITH_HANDLE_LOGIN }),
    )

    await elements.atprotoButton.click()
    expect(elements.atprotoLabel.textContent).toBe('Sign in with email')

    await elements.atprotoButton.click()
    expect(elements.atprotoLabel.textContent).toBe('Sign in with Atmosphere')
  })
})
