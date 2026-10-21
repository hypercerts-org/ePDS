/**
 * The login page runs one sign-in attempt at a time across every method:
 * the social buttons, sending and verifying an email code, a resend, and
 * the ATProto/Bluesky handle hand-off. Two in flight race each other — a
 * second POST /sign-in/social replaces the first one's OAuth state, and a
 * verify can land while the page is already leaving for a provider.
 *
 * Runs the page's real inline script (see __helpers__/login-page-script)
 * and drives its handlers directly, so the guard is shown to be checked in
 * each handler, not only through disabled buttons.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  jsonResponse,
  LOGIN_PAGE_OPTIONS,
  runPageScript,
  type PageScriptHandles,
} from './__helpers__/login-page-script.js'

vi.mock('../better-auth.js', () => ({
  socialProviders: {
    google: { clientId: 'google-id', clientSecret: 'google-secret' },
    github: { clientId: 'github-id', clientSecret: 'github-secret' },
  },
}))

const { renderLoginPage } = await import('../routes/login-page.js')

const GOOGLE_URL =
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=google-id&state=s'
const HANDLE_LOGIN_URL = 'https://app.example.com/api/oauth/login'

const SOCIAL = '/api/auth/sign-in/social'
const SEND = '/api/auth/email-otp/send-verification-otp'
const VERIFY = '/api/auth/sign-in/email-otp'
const PING = '/auth/ping'

type Answer = () => unknown

/** A request answer the test settles later, to hold a request in flight. */
function deferred() {
  let settle: (v: unknown) => void = () => undefined
  const promise = new Promise((resolve) => {
    settle = resolve
  })
  return {
    answer: (() => promise) as Answer,
    resolve: (status: number, body: unknown) => {
      void jsonResponse(status, body).then(settle)
    },
  }
}

const ok: Record<string, Answer> = {
  [SOCIAL]: () => jsonResponse(200, { url: GOOGLE_URL }),
  [SEND]: () => jsonResponse(200, { success: true }),
  [VERIFY]: () => jsonResponse(200, { token: 't' }),
  [PING]: () => jsonResponse(200, { ok: true }),
}

/** Run the page with `overrides` answering some endpoints. */
function runPage(overrides: Record<string, Answer> = {}) {
  const answers = { ...ok, ...overrides }
  const html = renderLoginPage({
    ...LOGIN_PAGE_OPTIONS,
    branding: {
      epds_social_providers: ['google', 'github'],
      epds_handle_login_url: HANDLE_LOGIN_URL,
    },
  })
  return runPageScript(html, (url) => {
    const answer = answers[url] as Answer | undefined
    if (!answer) throw new Error(`unexpected fetch ${url}`)
    return answer()
  })
}

/** Let every pending handler step run. */
function settle(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve)
  })
}

/** The URLs the page has fetched, without heartbeat pings. */
function requests(page: PageScriptHandles): string[] {
  return page.fetchSpy.mock.calls.map(([url]) => url).filter((u) => u !== PING)
}

function sendCode(page: PageScriptHandles) {
  page.elements.emailInput.value = 'alice@example.com'
  return page.elements.sendOtpForm.submit()
}

function verifyCode(page: PageScriptHandles) {
  page.elements.code.value = '123456'
  return page.elements.verifyForm.submit()
}

async function handOffHandle(page: PageScriptHandles) {
  await page.elements.atprotoButton.click()
  page.elements.emailInput.value = 'alice.bsky.social'
  return page.elements.sendOtpForm.submit()
}

/** Every way to start a sign-in, and what it leaves behind once started. */
const methods = {
  'the Google button': {
    start: (page: PageScriptHandles) => page.buttons.google.click(),
    endpoint: SOCIAL,
  },
  'the GitHub button': {
    start: (page: PageScriptHandles) => page.buttons.github.click(),
    endpoint: SOCIAL,
  },
  'sending an email code': { start: sendCode, endpoint: SEND },
  'resending an email code': {
    start: (page: PageScriptHandles) => page.elements.resendButton.click(),
    endpoint: SEND,
  },
  'verifying an email code': { start: verifyCode, endpoint: VERIFY },
}

type Method = keyof typeof methods

const pairs = (Object.keys(methods) as Method[]).flatMap((first) =>
  (Object.keys(methods) as Method[]).map((second) => [first, second] as const),
)

describe('login page sign-in guard', () => {
  it.each(pairs)(
    'while %s is in flight, %s does not start',
    async (first, second) => {
      const held = deferred()
      const page = runPage({ [methods[first].endpoint]: held.answer })

      const inFlight = methods[first].start(page)
      await methods[second].start(page)
      await settle()

      expect(requests(page)).toEqual([methods[first].endpoint])
      held.resolve(500, {})
      await inFlight
    },
  )

  it('blocks a handle hand-off while another sign-in is in flight', async () => {
    const held = deferred()
    const page = runPage({ [SOCIAL]: held.answer })

    const inFlight = page.buttons.google.click()
    await handOffHandle(page)

    expect(page.navigations).toEqual([])
    held.resolve(500, {})
    await inFlight
  })

  it('disables every social button while any sign-in is in flight', async () => {
    const held = deferred()
    const page = runPage({ [SEND]: held.answer })

    const inFlight = sendCode(page)
    expect(page.buttons.google.disabled).toBe(true)
    expect(page.buttons.github.disabled).toBe(true)

    held.resolve(200, { success: true })
    await inFlight
    expect(page.buttons.google.disabled).toBe(false)
    expect(page.buttons.github.disabled).toBe(false)
  })

  it('disables the email-code button while a social sign-in is in flight', async () => {
    const held = deferred()
    const page = runPage({ [SOCIAL]: held.answer })

    const inFlight = page.buttons.google.click()
    expect(page.elements.sendOtpButton.disabled).toBe(true)

    held.resolve(500, {})
    await inFlight
    expect(page.elements.sendOtpButton.disabled).toBe(false)
  })

  it('lets the code that was just sent be verified', async () => {
    const page = runPage()

    await sendCode(page)
    await verifyCode(page)

    expect(requests(page)).toEqual([SEND, VERIFY])
    expect(page.navigations).toEqual(['/auth/complete'])
  })

  it.each([
    ['a social sign-in', (p: PageScriptHandles) => p.buttons.google.click()],
    [
      'a verified email code',
      async (p: PageScriptHandles) => {
        await sendCode(p)
        await verifyCode(p)
      },
    ],
    ['a handle hand-off', handOffHandle],
  ])('keeps the guard while %s is navigating away', async (_label, start) => {
    const page = runPage()
    await start(page)
    const before = requests(page)
    const navigated = page.navigations.length
    expect(navigated).toBe(1)

    await page.buttons.github.click()
    await sendCode(page)
    await verifyCode(page)

    expect(requests(page)).toEqual(before)
    expect(page.navigations).toHaveLength(navigated)
  })

  it.each([
    ['a social sign-in that could not start', SOCIAL, () => ({})],
    ['an email code that could not be sent', SEND, () => ({ error: 'no' })],
  ])('releases the guard after %s', async (_label, endpoint, body) => {
    const page = runPage({ [endpoint]: () => jsonResponse(500, body()) })

    await (endpoint === SOCIAL ? page.buttons.google.click() : sendCode(page))
    await page.buttons.github.click()

    expect(requests(page)).toEqual([endpoint, SOCIAL])
  })

  it('releases the guard after a rejected code, so the user can retry or switch', async () => {
    const page = runPage({
      [VERIFY]: () => jsonResponse(400, { message: 'Invalid OTP' }),
    })

    await sendCode(page)
    await verifyCode(page)
    await verifyCode(page)
    await page.buttons.google.click()

    expect(requests(page)).toEqual([SEND, VERIFY, VERIFY, SOCIAL])
  })

  it('releases the guard when the page is restored from the back/forward cache', async () => {
    const page = runPage()
    await page.buttons.google.click()
    expect(page.assign).toHaveBeenCalledWith(GOOGLE_URL)

    for (const fn of page.windowListeners.pageshow ?? [])
      fn({ persisted: true })
    await sendCode(page)

    expect(requests(page)).toEqual([SOCIAL, SEND])
  })
})
