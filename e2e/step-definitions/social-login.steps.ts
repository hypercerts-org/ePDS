/**
 * Step definitions for social-login.feature (Google sign-in).
 *
 * Google is faked at both ends. The browser's navigation to
 * accounts.google.com is intercepted and redirected straight back to the
 * auth service's /api/auth/callback/google, carrying the scenario's chosen
 * ID token claims as the authorization code (or a cancel). When the auth
 * service itself redirects to Google, the trip is intercepted at the start
 * of the redirect chain instead (see fakeGoogleBehindRedirects). The auth
 * service, started with EPDS_TEST_FAKE_GOOGLE=1, answers its token request
 * with an ID token for those claims (packages/auth-service/src/lib/
 * test-google-token.ts). Everything between the two runs as in production.
 *
 * Only runs where testEnv.fakeGoogle is set (tag @fake-google); the Google
 * steps return 'pending' otherwise, for runs by --name that bypass tags.
 */

import { randomBytes } from 'node:crypto'
import { Given, Then, When } from '@cucumber/cucumber'
import { expect, type Page } from '@playwright/test'
import { testEnv } from '../support/env.js'
import { sharedBrowser } from '../support/hooks.js'
import {
  clearMailpit,
  countMessages,
  extractOtp,
  waitForEmail,
} from '../support/mailpit.js'
import { fillOtp } from '../support/otp.js'
import {
  assertDemoClientSession,
  getPage,
  resetBrowserContext,
} from '../support/utils.js'
import type { EpdsWorld } from '../support/world.js'

const demoBaseUrl = testEnv.demoUrl.replace(/\/$/, '')

function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now()}-${randomBytes(6).toString('hex')}`
}

/** Claims of a Google account that has verified `email`. */
function verifiedGoogleAccount(email: string): Record<string, unknown> {
  return { sub: uniqueId('google'), email, email_verified: true }
}

type GoogleOutcome = { claims: Record<string, unknown> } | 'cancel'

/**
 * Google's answer to a request for `googleUrl`: the redirect_uri it was
 * given, with the state, and either an authorization code that carries
 * `claims` or the error Google returns when the user cancels. The URL
 * Google was sent is kept on the world.
 */
function googleAnswer(
  world: EpdsWorld,
  googleUrl: URL,
  outcome: GoogleOutcome,
): string {
  world.googleAuthorizeUrl = googleUrl
  const back = new URL(googleUrl.searchParams.get('redirect_uri') ?? '')
  back.searchParams.set('state', googleUrl.searchParams.get('state') ?? '')
  if (outcome === 'cancel') {
    back.searchParams.set('error', 'access_denied')
  } else {
    back.searchParams.set(
      'code',
      Buffer.from(JSON.stringify(outcome.claims)).toString('base64url'),
    )
  }
  return back.href
}

/** Answer the browser's own navigations to Google (see googleAnswer). */
async function fakeGoogle(
  world: EpdsWorld,
  page: Page,
  outcome: GoogleOutcome,
): Promise<void> {
  await page.route('https://accounts.google.com/**', async (route) => {
    const location = googleAnswer(
      world,
      new URL(route.request().url()),
      outcome,
    )
    await route.fulfill({ status: 302, headers: { location } })
  })
}

/**
 * Answer a trip to Google that the browser makes only by following
 * redirects from a request to `firstHop`. Playwright routes just the first
 * request of a redirect chain, so this route follows the chain itself and
 * stands in for Google when it gets there. page.request shares the
 * browser's cookies, so each hop's cookies are kept as the browser would
 * keep them. The URL that redirected to Google is kept on the world.
 */
async function fakeGoogleBehindRedirects(
  world: EpdsWorld,
  page: Page,
  firstHop: (url: URL) => boolean,
  outcome: GoogleOutcome,
): Promise<void> {
  await page.route(firstHop, async (route) => {
    let response = await route.fetch({ maxRedirects: 0 })
    let at = new URL(route.request().url())
    for (let hops = 0; hops < 10; hops++) {
      const location = response.headers()['location']
      if (!location) break
      const next = new URL(location, at)
      if (next.origin === 'https://accounts.google.com') {
        world.googleRedirectedFrom = at
        await route.fulfill({
          status: 302,
          headers: { location: googleAnswer(world, next, outcome) },
        })
        return
      }
      response = await page.request.get(next.href, { maxRedirects: 0 })
      at = next
    }
    await route.fulfill({ response })
  })
}

/**
 * Open the auth service's login page for the trusted demo (via its flow 2
 * entry, which lands on the email step) and press "Sign in with Google".
 */
async function signInWithGoogle(
  world: EpdsWorld,
  outcome: GoogleOutcome,
): Promise<void> {
  const page = getPage(world)
  await fakeGoogle(world, page, outcome)
  await page.goto(`${demoBaseUrl}/flow2`)
  await page.click('button[type=submit]')
  await page.waitForLoadState('networkidle')
  await page.getByRole('button', { name: 'Sign in with Google' }).click()
}

/** The DID shown on the demo client's welcome page. */
async function welcomeDid(page: Page): Promise<string> {
  await page.waitForURL('**/welcome', { timeout: 30_000 })
  const did = /did:[a-z0-9:]+/i.exec(await page.locator('body').innerText())
  if (!did) throw new Error('Could not find DID on welcome page')
  return did[0]
}

/**
 * Sign in with an emailed code, entering the address in the email form on
 * the current page: the auth service's login page, or the demo's own form,
 * which hands the address to it.
 */
async function signInWithEmailCode(
  page: Page,
  email: string,
  submit = '#form-send-otp button[type=submit]',
): Promise<void> {
  await clearMailpit(email)
  await page.fill('#email', email)
  await page.click(submit)
  await expect(page.locator('#step-otp.active')).toBeVisible({
    timeout: 30_000,
  })
  const message = await waitForEmail(`to:${email}`)
  await fillOtp(page, await extractOtp(message.ID))
}

function testEmail(world: EpdsWorld): string {
  if (!world.testEmail) throw new Error('No test email set for this scenario')
  return world.testEmail
}

Given(
  'Google reports a verified email for the test user',
  function (this: EpdsWorld) {
    this.googleClaims = verifiedGoogleAccount(testEmail(this))
  },
)

Given(
  "Google's ID token has the {string} claim {string}",
  function (this: EpdsWorld, claim: string, value: string) {
    this.googleClaims = { ...this.googleClaims, [claim]: value }
  },
)

When(
  'a new user signs in with Google using a Gmail address',
  async function (this: EpdsWorld) {
    if (!testEnv.fakeGoogle || !testEnv.mailpitPass) return 'pending'
    this.testEmail = `${uniqueId('google')}@gmail.com`
    this.googleClaims = verifiedGoogleAccount(this.testEmail)
    await signInWithGoogle(this, { claims: this.googleClaims })
  },
)

When('the user signs in with Google', async function (this: EpdsWorld) {
  if (!testEnv.fakeGoogle) return 'pending'
  if (!this.googleClaims) throw new Error('No Google identity set up')
  await signInWithGoogle(this, { claims: this.googleClaims })
})

When(
  'the user signs in with Google but cancels at Google',
  async function (this: EpdsWorld) {
    if (!testEnv.fakeGoogle) return 'pending'
    await signInWithGoogle(this, 'cancel')
  },
)

When(
  'the user enters their email on the demo client and chooses Google',
  async function (this: EpdsWorld) {
    if (!testEnv.fakeGoogle || !testEnv.mailpitPass) return 'pending'
    if (!this.googleClaims) throw new Error('No Google identity set up')
    const email = testEmail(this)
    await clearMailpit(email)
    const page = getPage(this)
    await fakeGoogleBehindRedirects(
      this,
      page,
      (url) =>
        url.origin === new URL(demoBaseUrl).origin &&
        url.pathname === '/api/oauth/login',
      { claims: this.googleClaims },
    )
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', email)
    await page.getByRole('button', { name: 'Sign in with Google' }).click()
  },
)

When(
  'the user signs in with a code sent to that address',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    await signInWithEmailCode(getPage(this), testEmail(this))
  },
)

When(
  'the user later signs in with a code sent to that address',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    this.userDid = await welcomeDid(getPage(this))
    // A new browser, so the sign-in cannot ride on the Google session.
    await resetBrowserContext(this, sharedBrowser)
    const page = getPage(this)
    await page.goto(testEnv.demoUrl)
    await signInWithEmailCode(page, testEmail(this), 'button[type=submit]')
  },
)

Then(
  'Google is asked to show its account chooser for that address',
  function (this: EpdsWorld) {
    const url = this.googleAuthorizeUrl
    if (!url) throw new Error('The browser was never sent to Google')
    expect(url.searchParams.get('prompt')).toBe('select_account')
    expect(url.searchParams.get('login_hint')).toBe(testEmail(this))
  },
)

Then(
  'the auth service sent the browser straight to Google',
  function (this: EpdsWorld) {
    const from = this.googleRedirectedFrom
    if (!from) throw new Error('No redirect to Google was seen')
    expect(from.origin).toBe(new URL(testEnv.authUrl).origin)
    expect(from.pathname).toBe('/oauth/authorize')
    expect(from.searchParams.get('epds_social_provider')).toBe('google')
  },
)

Then(
  'no email code was sent to that address',
  async function (this: EpdsWorld) {
    expect(await countMessages(`to:${testEmail(this)}`)).toBe(0)
  },
)

Then('the browser returns to the login page', async function (this: EpdsWorld) {
  const page = getPage(this)
  await page.waitForURL(
    (url) =>
      url.origin === new URL(testEnv.authUrl).origin &&
      url.pathname === '/oauth/authorize' &&
      url.searchParams.has('epds_social_error'),
    { timeout: 30_000 },
  )
  await expect(page.locator('#step-email')).toBeVisible()
})

Then(
  'the login page asks the user to sign in with an email code instead',
  async function (this: EpdsWorld) {
    await expect(getPage(this).locator('#error-msg')).toContainText(
      'Please sign in with a code sent to your email instead.',
    )
  },
)

Then(
  'the login page says that sign-in was cancelled',
  async function (this: EpdsWorld) {
    await expect(getPage(this).locator('#error-msg')).toContainText(
      'Sign-in was cancelled.',
    )
  },
)

Then('no authenticated session is created', async function (this: EpdsWorld) {
  const page = getPage(this)
  const res = await page.request.get(`${testEnv.authUrl}/api/auth/get-session`)
  expect(res.ok()).toBe(true)
  expect(await res.json()).toBeNull()
})

Then(
  'the demo client is signed in to the same PDS account',
  async function (this: EpdsWorld) {
    if (!this.userDid) throw new Error('No PDS account recorded earlier')
    await assertDemoClientSession(this)
    expect(await welcomeDid(getPage(this))).toBe(this.userDid)
  },
)
