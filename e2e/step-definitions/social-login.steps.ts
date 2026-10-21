/**
 * Step definitions for social-login.feature (Google sign-in).
 *
 * Google is faked at both ends. The browser's navigation to
 * accounts.google.com is intercepted and redirected straight back to the
 * auth service's /api/auth/callback/google, carrying the scenario's chosen
 * ID token claims as the authorization code (or a cancel). The auth
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
import { clearMailpit, extractOtp, waitForEmail } from '../support/mailpit.js'
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

/**
 * Answer the browser's trip to Google: send it back to the redirect_uri
 * Google was given, with the state, and either an authorization code that
 * carries `claims` or the error Google returns when the user cancels.
 */
async function fakeGoogle(
  page: Page,
  outcome: { claims: Record<string, unknown> } | 'cancel',
): Promise<void> {
  await page.route('https://accounts.google.com/**', async (route) => {
    const request = new URL(route.request().url())
    const back = new URL(request.searchParams.get('redirect_uri') ?? '')
    back.searchParams.set('state', request.searchParams.get('state') ?? '')
    if (outcome === 'cancel') {
      back.searchParams.set('error', 'access_denied')
    } else {
      back.searchParams.set(
        'code',
        Buffer.from(JSON.stringify(outcome.claims)).toString('base64url'),
      )
    }
    await route.fulfill({ status: 302, headers: { location: back.href } })
  })
}

/**
 * Open the auth service's login page for the trusted demo (via its flow 2
 * entry, which lands on the email step) and press "Sign in with Google".
 */
async function signInWithGoogle(
  world: EpdsWorld,
  outcome: { claims: Record<string, unknown> } | 'cancel',
): Promise<void> {
  const page = getPage(world)
  await fakeGoogle(page, outcome)
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
