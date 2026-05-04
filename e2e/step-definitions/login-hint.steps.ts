/**
 * Step definitions for login-hint-resolution.feature.
 *
 * All scenarios depend on the Background "a returning user has a PDS account"
 * step, which populates world.testEmail, world.userHandle, and world.userDid.
 */

import { Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage, resetBrowserContext } from '../support/utils.js'
import { sharedBrowser } from '../support/hooks.js'
import { clearMailpit, extractOtp, waitForEmail } from '../support/mailpit.js'

interface LoginHintOptions {
  /** Raw login_hint value (email, handle, or DID). */
  hint: string
  /** Where the demo client places the hint. Defaults to 'query'. */
  location?: 'query' | 'body'
}

/**
 * Drive the demo client to initiate OAuth with a raw login_hint, bypassing
 * the ?email / ?handle query params so we can exercise email, handle, DID,
 * and "body-only" hint placement uniformly.
 *
 * Hits /api/oauth/login directly — the demo home page doesn't forward
 * query params, and the login route is where rawLoginHint is read.
 *
 * Resets the browser context first — all Background accounts were created
 * through a prior OAuth flow and the session cookie would short-circuit
 * login_hint behavior on the next visit.
 */
async function initiateOAuthWithLoginHint(
  world: EpdsWorld,
  opts: LoginHintOptions,
): Promise<void> {
  if (!testEnv.mailpitPass) {
    throw new Error('initiateOAuthWithLoginHint requires mailpit')
  }
  await resetBrowserContext(world, sharedBrowser)
  const page = getPage(world)
  const location = opts.location ?? 'query'
  const url = new URL('/api/oauth/login', testEnv.demoUrl)
  url.searchParams.set('login_hint', opts.hint)
  url.searchParams.set('login_hint_location', location)
  await page.goto(url.toString())
}

When(
  'the demo client initiates OAuth with the test email as login_hint',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email — "a returning user has a PDS account" step must run first',
      )
    }
    await clearMailpit(this.testEmail)
    await initiateOAuthWithLoginHint(this, { hint: this.testEmail })
  },
)

When(
  'the demo client initiates OAuth with the test handle as login_hint',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userHandle || !this.testEmail) {
      throw new Error(
        'No userHandle/testEmail — "a returning user has a PDS account" step must run first',
      )
    }
    await clearMailpit(this.testEmail)
    await initiateOAuthWithLoginHint(this, { hint: this.userHandle })
  },
)

When(
  'the demo client initiates OAuth with the test DID as login_hint',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userDid || !this.testEmail) {
      throw new Error(
        'No userDid/testEmail — "a returning user has a PDS account" step must run first',
      )
    }
    await clearMailpit(this.testEmail)
    await initiateOAuthWithLoginHint(this, { hint: this.userDid })
  },
)

When(
  'the demo client submits the test handle as login_hint in the PAR body only',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userHandle || !this.testEmail) {
      throw new Error(
        'No userHandle/testEmail — "a returning user has a PDS account" step must run first',
      )
    }
    await clearMailpit(this.testEmail)
    await initiateOAuthWithLoginHint(this, {
      hint: this.userHandle,
      location: 'body',
    })
  },
)

When(
  'the demo client initiates OAuth with an unknown handle as login_hint',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    // A handle that resolves to no account. Must be syntactically valid so
    // the demo's validateHandle check doesn't reject it before PAR.
    await initiateOAuthWithLoginHint(this, {
      hint: `nonexistent-${Date.now()}.pds.test`,
    })
  },
)

Then(
  'the login page renders directly at the OTP verification step',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
    await expect(page.locator('#step-email.hidden')).toBeAttached()
  },
)

Then(
  'an OTP email is auto-sent to the test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error('No testEmail — Background step must run first')
    }
    const message = await waitForEmail(`to:${this.testEmail}`)
    this.lastEmailSubject = message.Subject
    this.otpCode = await extractOtp(message.ID)
  },
)

Then(
  'the login page shows the email input form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible({ timeout: 30_000 })
    await expect(page.locator('#step-otp.active')).toBeHidden()
  },
)
