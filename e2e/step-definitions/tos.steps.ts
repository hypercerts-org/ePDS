/**
 * Step definitions for the Terms-of-Service acceptance enforcement
 * scenarios in features/security.feature and features/passwordless-authentication.feature.
 *
 * Server-side enforcement lives in packages/auth-service/src/better-auth.ts
 * (enforceTosAcceptance, wired as a hooks.before on better-auth). The unit
 * tests in better-auth-otp.test.ts cover that helper in isolation; these
 * E2E steps exercise it end-to-end against the deployed auth service:
 *
 *   - "new user without tosAccepted" → direct HTTP against
 *     /api/auth/email-otp/send-verification-otp + /api/auth/sign-in/email-otp,
 *     asserting a 400 with the expected error message.
 *
 *   - "returning user without tosAccepted" → creates a real account via
 *     the browser-driven sign-up flow, then drives a fresh sign-in via
 *     direct HTTP with no tosAccepted flag, asserting success.
 *
 *   - "OTP form does not show a ToS checkbox" → DOM assertion that
 *     #tos-field stays hidden on the login page for the returning-user
 *     case (the email step has already left the world on the OTP form).
 */

import { Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage } from '../support/utils.js'
import { clearMailpit, extractOtp, waitForEmail } from '../support/mailpit.js'

const AUTH_BASE = () => `${testEnv.authUrl}/api/auth`

async function sendVerificationOtp(email: string): Promise<void> {
  const res = await fetch(`${AUTH_BASE()}/email-otp/send-verification-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, type: 'sign-in' }),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(
      `send-verification-otp failed: ${res.status} ${text.slice(0, 200)}`,
    )
  }
}

async function signInWithOtp(
  world: EpdsWorld,
  email: string,
  otp: string,
  includeTosAccepted: boolean,
): Promise<void> {
  const body: Record<string, unknown> = { email, otp }
  if (includeTosAccepted) body.tosAccepted = true

  const res = await fetch(`${AUTH_BASE()}/sign-in/email-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  world.lastHttpStatus = res.status
  const text = await res.text()
  try {
    world.lastHttpJson = JSON.parse(text) as Record<string, unknown>
  } catch {
    world.lastHttpJson = { body: text }
  }
}

When(
  'a new user submits a valid OTP code without the tosAccepted flag',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const email = `tos-new-${Date.now()}@example.com`
    this.testEmail = email

    await clearMailpit(email)
    await sendVerificationOtp(email)
    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)

    await signInWithOtp(this, email, otp, false)
  },
)

When(
  'the returning user submits a valid OTP code without the tosAccepted flag',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No testEmail — "a returning user has a PDS account" Given must run first',
      )
    }
    await clearMailpit(this.testEmail)
    await sendVerificationOtp(this.testEmail)
    const message = await waitForEmail(`to:${this.testEmail}`)
    const otp = await extractOtp(message.ID)

    await signInWithOtp(this, this.testEmail, otp, false)
  },
)

Then('the auth service returns a 400 Bad Request', function (this: EpdsWorld) {
  expect(this.lastHttpStatus).toBe(400)
})

Then(
  'the error message is {string}',
  function (this: EpdsWorld, expected: string) {
    const body = this.lastHttpJson ?? {}
    const message = (body as { message?: string }).message
    expect(message).toBe(expected)
  },
)

Then('the sign-in succeeds', function (this: EpdsWorld) {
  expect(this.lastHttpStatus).toBe(200)
})

Then(
  'the OTP form does not show a Terms of Service checkbox',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // The server renders #tos-field into the DOM unconditionally but
    // sets inline display:none for non-new-users; the client-side
    // isNewUser check flips it to block only when isNewUser === true.
    // Assert it's hidden (either absent or display:none).
    const tosField = page.locator('#tos-field')
    await expect(tosField).toBeHidden()
  },
)

Then(
  'the OTP form shows a Terms of Service checkbox',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // Client-side JS flips #tos-field from display:none to display:block
    // once checkIsNewUser confirms isNewUser === true. Wait up to 10s for
    // the Path B new-user-check POST to resolve.
    await expect(page.locator('#tos-field')).toBeVisible({ timeout: 10_000 })
    await expect(page.locator('#tos-accept')).toBeVisible()
  },
)

When(
  'the user submits the OTP code without accepting the Terms of Service',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)

    // The preceding "the user requests an OTP for {string}" step doesn't
    // populate world.otpCode, so fetch it here from the input that was
    // used on the login page — mailpit is keyed by recipient.
    const email = await page.inputValue('#email')
    if (!email) throw new Error('Email input is empty — cannot locate OTP')
    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)
    this.otpCode = otp

    // Deliberately leave #tos-accept unchecked. The client-side gate
    // (if (isNewUser === true && !tosChecked)) would block submit — strip
    // the `required` attribute so the form actually POSTs, letting the
    // server's enforceTosAcceptance hook return the 400 we want to test.
    // Remove the `required` attribute so the form can submit with the
    // checkbox unchecked — letting the server's enforceTosAcceptance hook
    // reject with 400 (the behavior under test).
    await page.evaluate(() => {
      document.getElementById('tos-accept')?.removeAttribute('required')
    })
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')
  },
)

When('the user accepts the Terms of Service', async function (this: EpdsWorld) {
  const page = getPage(this)
  await page.check('#tos-accept')
})

When(
  'the user enters the OTP code from the email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)
    const email = await page.inputValue('#email')
    if (!email) throw new Error('Email input is empty — cannot locate OTP')
    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)
    this.otpCode = otp
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')
  },
)

Then('the sign-in is not completed', async function (this: EpdsWorld) {
  const page = getPage(this)
  // Stay on the login page — never reach /welcome or /auth/choose-handle.
  // Give the browser a moment to process any navigation that might occur.
  await page.waitForTimeout(1500)
  const url = page.url()
  expect(url).not.toMatch(/\/welcome/)
  expect(url).not.toMatch(/\/auth\/choose-handle/)
})
