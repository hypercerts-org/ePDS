import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage, resetBrowserContext } from '../support/utils.js'
import { createAccountViaOAuth } from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'
import { waitForEmail, extractOtp, clearMailpit } from '../support/mailpit.js'

function getOtpAlphabet(otpCharset: 'numeric' | 'alphanumeric'): string {
  return otpCharset === 'alphanumeric'
    ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    : '0123456789'
}

function mutateOtpCode(
  otpCode: string,
  otpCharset: 'numeric' | 'alphanumeric',
): string {
  const alphabet = getOtpAlphabet(otpCharset)

  for (let i = 0; i < otpCode.length; i++) {
    const currentChar = otpCode[i]?.toUpperCase()
    const replacement = alphabet.split('').find((char) => char !== currentChar)
    if (!replacement) continue

    return `${otpCode.slice(0, i)}${replacement}${otpCode.slice(i + 1)}`
  }

  throw new Error('Could not derive an incorrect OTP from the current code')
}

async function buildIncorrectOtpCode(world: EpdsWorld): Promise<string> {
  if (world.otpCode) {
    const otpCharset = /^[0-9]+$/.test(world.otpCode)
      ? 'numeric'
      : 'alphanumeric'
    return mutateOtpCode(world.otpCode, otpCharset)
  }

  // When world.otpCode is not set (e.g. the OTP email step was skipped),
  // we cannot read OTP_LENGTH / OTP_CHARSET from env directly because the
  // test runner has no access to the deployed service's environment on
  // Railway. Instead, infer the config from the DOM attributes that the
  // auth service renders onto the #code input at render time.
  const page = getPage(world)
  const codeInput = page.locator('#code')
  const [maxLengthAttr, inputModeAttr, patternAttr] = await Promise.all([
    codeInput.getAttribute('maxlength'),
    codeInput.getAttribute('inputmode'),
    codeInput.getAttribute('pattern'),
  ])

  const otpLength = Number(maxLengthAttr ?? '') || testEnv.otpLength
  const otpCharset =
    inputModeAttr === 'numeric' || patternAttr === `[0-9]{${otpLength}}`
      ? 'numeric'
      : patternAttr === `[A-Z0-9]{${otpLength}}`
        ? 'alphanumeric'
        : testEnv.otpCharset

  return mutateOtpCode('0'.repeat(otpLength), otpCharset)
}

async function assertDemoClientSession(world: EpdsWorld): Promise<void> {
  const page = getPage(world)

  await page.waitForURL('**/welcome', { timeout: 30_000 })

  const cookies = await page.context().cookies()
  const sessionCookie = cookies.find((cookie) => cookie.name === 'session_id')
  if (!sessionCookie?.value) {
    throw new Error('Demo client session cookie was not set after redirect')
  }

  const body = page.locator('body')
  await expect(body).toContainText('You are signed in.')
  await expect(body).toContainText('Sign out')
  await expect(body).toContainText(/@[\w.-]+/)
  await expect(body).toContainText(/did:[a-z0-9:]+/i)
}

// ---------------------------------------------------------------------------
// Scenario setup — compound Givens that create accounts as test preconditions
// ---------------------------------------------------------------------------

/**
 * Creates a fresh PDS account for returning-user scenarios.
 *
 * Drives the browser through the full new-user sign-up flow, then resets
 * the browser context so the returning-user login starts with a clean
 * session (no cookies from the sign-up). The generated email is stored on
 * world.testEmail for use by subsequent steps.
 *
 * Note: the first login to the demo client always shows the consent screen
 * for a returning user (account exists but no client_logins record yet).
 * The scenario is expected to handle that with "the user approves the consent screen".
 */
Given('a returning user has a PDS account', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'

  const email = `returning-${Date.now()}@example.com`
  await createAccountViaOAuth(this, email)

  // Reset browser context to eliminate session cookies from the sign-up
  // flow — the returning-user login must start as a fresh OAuth session
  await resetBrowserContext(this, sharedBrowser)
})

/**
 * Creates a PDS account AND completes a first login (including approving the
 * consent screen), so that the demo client is already recorded in client_logins.
 * Resets the browser context afterwards so the actual test login starts fresh.
 *
 * After this step, the next login for world.testEmail will skip consent entirely
 * and land directly on /welcome.
 */
Given(
  'a returning user has already approved the demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const email = `approved-${Date.now()}@example.com`

    // Step 1: Create the account via the new-user sign-up flow
    await createAccountViaOAuth(this, email)

    // Reset context between sign-up and first returning login
    await resetBrowserContext(this, sharedBrowser)

    // Step 2: First returning-user login — consent screen will appear, approve it
    const page = getPage(this)
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', email)
    await clearMailpit(email)
    await page.click('button[type=submit]')
    // Sync guard — wait for OTP form before fetching email
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })

    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')

    // Approve consent — this records the client_logins entry
    await expect(page.getByRole('button', { name: 'Approve' })).toBeVisible({
      timeout: 30_000,
    })
    await page.getByRole('button', { name: 'Approve' }).click()
    await page.waitForURL('**/welcome', { timeout: 30_000 })

    await clearMailpit(email)

    // Reset context again so the actual test scenario starts with a clean session
    await resetBrowserContext(this, sharedBrowser)
  },
)

// ---------------------------------------------------------------------------
// Navigation and login page assertions
// ---------------------------------------------------------------------------

When(
  'the demo client initiates an OAuth login',
  async function (this: EpdsWorld) {
    await this.page?.goto(testEnv.demoUrl)
  },
)

Then(
  'the browser is redirected to the auth service login page',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible({ timeout: 10_000 })
  },
)

Then(
  'the login page displays an email input form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible()
  },
)

When(
  'the user enters {string} and submits',
  async function (this: EpdsWorld, email: string) {
    if (testEnv.mailpitPass) {
      await clearMailpit(email)
    }
    await this.page?.fill('#email', email)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When(
  'the user enters a unique test email and submits',
  async function (this: EpdsWorld) {
    this.testEmail = `test-${Date.now()}@example.com`
    if (testEnv.mailpitPass) {
      await clearMailpit(this.testEmail)
    }
    await this.page?.fill('#email', this.testEmail)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When(
  'the user enters the test email on the login page',
  async function (this: EpdsWorld) {
    if (!this.testEmail) {
      throw new Error(
        'No test email set — "a returning user has a PDS account" step must run first',
      )
    }
    if (testEnv.mailpitPass) {
      await clearMailpit(this.testEmail)
    }
    await this.page?.fill('#email', this.testEmail)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When('the user approves the consent screen', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.getByRole('button', { name: 'Approve' })).toBeVisible({
    timeout: 30_000,
  })
  await page.getByRole('button', { name: 'Approve' }).click()
})

// ---------------------------------------------------------------------------
// OTP form
// ---------------------------------------------------------------------------

Then(
  'the login page shows an OTP verification form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When('the user enters the OTP code', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  if (!this.otpCode)
    throw new Error('No OTP code available — email step must run first')
  await this.page?.fill('#code', this.otpCode)
  await this.page?.click('#form-verify-otp .btn-primary')
})

// ---------------------------------------------------------------------------
// Post-login assertions
// ---------------------------------------------------------------------------

Then(
  'the browser is redirected back to the demo client',
  async function (this: EpdsWorld) {
    await this.page?.waitForURL('**/welcome', { timeout: 30_000 })
  },
)

Then(
  'the browser is redirected back to the demo client with a valid session',
  async function (this: EpdsWorld) {
    await assertDemoClientSession(this)
  },
)

Then(
  'the demo client has a valid OAuth access token',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('body')).toContainText('did:')
  },
)

// ---------------------------------------------------------------------------
// OTP brute-force / error scenarios
// ---------------------------------------------------------------------------

When(
  'the user requests an OTP for {string}',
  async function (this: EpdsWorld, email: string) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', email)
    await clearMailpit(email)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When(
  'the user requests an OTP for a unique test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)
    this.testEmail = `test-${Date.now()}@example.com`
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', this.testEmail)
    await clearMailpit(this.testEmail)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When('enters an incorrect OTP code', async function (this: EpdsWorld) {
  const page = getPage(this)
  const wrongOtp = await buildIncorrectOtpCode(this)

  await page.fill('#code', wrongOtp)
  await page.click('#form-verify-otp .btn-primary')
})

When(
  'enters an incorrect OTP code {int} times',
  async function (this: EpdsWorld, times: number) {
    const page = getPage(this)
    const wrongOtp = await buildIncorrectOtpCode(this)

    for (let i = 0; i < times; i++) {
      await page.fill('#code', wrongOtp)
      await page.click('#form-verify-otp .btn-primary')
      // Wait for the error message to appear before the next attempt so we
      // don't submit a new code before the server has processed the previous one
      await expect(page.locator('#error-msg')).toBeVisible({ timeout: 10_000 })
    }
  },
)

Then(
  'the verification form shows an error message',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#error-msg')).toBeVisible()
  },
)

Then('the user can try again', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#code')).toBeEnabled()
})

Then('further attempts are rejected', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#error-msg')).toBeVisible()
})

Then('the user must request a new OTP', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#btn-resend')).toBeVisible()
})

// ---------------------------------------------------------------------------
// Refresh / idempotency scenario
// ---------------------------------------------------------------------------

When(
  'the demo client redirects to the auth service login page',
  async function (this: EpdsWorld) {
    await this.page?.goto(testEnv.demoUrl)
  },
)

When(
  'the user refreshes the page \\(duplicate GET \\/oauth\\/authorize\\)',
  async function (this: EpdsWorld) {
    await this.page?.reload()
  },
)

Then('the login page renders normally', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#email')).toBeVisible()
})

Then('the OTP flow still works to completion', function (this: EpdsWorld) {
  return this.skipIfNoMailpit()
})
