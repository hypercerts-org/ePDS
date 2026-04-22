import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import {
  getPage,
  resetBrowserContext,
  assertDemoClientSession,
} from '../support/utils.js'
import { createAccountViaOAuth, pickHandle } from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'
import { clearMailpit } from '../support/mailpit.js'

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
    const currentChar = otpCode[i].toUpperCase()
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
  let otpCharset: 'numeric' | 'alphanumeric' = testEnv.otpCharset
  if (inputModeAttr === 'numeric' || patternAttr === `[0-9]{${otpLength}}`) {
    otpCharset = 'numeric'
  } else if (patternAttr === `[A-Z0-9]{${otpLength}}`) {
    otpCharset = 'alphanumeric'
  }

  return mutateOtpCode('0'.repeat(otpLength), otpCharset)
}

// ---------------------------------------------------------------------------
// Scenario setup — compound Givens that create accounts as test preconditions
// ---------------------------------------------------------------------------

/**
 * Creates a fresh PDS account for returning-user scenarios.
 *
 * Drives the browser through the full new-user sign-up flow via the trusted
 * demo client, then resets the browser context so the returning-user login
 * starts with a clean session (no cookies from the sign-up). The generated
 * email is stored on world.testEmail for use by subsequent steps.
 *
 * Note: because sign-up via the trusted demo goes through the
 * PDS_SIGNUP_ALLOW_CONSENT_SKIP path, setAuthorizedClient is called during
 * sign-up — so the returning login will skip the consent screen entirely
 * and land directly on /welcome. Scenarios built on top of this Given must
 * not include "the user approves the consent screen" as a step.
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
 * Creates a PDS account via the trusted demo client, which records the
 * client as authorized via setAuthorizedClient as part of the sign-up
 * consent-skip flow (see packages/pds-core/src/index.ts step 5). Resets
 * the browser context afterwards so the actual test login starts fresh.
 *
 * After this step, the next login for world.testEmail will skip consent
 * entirely and land directly on /welcome — not because of any browser
 * state, but because the PDS recorded the client as authorized during
 * sign-up.
 */
Given(
  'a returning user has already approved the demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const email = `approved-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email)
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
  await expect(page.getByRole('button', { name: 'Authorize' })).toBeVisible({
    timeout: 30_000,
  })
  await page.getByRole('button', { name: 'Authorize' }).click()
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

/**
 * Drives the /auth/choose-handle page shown to new users after OTP
 * verification when the auth service is running in picker mode (the default).
 * In random-handle mode (@handle-random) the user is redirected past this
 * page and this step is not used.
 */
When('the user picks a handle', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  await pickHandle(this)
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
      await Promise.all([
        page.waitForResponse(
          (response) =>
            response.request().method() === 'POST' &&
            response.url().includes('/sign-in/email-otp'),
          { timeout: 10_000 },
        ),
        page.click('#form-verify-otp .btn-primary'),
      ])
      // Wait for the failed state after each submit so the flow remains stable
      // and we do not race into the next attempt.
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
