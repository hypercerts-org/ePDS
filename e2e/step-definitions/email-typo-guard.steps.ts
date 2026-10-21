import { randomBytes } from 'node:crypto'
import { Then, When } from '@cucumber/cucumber'
import { expect, type Request } from '@playwright/test'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import type { EpdsWorld } from '../support/world.js'

function isOtpSendRequest(request: Request): boolean {
  const pathname = new URL(request.url()).pathname
  return (
    pathname.endsWith('/email-otp/send-verification-otp') ||
    pathname === '/account/send-otp'
  )
}

function requestEmail(request: Request): string | undefined {
  const body = request.postData()
  if (!body) return undefined

  try {
    const parsed = JSON.parse(body) as { email?: unknown }
    if (typeof parsed.email === 'string') return parsed.email.toLowerCase()
  } catch {
    const email = new URLSearchParams(body).get('email')
    if (email) return email.toLowerCase()
  }
  return undefined
}

function watchOtpSendRequests(world: EpdsWorld): void {
  const page = getPage(world)
  world.otpSendRequestCount = 0
  world.lastOtpRequestEmail = undefined
  page.on('request', (request) => {
    if (!isOtpSendRequest(request)) return
    world.otpSendRequestCount = (world.otpSendRequestCount ?? 0) + 1
    world.lastOtpRequestEmail = requestEmail(request)
  })
}

When(
  'the user enters an email at {string} that should be {string}',
  async function (this: EpdsWorld, typoDomain: string, correctDomain: string) {
    const localPart = `typo-${Date.now()}-${randomBytes(3).toString('hex')}`
    this.emailTypoOriginal = `${localPart}@${typoDomain}`
    this.emailTypoSuggestion = `${localPart}@${correctDomain}`
    watchOtpSendRequests(this)

    const page = getPage(this)
    await page.locator('#email').fill(this.emailTypoOriginal)
  },
)

Then(
  'the corrected-address suggestion appears before any code request',
  async function (this: EpdsWorld) {
    if (!this.emailTypoOriginal || !this.emailTypoSuggestion) {
      throw new Error('No typo email is available — submit a typo first')
    }

    const page = getPage(this)
    const prompt = page.locator('.email-typo-suggestion')
    await expect(prompt).toBeVisible()
    await expect(prompt.locator('[role="status"]')).toHaveText(
      `Did you mean ${this.emailTypoSuggestion}?`,
    )
    await expect(prompt).not.toContainText(this.emailTypoOriginal)
    await expect(prompt.locator('.email-typo-accept')).toHaveText('Yes, fix it')
    await expect(prompt.locator('.email-typo-action')).toHaveCount(1)
    await expect(prompt.locator('.email-typo-dismiss')).toHaveAccessibleName(
      'Dismiss email correction suggestion',
    )
    await expect(page.locator('#email')).toHaveValue(this.emailTypoOriginal)
    expect(this.otpSendRequestCount).toBe(0)
  },
)

Then(
  'the form cannot continue until the user resolves the suggestion',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const submitButton = page.locator('form:has(#email) button[type="submit"]')
    await expect(submitButton).toBeDisabled()

    // The disabled button covers pointer users; the capture-phase guard must
    // also stop implicit keyboard submission while the choice is unresolved.
    await page.locator('#email').press('Enter')
    expect(this.otpSendRequestCount).toBe(0)
    await expect(page.locator('.email-typo-suggestion')).toBeVisible()
  },
)

When(
  'the user accepts the corrected email suggestion',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.locator('.email-typo-accept').click()
  },
)

When(
  'the user dismisses the email correction suggestion',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.locator('.email-typo-dismiss').click()
  },
)

Then(
  'the corrected address replaces the email and Continue is re-enabled',
  async function (this: EpdsWorld) {
    if (!this.emailTypoSuggestion) {
      throw new Error('No corrected email is available — submit a typo first')
    }
    const page = getPage(this)
    await expect(page.locator('#email')).toHaveValue(this.emailTypoSuggestion)
    await expect(page.locator('.email-typo-suggestion')).toBeHidden()
    await expect(
      page.locator('form:has(#email) button[type="submit"]'),
    ).toBeEnabled()
    expect(this.otpSendRequestCount).toBe(0)
  },
)

Then(
  'the original address remains and Continue is re-enabled',
  async function (this: EpdsWorld) {
    if (!this.emailTypoOriginal) {
      throw new Error('No original email is available — submit a typo first')
    }
    const page = getPage(this)
    await expect(page.locator('#email')).toHaveValue(this.emailTypoOriginal)
    await expect(page.locator('.email-typo-suggestion')).toBeHidden()
    await expect(
      page.locator('form:has(#email) button[type="submit"]'),
    ).toBeEnabled()
    expect(this.otpSendRequestCount).toBe(0)
  },
)

When(
  'the user continues from the email form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.locator('form:has(#email) button[type="submit"]').click()
  },
)

Then(
  'one code request targets the corrected email address',
  async function (this: EpdsWorld) {
    if (!this.emailTypoSuggestion) {
      throw new Error('No corrected email is available — submit a typo first')
    }
    await expect.poll(() => this.otpSendRequestCount).toBe(1)
    expect(this.lastOtpRequestEmail).toBe(
      this.emailTypoSuggestion.toLowerCase(),
    )
  },
)

Then(
  'one code request targets the original email address',
  async function (this: EpdsWorld) {
    if (!this.emailTypoOriginal) {
      throw new Error('No original email is available — submit a typo first')
    }
    await expect.poll(() => this.otpSendRequestCount).toBe(1)
    expect(this.lastOtpRequestEmail).toBe(this.emailTypoOriginal.toLowerCase())
  },
)

Then('the email code form is shown', async function (this: EpdsWorld) {
  const page = getPage(this)
  const oauthCodeForm = page.locator('#step-otp.active')
  const accountCodeForm = page.locator('#otp')
  await expect
    .poll(
      async () =>
        (await oauthCodeForm.isVisible()) ||
        (await accountCodeForm.isVisible()),
    )
    .toBe(true)
})

When(
  'the user opens the account settings email sign-in page',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.goto(`${testEnv.authUrl}/account/login`)
    await expect(page.locator('#email')).toBeVisible()
  },
)
