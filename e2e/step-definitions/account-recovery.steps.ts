/**
 * Step definitions for account-recovery.feature.
 *
 * These scenarios layer on top of the existing account-settings and
 * login-hint steps. Backup emails are seeded through the real UI
 * (add → click verification link) so we exercise the same code path
 * real users go through — there is no internal API to fast-seed them.
 */

import * as crypto from 'node:crypto'

import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage, resetBrowserContext } from '../support/utils.js'
import { sharedBrowser } from '../support/hooks.js'
import {
  clearMailpit,
  extractOtp,
  fetchEmailBody,
  mailpitAuthHeader,
  waitForEmail,
} from '../support/mailpit.js'

/** Poll Mailpit for up to timeoutMs looking for an email; return true iff none arrives. */
async function assertNoEmailFor(
  recipient: string,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const res = await fetch(
      `${testEnv.mailpitUrl}/api/v1/search?query=${encodeURIComponent(`to:${recipient}`)}&limit=1`,
      { headers: { Authorization: mailpitAuthHeader() } },
    )
    if (res.ok) {
      const body = (await res.json()) as { messages?: unknown[] }
      if (body.messages && body.messages.length > 0) {
        throw new Error(
          `Expected no email for ${recipient}, but one arrived within ${timeoutMs}ms`,
        )
      }
    }
    await new Promise((r) => setTimeout(r, 500))
  }
}

/**
 * Characters that commonly trail a URL in an email body (punctuation,
 * quote marks, angle brackets from quoted-printable). Each must be
 * stripped from the end of the captured URL before navigation.
 */
const URL_TRAILING_JUNK = new Set(['.', '>', '"', "'", ','])

/**
 * Extract the first backup-email verification URL from an email body and
 * strip any trailing punctuation. Implemented with a while loop rather
 * than a trailing-anchored regex to avoid tripping Sonar's ReDoS rule —
 * input is already bounded by the preceding \S+ match, but the loop makes
 * the linear-time behaviour syntactically obvious.
 */
function extractVerifyUrl(body: string): string | null {
  const linkMatch =
    /https?:\/\/\S*\/account\/backup-email\/verify\?token=\S+/.exec(body)
  if (!linkMatch) return null
  let url = linkMatch[0]
  while (url.length > 0 && URL_TRAILING_JUNK.has(url[url.length - 1] ?? '')) {
    url = url.slice(0, -1)
  }
  return url
}

/**
 * Add a unique backup email, click the verification link, confirm.
 * Assumes the account-settings page is already loaded.
 */
async function addAndVerifyBackupEmail(world: EpdsWorld): Promise<string> {
  const page = getPage(world)
  const backupEmail = `backup-${Date.now()}-${crypto.randomBytes(4).toString('hex')}@example.com`
  world.backupEmail = backupEmail
  await clearMailpit(backupEmail)

  const backupForm = page.locator('form[action="/account/backup-email/add"]')
  await backupForm.locator('input[name="email"]').fill(backupEmail)
  await Promise.all([
    page.waitForURL(
      (url) =>
        url.origin === testEnv.authUrl &&
        url.pathname === '/account' &&
        url.searchParams.get('success') === 'backup_added',
    ),
    backupForm.getByRole('button', { name: 'Add backup email' }).click(),
  ])

  const message = await waitForEmail(`to:${backupEmail}`)
  const body = await fetchEmailBody(message.ID)
  const verifyUrl = extractVerifyUrl(body)
  if (!verifyUrl) {
    throw new Error('No verification link in backup email body')
  }

  await page.goto(verifyUrl)
  await Promise.all([
    page.waitForURL(
      (url) =>
        url.origin === testEnv.authUrl &&
        url.pathname === '/account' &&
        url.searchParams.get('success') === 'backup_verified',
    ),
    page.getByRole('button', { name: 'Confirm verification' }).click(),
  ])

  return backupEmail
}

When(
  'the user clicks the verification link in that email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.lastEmailBody) {
      throw new Error(
        'No email body captured — verification email arrival step must run first',
      )
    }
    const verifyUrl = extractVerifyUrl(this.lastEmailBody)
    if (!verifyUrl) {
      throw new Error('No verification link in captured email body')
    }
    const page = getPage(this)
    await page.goto(verifyUrl)
    await Promise.all([
      page.waitForURL(
        (url) =>
          url.origin === testEnv.authUrl &&
          url.pathname === '/account' &&
          url.searchParams.get('success') === 'backup_verified',
      ),
      page.getByRole('button', { name: 'Confirm verification' }).click(),
    ])
  },
)

Then(
  'the backup email is marked as verified on the account settings page',
  async function (this: EpdsWorld) {
    if (!this.backupEmail) {
      throw new Error('No backupEmail set — add-backup step must run first')
    }
    const page = getPage(this)
    const row = page
      .locator('.setting-row')
      .filter({ hasText: this.backupEmail })
    await expect(row).toContainText('(verified)', { timeout: 10_000 })
  },
)

Given(
  'the test user has a verified backup email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No testEmail — "a returning user has a PDS account" step must run first',
      )
    }
    // Log in to /account via OTP, then seed a verified backup email.
    // Reset first so getPage() returns a live page on the fresh context —
    // capturing it before reset leaves a stale reference to the closed page.
    await resetBrowserContext(this, sharedBrowser)
    const page = getPage(this)
    await page.goto(`${testEnv.authUrl}/account`)
    await clearMailpit(this.testEmail)
    await page.fill('#email', this.testEmail)
    await page.getByRole('button', { name: 'Continue with email' }).click()
    await expect(page.locator('#otp')).toBeVisible({ timeout: 30_000 })
    const message = await waitForEmail(`to:${this.testEmail}`)
    const otp = await extractOtp(message.ID)
    await page.fill('#otp', otp)
    await page.getByRole('button', { name: 'Verify' }).click()
    await expect(page).toHaveURL(new RegExp(`${testEnv.authUrl}/account`))
    await addAndVerifyBackupEmail(this)
  },
)

When(
  'the user navigates to the recovery page',
  async function (this: EpdsWorld) {
    // PR 110 removed the #recovery-link from the login page — recovery is
    // no longer reachable from the OAuth login flow's UI, only via direct
    // navigation. The auth_flow cookie set by the prior OAuth step carries
    // the real request_uri used for the back-link; the URL's request_uri
    // here is just a placeholder so the route's required-param check passes.
    const page = getPage(this)
    await page.goto(
      `${testEnv.authUrl}/auth/recover?request_uri=urn:ietf:params:oauth:request_uri:placeholder`,
    )
  },
)

When(
  'the user enters the backup email on the recovery page',
  async function (this: EpdsWorld) {
    if (!this.backupEmail) {
      throw new Error(
        'No backupEmail set — "the test user has a verified backup email" step must run first',
      )
    }
    const page = getPage(this)
    await clearMailpit(this.backupEmail)
    await page.fill('input[name="email"]', this.backupEmail)
    await page.getByRole('button', { name: 'Send recovery code' }).click()
  },
)

When(
  'the user enters a random non-existent email on the recovery page',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const nonExistent = `nonexistent-${Date.now()}@example.com`
    this.backupEmail = nonExistent
    await clearMailpit(nonExistent)
    await page.fill('input[name="email"]', nonExistent)
    await page.getByRole('button', { name: 'Send recovery code' }).click()
  },
)

Then(
  'an OTP email arrives in the mail trap for the backup email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.backupEmail) {
      throw new Error('No backupEmail set — recovery email step must run first')
    }
    const message = await waitForEmail(`to:${this.backupEmail}`)
    this.lastEmailSubject = message.Subject
    this.otpCode = await extractOtp(message.ID)
  },
)

When('the user enters the recovery OTP', async function (this: EpdsWorld) {
  if (!this.otpCode) {
    throw new Error(
      'No otpCode captured — recovery OTP email step must run first',
    )
  }
  const page = getPage(this)
  await page.fill('input[name="code"]', this.otpCode)
  await page.getByRole('button', { name: 'Verify' }).click()
})

Then('the recovery OTP form is displayed', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('input[name="code"]')).toBeVisible({
    timeout: 30_000,
  })
  await expect(page.getByRole('button', { name: 'Verify' })).toBeVisible()
})

Then(
  'no email arrives for that non-existent address',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.backupEmail) {
      throw new Error('No backupEmail set — non-existent step must run first')
    }
    await assertNoEmailFor(this.backupEmail)
  },
)

When(
  'the user removes the backup email from account settings',
  async function (this: EpdsWorld) {
    if (!this.backupEmail) {
      throw new Error(
        'No backupEmail set — "the test user has a verified backup email" step must run first',
      )
    }
    const page = getPage(this)
    // Return to /account in case previous step navigated elsewhere.
    if (!page.url().startsWith(`${testEnv.authUrl}/account`)) {
      await page.goto(`${testEnv.authUrl}/account`)
    }
    const removeForm = page
      .locator('form[action="/account/backup-email/remove"]')
      .filter({ has: page.locator(`input[value="${this.backupEmail}"]`) })
    await Promise.all([
      page.waitForURL(
        (url) => url.origin === testEnv.authUrl && url.pathname === '/account',
      ),
      removeForm.getByRole('button', { name: 'Remove' }).click(),
    ])
  },
)

Then(
  'the backup email no longer appears on the account settings page',
  async function (this: EpdsWorld) {
    if (!this.backupEmail) {
      throw new Error('No backupEmail set — remove step must run first')
    }
    const page = getPage(this)
    await expect(
      page.locator('.setting-row').filter({ hasText: this.backupEmail }),
    ).toHaveCount(0)
  },
)

Then(
  'recovery via the removed backup email no longer works',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.backupEmail) {
      throw new Error('No backupEmail set — remove step must run first')
    }
    // Hit /auth/recover directly (without a live auth flow) and submit the
    // removed email. The route always shows the OTP form (anti-enumeration),
    // but we can verify no recovery OTP email is actually sent.
    const page = getPage(this)
    await clearMailpit(this.backupEmail)
    await page.goto(
      `${testEnv.authUrl}/auth/recover?request_uri=urn:ietf:params:oauth:request_uri:no-flow`,
    )
    await page.fill('input[name="email"]', this.backupEmail)
    await page.getByRole('button', { name: 'Send recovery code' }).click()
    await expect(page.locator('input[name="code"]')).toBeVisible({
      timeout: 30_000,
    })
    await assertNoEmailFor(this.backupEmail)
  },
)
