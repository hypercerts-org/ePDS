/**
 * Step definitions for atproto-login-button.feature.
 *
 * Exercises the "Or sign in with ATProto/Bluesky" button rendered on
 * the auth-service login page when the OAuth client declares
 * `epds_handle_login_url` in its client metadata.
 *
 * The demo client opts in via packages/demo/src/app/client-metadata.json/route.ts.
 */

import { Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage } from '../support/utils.js'

const ATPROTO_BUTTON_SELECTOR = '.btn-atproto'

// E2E_DEMO_URL may or may not have a trailing slash depending on how it
// was set; strip once here so URL composition and match patterns are
// stable across step definitions.
const demoBaseUrl = testEnv.demoUrl.replace(/\/$/, '')

// Drive the trusted demo client through its flow2 entry point: a plain
// "Sign in" form (no email/handle prefill) that posts to /api/oauth/login
// and lands the browser directly on the auth-service login page. We use
// flow2 (not the demo home page's email form) because we need to land on
// the auth-service login page where the ATProto button lives — the home
// page has its own email form on the demo origin.
When(
  'the demo client initiates an OAuth login via flow 2',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const flow2Url = `${demoBaseUrl}/flow2`
    await page.goto(flow2Url)
    await page.click('button[type=submit]')
    // Wait for the auth-service login page to fully load before letting
    // subsequent steps interact with it. Without this, the click on the
    // ATProto button can land before the inline <script> attaches its
    // listener, so the toggle JS never runs and the input attributes
    // stay in email mode.
    await page.waitForLoadState('networkidle')
  },
)

// Click the ATProto button via its class selector rather than the generic
// "the user clicks {string}" step (which uses getByRole('button', {name})).
// Direct selector gives deterministic locator behaviour across Railway
// preview latency profiles. We don't share `the user clicks {string}` for
// the handle-mode toggle anyway because the button is a label-toggling
// control, not a generic named button.
When(
  'the user clicks the ATProto handle login button',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const btn = page.locator(ATPROTO_BUTTON_SELECTOR)
    await expect(btn).toBeVisible({ timeout: 10_000 })
    await btn.click()
  },
)

Then(
  'the login page displays an {string} button',
  async function (this: EpdsWorld, label: string) {
    const page = getPage(this)
    const btn = page.locator(ATPROTO_BUTTON_SELECTOR)
    await expect(btn).toBeVisible({ timeout: 10_000 })
    await expect(btn).toHaveText(label)
  },
)

Then(
  'the login form input is in handle-entry mode',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const input = page.locator('#email')
    await expect(input).toHaveAttribute('type', 'text')
    await expect(input).toHaveAttribute('name', 'handle')
    await expect(input).toHaveAttribute('placeholder', 'you.bsky.social')
    await expect(page.locator('label[for="email"]')).toHaveText('Handle')
  },
)

Then(
  'the login form input is in email-entry mode',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const input = page.locator('#email')
    await expect(input).toHaveAttribute('type', 'email')
    await expect(input).toHaveAttribute('name', 'email')
    await expect(input).toHaveAttribute('placeholder', 'you@example.com')
    await expect(page.locator('label[for="email"]')).toHaveText(
      'Enter your email address',
    )
  },
)

Then(
  'the button label changes to {string}',
  async function (this: EpdsWorld, label: string) {
    const page = getPage(this)
    await expect(page.locator(ATPROTO_BUTTON_SELECTOR)).toHaveText(label)
  },
)

When(
  'the user enters the handle {string} and submits',
  async function (this: EpdsWorld, handle: string) {
    const page = getPage(this)
    // Intercept the redirect to the demo client's /api/oauth/login route
    // and abort it. The demo route does external handle resolution
    // (handle → DID → PDS) which would either be flaky or require live
    // Bluesky access; we only need to assert the redirect URL shape.
    const expectedUrlPrefix = `${demoBaseUrl}/api/oauth/login`
    this.handleLoginRedirectUrl = undefined
    await page.route(`${expectedUrlPrefix}**`, (route) => {
      this.handleLoginRedirectUrl = route.request().url()
      return route.abort()
    })
    await page.fill('#email', handle)
    await page.click('#form-send-otp button[type=submit]')
  },
)

Then(
  "the browser is navigated to the demo client's handle login URL with handle {string}",
  async function (this: EpdsWorld, handle: string) {
    const page = getPage(this)
    await expect
      .poll(() => this.handleLoginRedirectUrl, { timeout: 10_000 })
      .toBeDefined()
    const current = new URL(this.handleLoginRedirectUrl as string)
    expect(current.origin + current.pathname).toBe(
      `${demoBaseUrl}/api/oauth/login`,
    )
    expect(current.searchParams.get('handle')).toBe(handle)
    // Stop intercepting so subsequent steps in this scenario aren't affected.
    await page.unroute(`${demoBaseUrl}/api/oauth/login**`)
  },
)
