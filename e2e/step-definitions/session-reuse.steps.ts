/**
 * Step definitions for the HYPER-268 session-reuse scenarios in
 * passwordless-authentication.feature.
 *
 * These exercise the cross-client SSO behaviour: after a user has
 * authenticated once via any OAuth client, a subsequent /oauth/authorize
 * request from a different client in the same browser must not re-trigger
 * the email OTP flow. ePDS should recognise the existing device session
 * and jump straight to the account chooser (flow 2) or directly to consent
 * (flow 1, when a matching login_hint is supplied).
 *
 * Crucially, these steps deliberately do NOT call resetBrowserContext
 * between the first and second OAuth flows — preserving the browser's
 * cookies is the whole point of the test.
 */

import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import {
  createAccountViaOAuth,
  startSignUpAwaitingConsent,
} from '../support/flows.js'
import { countMessages, clearMailpit } from '../support/mailpit.js'

function requireUntrustedDemoUrl(): string {
  const url = testEnv.demoUntrustedUrl
  if (!url) {
    throw new Error(
      'E2E_DEMO_UNTRUSTED_URL is not set — required by HYPER-268 session-reuse ' +
        'scenarios. Set it in e2e/.env (locally) or the workflow (CI).',
    )
  }
  return url
}

// ---------------------------------------------------------------------------
// Given: browser-state setup
// ---------------------------------------------------------------------------

/**
 * Sign the user in via the trusted demo client, then clear the mail
 * trap for that email. Browser context is intentionally NOT reset — the
 * next step will open the untrusted demo in the same context and rely
 * on whatever session state ePDS has set (shared cookie, device session,
 * etc.).
 *
 * After this step: world.testEmail is set, the mail trap for testEmail
 * is empty, and the browser sits on the trusted demo's /welcome page.
 */
Given(
  'the user has just signed in via the trusted demo client in this browser',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    // Reuse an email already set by an earlier Given (e.g. the
    // "already approved the untrusted demo client" precondition),
    // otherwise mint a fresh one.
    const email = this.testEmail ?? `sso-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email, testEnv.demoTrustedUrl)

    // Wipe the mail trap so the subsequent "no new OTP email is sent"
    // assertion starts from a clean baseline — the sign-up above
    // legitimately produced an OTP email, and we don't want that one
    // counted against the second flow.
    await clearMailpit(email)
  },
)

/**
 * Drive a returning-user sign-in via the trusted demo client, preserving
 * the browser context. This is the returning-user counterpart of the
 * "just signed in" Given above, used by scenarios that need to layer a
 * trusted-demo session on top of an *existing* untrusted account created
 * by a prior Given.
 *
 * Preconditions: world.testEmail must already be set (by an earlier Given
 * that created the account, e.g. the "already approved the untrusted demo
 * client" precondition). Calling createAccountViaOAuth with a pre-existing
 * email fails because the account already exists, so this step instead
 * drives the returning-user path: navigate to the trusted demo, enter the
 * existing email, verify the Sign-in OTP, skip consent (because the
 * trusted demo's sign-up has already marked the client as authorized for
 * this user during the original untrusted-client account creation... or
 * because auto-consent is granted to trusted clients).
 *
 * After this step the browser has a fresh device session cookie bound to
 * world.testEmail, and the mail trap for that email has been cleared.
 */
Given(
  'the user has a returning session on the trusted demo client in this browser',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'the user has a returning session on the trusted demo client in this browser: ' +
          'world.testEmail must be set by an earlier Given — this step drives a ' +
          'returning-user sign-in, not a fresh sign-up.',
      )
    }
    const page = getPage(this)
    const email = this.testEmail
    await clearMailpit(email)

    // The pre-approval Given that runs before this one has already
    // bound the user's account to this device's dev-id and left the
    // browser context intact. Starting an OAuth flow on the trusted
    // demo therefore exercises the cross-client session-reuse path:
    // auth-service detects the dev-id cookie and hands off to
    // pds-core/upstream, which renders the chooser for confirmation
    // (no OTP). The trusted client then auto-consents on the existing
    // grant; we still click Authorize defensively in case a consent
    // screen is rendered.
    await page.goto(testEnv.demoTrustedUrl)
    await page.fill('#email', email)
    await page.click('button[type=submit]')

    const pdsHost = new URL(testEnv.pdsUrl).host
    await page.waitForURL(
      (u) => u.host === pdsHost || /\/welcome(\?|$|#)/.test(u.pathname),
      { timeout: 30_000 },
    )
    while (new URL(page.url()).host === pdsHost) {
      await page.waitForLoadState('networkidle', { timeout: 30_000 })
      const authorize = page.getByRole('button', { name: 'Authorize' })
      if (await authorize.count()) {
        await Promise.all([
          page.waitForURL('**/welcome', { timeout: 30_000 }),
          authorize.click({ noWaitAfter: true }),
        ])
        break
      }
      const emailLocator = page.locator(`text=${email}`).first()
      if (await emailLocator.count()) {
        const button = emailLocator
          .locator('xpath=ancestor-or-self::button[1]')
          .first()
        if (await button.count()) await button.click()
        else await emailLocator.click()
      } else {
        await page.locator('#root button').first().click()
      }
      await page.waitForLoadState('networkidle', { timeout: 30_000 })
    }
    if (!/\/welcome(\?|$|#)/.test(new URL(page.url()).pathname)) {
      await page.waitForURL('**/welcome', { timeout: 30_000 })
    }

    // Clear mail trap so the "no new OTP email" assertion starts clean
    // (no OTP should have been sent above, but we clear defensively).
    await clearMailpit(email)
  },
)

/**
 * Variant of consent.steps.ts' "already approved the untrusted demo
 * client" Given that does NOT reset the browser context afterwards.
 * Session-reuse scenarios layer a subsequent trusted-demo sign-in on
 * top of this, and must preserve the mail-trap state and (more
 * importantly) not reset cookies mid-setup.
 */
Given(
  'the user has already approved the untrusted demo client in a prior session',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const untrustedUrl = requireUntrustedDemoUrl()
    const email = `sso-approved-${Date.now()}@example.com`
    await startSignUpAwaitingConsent(this, email, untrustedUrl)

    const page = getPage(this)
    await page.getByRole('button', { name: 'Authorize' }).click()
    await page.waitForURL('**/welcome', { timeout: 30_000 })

    // Browser context is intentionally NOT reset here. The persistent
    // grant created by the Authorize click above is keyed by
    // (sub, clientId) in the authorized_client table, but upstream
    // only finds it via the dev-id cookie (the device row carries the
    // bound DIDs whose authorized_clients are then loaded). Resetting
    // would mint a new dev-id, the device lookup would miss, the
    // chooser wouldn't render, and the "no consent screen on return"
    // assertion this scenario depends on would fail for the wrong
    // reason (lost cookie instead of missing grant). Cross-scenario
    // isolation is provided by the global Before hook in hooks.ts;
    // intra-scenario state must survive.
  },
)

// ---------------------------------------------------------------------------
// When: navigation to the second (untrusted) client
// ---------------------------------------------------------------------------

/**
 * Drive the "flow 2" variant on the untrusted demo client: a single
 * "Sign in" button that redirects straight to the authorization server
 * without a login_hint. This is the flow that should trigger ePDS's
 * account chooser (upstream oauth-provider's /account page) on session
 * reuse.
 *
 * See packages/demo/src/app/flow2/page.tsx for the demo side: the flow2
 * page submits a form to /api/oauth/login with no handle_mode or email,
 * which forwards to /oauth/authorize on the authorization server.
 */
When(
  'the untrusted demo client initiates an OAuth login via flow 2',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const untrustedUrl = requireUntrustedDemoUrl()
    // flow2 is a separate Next.js route on the demo app — no trailing slash.
    const flow2Url = `${untrustedUrl.replace(/\/$/, '')}/flow2`
    await page.goto(flow2Url)
    // flow2 page renders a single sign-in form with no email input.
    // Clicking it posts to /api/oauth/login which 302s to /oauth/authorize.
    await page.click('button[type=submit]')
  },
)

// ---------------------------------------------------------------------------
// Then: OTP suppression
// ---------------------------------------------------------------------------

/**
 * Assert that no new OTP emails have been delivered to the test email
 * since the mail trap was last cleared. Uses a short grace period so
 * an in-flight send is not missed.
 */
Then(
  'no new OTP email is sent to the test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error('No testEmail on world — a sign-in Given must run first')
    }

    // Give any would-be email 3 seconds to arrive before we count.
    // This catches a broken fix that still sends the OTP asynchronously.
    await new Promise((r) => setTimeout(r, 3_000))

    const count = await countMessages(`to:${this.testEmail}`)
    expect(
      count,
      `Expected no new OTP emails for ${this.testEmail}, but found ${count} — ` +
        'the second OAuth flow is still triggering the email OTP path instead ' +
        'of reusing the existing ePDS authentication session (HYPER-268).',
    ).toBe(0)
  },
)

// ---------------------------------------------------------------------------
// Then: account chooser assertions
// ---------------------------------------------------------------------------

/**
 * Assert that the ePDS authorization server is currently rendering the
 * upstream @atproto/oauth-provider account chooser screen. We identify
 * the chooser by two signals:
 *
 *   1. The URL host is pds-core (not auth-service) AND the path is
 *      /account or /oauth/authorize (the upstream middleware may serve
 *      the chooser from either depending on the request shape).
 *   2. The page body contains the React SPA's hydration root (#root
 *      div) with device-session data in its sibling <script> tag.
 *
 * We deliberately DO NOT assert on specific upstream React SPA DOM
 * structure — that bundle is versioned and minified, and selectors
 * could change between upstream releases.
 */
Then('the account chooser is displayed', async function (this: EpdsWorld) {
  const page = getPage(this)

  // Wait for the navigation that produces the chooser to complete.
  await page.waitForLoadState('networkidle', { timeout: 30_000 })

  const url = new URL(page.url())
  const pdsHost = new URL(testEnv.pdsUrl).host
  expect(
    url.host,
    `Account chooser should be served from the pds host (${pdsHost}), ` +
      `but the browser is on ${url.host}. URL: ${page.url()}`,
  ).toBe(pdsHost)

  // The upstream SPA hydrates into #root with __deviceSessions JSON
  // injected as a <script> tag. Both signals together distinguish the
  // chooser from, say, the stock /oauth/authorize error page.
  await expect(page.locator('#root')).toBeAttached({ timeout: 10_000 })
  const html = await page.content()
  expect(
    html.includes('__deviceSessions') || html.includes('deviceSessions'),
    `Expected chooser hydration data on the page but did not find it. ` +
      `URL: ${page.url()}`,
  ).toBe(true)
})

/**
 * Negative counterpart: flow 1 with a login_hint match should skip
 * the chooser entirely (upstream auto-selects the matching session
 * and issues a code directly). Assert that the chooser URL is NOT
 * reached — by the time this step runs the flow should already be
 * on the consent page on pds-core, or onwards.
 */
Then('the account chooser is not displayed', async function (this: EpdsWorld) {
  const page = getPage(this)
  // Give the flow a moment to settle on whatever it lands on.
  await page.waitForLoadState('networkidle', { timeout: 30_000 })
  const html = await page.content()
  expect(
    html.includes('__deviceSessions'),
    'Expected no account chooser, but found device-session hydration data ' +
      `on the page. URL: ${page.url()}`,
  ).toBe(false)
})

/**
 * Assert that the chooser page contains the test email somewhere in
 * its rendered HTML. This is the user-facing test of HYPER-268's
 * email-on-chooser customisation — the upstream SPA doesn't render
 * email by default; ePDS injects it so random handles remain
 * recognisable.
 */
Then(
  'the account chooser displays the test email',
  async function (this: EpdsWorld) {
    if (!this.testEmail) {
      throw new Error('No testEmail on world — a sign-in Given must run first')
    }
    const page = getPage(this)
    // Wait up to 10s for the SPA + ePDS post-hydration script to
    // render the email. We poll the page content rather than looking
    // for a specific DOM node so the assertion is robust to how the
    // script chooses to inject the text.
    await expect
      .poll(
        async () => {
          const html = await page.content()
          return html.includes(this.testEmail!)
        },
        { timeout: 10_000, message: 'Chooser never rendered test email' },
      )
      .toBe(true)
  },
)

/**
 * Click the single account row on the chooser. Upstream's React SPA
 * renders each account as a clickable element — we find it by hunting
 * for the test email text (which ePDS's post-hydration script has
 * attached to the matching row) and clicking the nearest clickable
 * ancestor. If that's too fragile, the next fallback is clicking the
 * first button/list-item under #root.
 */
When(
  'the user confirms their account on the chooser',
  async function (this: EpdsWorld) {
    if (!this.testEmail) {
      throw new Error('No testEmail on world — a sign-in Given must run first')
    }
    const page = getPage(this)
    // Strategy 1: click the element containing the test email text,
    // rolled up to a button/link ancestor.
    const emailLocator = page.locator(`text=${this.testEmail}`).first()
    if (await emailLocator.count()) {
      // Click the button role, or the element itself if no ancestor.
      const button = emailLocator
        .locator('xpath=ancestor-or-self::button[1]')
        .first()
      if (await button.count()) {
        await button.click()
        return
      }
      await emailLocator.click()
      return
    }
    // Fallback: click the first button under #root (the primary
    // account tile in upstream's default chooser layout).
    await page.locator('#root button').first().click()
  },
)

/**
 * Click upstream's "Another account" button on the chooser. The button
 * is rendered by @atproto/oauth-provider-ui with
 * aria-label="Login to account that is not listed". ePDS must intercept
 * the click (upstream swaps to its stock sign-in component client-side)
 * and hard-navigate to the auth-service email/OTP form instead.
 */
When(
  'the user clicks "Another account" on the chooser',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page
      .getByRole('button', { name: 'Login to account that is not listed' })
      .click()
  },
)

// ---------------------------------------------------------------------------
// Then: post-chooser outcomes
// ---------------------------------------------------------------------------

/**
 * Assert the browser has landed on auth-service's email input form —
 * used by the "Another account" scenario to check that the user has
 * been handed off back to the sign-in-as-someone-else path.
 */
Then(
  'the browser is on the auth service email form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible({ timeout: 30_000 })
    const url = new URL(page.url())
    const authHost = new URL(testEnv.authUrl).host
    expect(
      url.host,
      `Expected to be on auth-service host (${authHost}) but got ${url.host}`,
    ).toBe(authHost)
  },
)

/**
 * Strict-form assertions used by the "Another account + login_hint" repro
 * for issue #138: the email form must not carry the previous account's
 * email pre-fill, and the OTP step must not be the active step (the
 * regression rendered the page with both #email and #step-otp.active).
 */
Then('the email input is empty', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#email')).toHaveValue('')
})

Then(
  'the OTP verification step is not active',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#step-otp.active')).toBeHidden()
  },
)

/**
 * Negative assertion for the auto-approve path: the second OAuth flow
 * must complete without the consent screen ever appearing. Checked by
 * looking for the Authorize button on the current page — by the time
 * this step runs, the flow has already landed on the demo's /welcome,
 * so a visible Authorize button can only mean the flow stalled on
 * consent.
 */
Then(
  'no consent screen was shown during the second login',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // After the chooser confirm, upstream still has to issue the
    // authorization code and bounce back to the demo's /welcome —
    // wait for that redirect chain to settle before asserting.
    await page.waitForURL(/\/welcome(\?|$|#)/, { timeout: 30_000 })
    await expect(page.getByRole('button', { name: 'Authorize' })).toHaveCount(0)
  },
)
