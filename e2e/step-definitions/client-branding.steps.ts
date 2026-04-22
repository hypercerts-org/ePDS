/**
 * Step definitions for features/client-branding.feature.
 *
 * Exercises the CSS injection path that lets trusted OAuth clients ship a
 * `branding.css` block in their client-metadata.json and have it inlined
 * into the auth-service login page. The untrusted demo client serves the
 * same metadata but is not in PDS_OAUTH_TRUSTED_CLIENTS, so injection must
 * be suppressed — that asymmetry is what these scenarios verify end-to-end.
 */
import * as crypto from 'node:crypto'
import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage, resetBrowserContext } from '../support/utils.js'
import { sharedBrowser } from '../support/hooks.js'
import { startSignUpAwaitingConsent } from '../support/flows.js'
import { waitForEmail, extractOtp, clearMailpit } from '../support/mailpit.js'

// A short, stable fragment from the demo's branding.css. Any substring that
// only the injected CSS would produce works — we pick the dark body bg since
// it's also what makes the visual difference in the comparison scenario.
const INJECTED_CSS_SIGNATURE = 'body { background: #1a1208'

// Default background declared in the auth-service login-page template when
// no branding CSS is injected. Matches demo metadata's `background_color`.
const DEFAULT_LOGIN_BG_RGB = 'rgb(248, 249, 250)' // #f8f9fa

async function waitForLoginPage(world: EpdsWorld): Promise<void> {
  const page = getPage(world)
  // Wait for auth-service-specific element — #step-otp only exists on
  // the auth-service login page, not the demo app. Use toBeAttached
  // rather than toBeVisible because #step-otp may be hidden (no
  // 'active' class) if the email step is showing, and #step-email may
  // be hidden if the OTP step is showing (login_hint provided).
  await expect(page.locator('#step-otp')).toBeAttached({ timeout: 30_000 })
}

/**
 * Navigate through a demo app to reach the auth-service login page.
 *
 * The demo's home page and the auth-service login page both have an
 * #email input, so waiting for #email alone is ambiguous. This helper
 * submits the demo's email form with a dummy address, which triggers
 * the OAuth PAR + redirect to the auth-service. We then wait for the
 * auth-service-specific #step-email element to confirm we've arrived.
 */
async function navigateToAuthLoginPage(
  world: EpdsWorld,
  demoUrl: string,
): Promise<void> {
  const page = getPage(world)
  await page.goto(demoUrl)
  await expect(page.locator('#email')).toBeVisible({ timeout: 30_000 })
  // Fill a dummy email and submit to trigger the OAuth redirect.
  // The email doesn't need to be real — we only need to reach the
  // auth-service login page, not complete the OTP flow.
  await page.fill('#email', `css-test-${Date.now()}@example.com`)
  await page.click('button[type=submit]')
  // Wait for the auth-service login page — #step-otp is specific to
  // the auth-service and does not exist on the demo page. Use
  // toBeAttached because the OTP step may be immediately active
  // (email provided via login_hint) or hidden (email step showing).
  await expect(page.locator('#step-otp')).toBeAttached({ timeout: 30_000 })
}

// ---------------------------------------------------------------------------
// Navigation — trusted vs. untrusted demo OAuth start
// ---------------------------------------------------------------------------

When(
  'the trusted demo client initiates an OAuth login',
  async function (this: EpdsWorld) {
    await navigateToAuthLoginPage(this, testEnv.demoTrustedUrl)
  },
)

When(
  'the untrusted demo client initiates an OAuth login to the auth service',
  async function (this: EpdsWorld) {
    if (!testEnv.demoUntrustedUrl) return 'pending'
    await navigateToAuthLoginPage(this, testEnv.demoUntrustedUrl)
  },
)

// ---------------------------------------------------------------------------
// HTML-level assertions — <style> tag content
// ---------------------------------------------------------------------------

Then(
  "the login page HTML contains the trusted client's custom CSS",
  async function (this: EpdsWorld) {
    await waitForLoginPage(this)
    const html = await getPage(this).content()
    expect(html).toContain(INJECTED_CSS_SIGNATURE)
  },
)

Then(
  "the login page HTML does not contain the trusted client's custom CSS",
  async function (this: EpdsWorld) {
    await waitForLoginPage(this)
    const html = await getPage(this).content()
    expect(html).not.toContain(INJECTED_CSS_SIGNATURE)
  },
)

Then(
  'the login page body uses the default background color',
  async function (this: EpdsWorld) {
    await waitForLoginPage(this)
    const bg = await getPage(this)
      .locator('body')
      .evaluate((el) => getComputedStyle(el).backgroundColor)
    expect(bg).toBe(DEFAULT_LOGIN_BG_RGB)
  },
)

// ---------------------------------------------------------------------------
// Visual-difference assertion — computed background colors differ
// ---------------------------------------------------------------------------

When(
  'the login page body background color is captured as {string}',
  async function (this: EpdsWorld, label: string) {
    await waitForLoginPage(this)
    const bg = await getPage(this)
      .locator('body')
      .evaluate((el) => getComputedStyle(el).backgroundColor)
    const store = (this.capturedBgColors ??= {})
    store[label] = bg
  },
)

When('the browser session is reset', async function (this: EpdsWorld) {
  await resetBrowserContext(this, sharedBrowser)
})

Then(
  'the captured {string} and {string} background colors differ',
  function (this: EpdsWorld, a: string, b: string) {
    const store = this.capturedBgColors ?? {}
    const colorA = store[a]
    const colorB = store[b]
    expect(colorA, `no background color captured for "${a}"`).toBeTruthy()
    expect(colorB, `no background color captured for "${b}"`).toBeTruthy()
    expect(
      colorA,
      `expected "${a}" (${colorA}) and "${b}" (${colorB}) to differ`,
    ).not.toBe(colorB)
  },
)

// ---------------------------------------------------------------------------
// Generic HTML-level CSS assertion (works on any auth-service page)
// ---------------------------------------------------------------------------

Then(
  "the page HTML contains the trusted client's custom CSS",
  async function (this: EpdsWorld) {
    const html = await getPage(this).content()
    expect(html).toContain(INJECTED_CSS_SIGNATURE)
  },
)

// ---------------------------------------------------------------------------
// Choose-handle page CSS injection
// ---------------------------------------------------------------------------

When(
  'a new user reaches the handle selection page via the trusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const page = getPage(this)
    const email = `css-handle-${Date.now()}@example.com`
    await clearMailpit(email)

    await page.goto(testEnv.demoTrustedUrl)
    await page.fill('#email', email)
    await page.click('button[type=submit]')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })

    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')

    // Wait for the choose-handle page — don't submit the handle form
    await page.waitForURL('**/auth/choose-handle', { timeout: 30_000 })
  },
)

// ---------------------------------------------------------------------------
// Recovery page CSS injection
// ---------------------------------------------------------------------------

When(
  'a user navigates to the account recovery page via the trusted demo client',
  async function (this: EpdsWorld) {
    // Navigate to the auth-service login page via the trusted demo,
    // which creates an auth flow with the trusted client_id.
    await navigateToAuthLoginPage(this, testEnv.demoTrustedUrl)

    const page = getPage(this)
    // The recovery link is visible when the OTP step is showing
    await expect(page.locator('#recovery-link')).toBeVisible({
      timeout: 10_000,
    })
    await page.click('#recovery-link')
    // Wait for the recovery page to load
    await page.waitForURL('**/auth/recover**', { timeout: 30_000 })
  },
)

// ---------------------------------------------------------------------------
// PDS-core consent-page CSS injection (trusted client on /oauth/authorize)
// ---------------------------------------------------------------------------

// Sign up via the untrusted demo to create an account without triggering
// the consent-skip path. This gives us an existing user who has never
// approved the trusted demo client — so the next login via the trusted
// demo will hit the stock /oauth/authorize consent UI, where the pds-core
// CSS-injection middleware can be exercised.
Given(
  'a user has signed up via the untrusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.demoUntrustedUrl) return 'pending'

    const email = `css-consent-${Date.now()}@example.com`
    await startSignUpAwaitingConsent(this, email, testEnv.demoUntrustedUrl)

    // Click Authorize on the untrusted demo's consent screen
    const page = getPage(this)
    await page.getByRole('button', { name: 'Authorize' }).click()
    await page.waitForURL('**/welcome', { timeout: 30_000 })

    // Reset browser so the next login starts clean
    await resetBrowserContext(this, sharedBrowser)
  },
)

// Log into the trusted demo as an existing user. Since the user has never
// approved the trusted client, this will show the stock /oauth/authorize
// consent page — exactly the surface where pds-core injects CSS for
// trusted clients.
When(
  'the user logs into the trusted demo client for the first time',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No testEmail on world — the "signed up via untrusted" Given must run first',
      )
    }

    const page = getPage(this)
    await clearMailpit(this.testEmail)

    await page.goto(testEnv.demoTrustedUrl)
    await page.fill('#email', this.testEmail)
    await page.click('button[type=submit]')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })

    const message = await waitForEmail(`to:${this.testEmail}`)
    const otp = await extractOtp(message.ID)
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')

    // Wait for the consent screen's Authorize button — this is the
    // stock @atproto/oauth-provider consent UI served by pds-core at
    // /oauth/authorize. The pds-core CSS-injection middleware should
    // have modified this response.
    await expect(page.getByRole('button', { name: 'Authorize' })).toBeVisible({
      timeout: 30_000,
    })
  },
)

Then(
  "the consent page HTML contains the trusted client's custom CSS",
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const html = await page.content()
    expect(html).toContain(INJECTED_CSS_SIGNATURE)
  },
)

Then(
  'the Content-Security-Policy style-src directive includes the CSS SHA-256 hash',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // The pds-core middleware computes SHA-256 of the injected CSS and
    // appends it to the CSP style-src directive as 'sha256-<base64>'.
    // We compute the same hash from the known CSS signature to verify.
    const html = await page.content()

    // Find the injected <style> tag (not the first one, which may be
    // the upstream oauth-provider's own styles)
    const styleMatches = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)]
    const injectedStyle = styleMatches.find(([, css]) =>
      css.includes(INJECTED_CSS_SIGNATURE),
    )
    if (!injectedStyle) {
      throw new Error(
        'Injected client CSS <style> tag not found in consent page HTML',
      )
    }
    const cssContent = injectedStyle[1]

    // Compute SHA-256 hash the same way the middleware does
    const hash = crypto.createHash('sha256').update(cssContent).digest('base64')
    const expectedDirective = `'sha256-${hash}'`

    // Read the CSP header from the page's response. Playwright doesn't
    // expose response headers on page.content(), so we check the <meta>
    // http-equiv="Content-Security-Policy" tag that @atproto/oauth-provider
    // renders, or fall back to checking the response header via a
    // fresh fetch.
    const cspMeta = await page
      .locator('meta[http-equiv="Content-Security-Policy"]')
      .getAttribute('content')
      .catch(() => null)

    if (cspMeta) {
      expect(cspMeta).toContain(expectedDirective)
    } else {
      // Fall back: fetch the current URL and check the response header
      const response = await page.context().request.get(page.url())
      const cspHeader = response.headers()['content-security-policy'] ?? ''
      expect(cspHeader).toContain(expectedDirective)
    }
  },
)
