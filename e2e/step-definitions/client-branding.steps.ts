/**
 * Step definitions for features/client-branding.feature.
 *
 * Exercises the CSS injection path that lets trusted OAuth clients ship a
 * `branding.css` block in their client-metadata.json and have it inlined
 * into the auth-service login page. The untrusted demo client serves the
 * same metadata but is not in PDS_OAUTH_TRUSTED_CLIENTS, so injection must
 * be suppressed — that asymmetry is what these scenarios verify end-to-end.
 */
import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage, resetBrowserContext } from '../support/utils.js'
import { sharedBrowser } from '../support/hooks.js'

// A short, stable fragment from the demo's branding.css. Any substring that
// only the injected CSS would produce works — we pick the dark body bg since
// it's also what makes the visual difference in the comparison scenario.
const INJECTED_CSS_SIGNATURE = 'body { background: #0f172a'

// Default background declared in the auth-service login-page template when
// no branding CSS is injected. Matches demo metadata's `background_color`.
const DEFAULT_LOGIN_BG_RGB = 'rgb(248, 249, 250)' // #f8f9fa

async function waitForLoginPage(world: EpdsWorld): Promise<void> {
  const page = getPage(world)
  await expect(page.locator('#email')).toBeVisible({ timeout: 30_000 })
}

// ---------------------------------------------------------------------------
// Navigation — trusted vs. untrusted demo OAuth start
// ---------------------------------------------------------------------------

When(
  'the trusted demo client initiates an OAuth login',
  async function (this: EpdsWorld) {
    await this.page?.goto(testEnv.demoTrustedUrl)
    await waitForLoginPage(this)
  },
)

// Note: "the untrusted demo client initiates an OAuth login" is already
// defined in consent.steps.ts (it navigates but does not wait for the
// login page to be interactive). "the demo client initiates an OAuth
// login" is defined in auth.steps.ts and targets the trusted demo.
// We reuse both rather than duplicating them here.

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
// Manual / placeholder Givens referenced by the @manual consent scenario.
// Defined so Cucumber doesn't emit "undefined step" warnings on dry runs.
// ---------------------------------------------------------------------------

Given(
  'the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS',
  function (this: EpdsWorld) {
    // Environmental precondition — asserted implicitly by other scenarios
    // that observe CSS injection working. No runtime assertion here.
  },
)
