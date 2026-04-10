/**
 * Step definitions for consent-screen.feature.
 *
 * TODO: The @manual "client branding" scenario is not automated yet —
 * it depends on custom CSS injection being wired into the consent route
 * (renderConsent() needs to accept and apply clientBrandingCss from the
 * client metadata).
 */

import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import {
  getPage,
  resetBrowserContext,
  assertDemoClientSession,
} from '../support/utils.js'
import {
  createAccountViaOAuth,
  startSignUpAwaitingConsent,
} from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'
import { waitForEmail, extractOtp, clearMailpit } from '../support/mailpit.js'

// Steps that drive the untrusted demo client start with an early
// `if (!testEnv.demoUntrustedUrl) return 'pending'` guard. This is
// defence-in-depth for --name invocations: normally these scenarios
// are tagged @untrusted-client and excluded by cucumber.mjs when
// E2E_DEMO_UNTRUSTED_URL is unset, but a user running a single
// scenario by name bypasses tag exclusions, so the step-level guard
// is the only safety net.

// Note: When('the user clicks {string}') lives in common.steps.ts — it is a
// generic UI interaction step used here for "Authorize" and "Deny access" buttons.

Then('a consent screen is displayed', async function (this: EpdsWorld) {
  const page = getPage(this)

  // 1. The Authorize button is the most reliable marker that we're
  //    actually on the consent page (as opposed to e.g. /welcome,
  //    which has no Authorize button).
  await expect(page.getByRole('button', { name: 'Authorize' })).toBeVisible({
    timeout: 30_000,
  })

  // 2. The demo clients request `atproto transition:generic`. For that
  //    scope set, @atproto/oauth-provider-ui's ScopeDescription renders
  //    multiple permission cards — including one titled "Authenticate"
  //    via the RpcMethodsDetails component, which fires on
  //    hasTransitionGeneric. Assert that card is visible: this proves
  //    the scope was actually parsed and rendered a permission summary,
  //    not that the page loaded blank with just an Authorize button.
  //
  //    We deliberately do NOT assert on the raw scope strings
  //    (`atproto`, `transition:generic`) being visible on the page —
  //    those only appear inside a collapsed "Technical details"
  //    <Admonition> panel that is hidden (HTML `hidden` attribute +
  //    aria-hidden="true") until the user clicks its disclosure
  //    button. Asserting on the user-facing scope card is both more
  //    meaningful (what users actually see) and more resilient
  //    (doesn't depend on the details-panel implementation).
  await expect(
    page.getByRole('heading', { name: 'Authenticate' }),
  ).toBeVisible()
})

Then(
  'it identifies the untrusted demo client by its URL host',
  async function (this: EpdsWorld) {
    if (!testEnv.demoUntrustedUrl) return 'pending'
    // @atproto/oauth-provider-ui's <ClientName> component only renders
    // the self-declared client_name for clients listed in
    // PDS_OAUTH_TRUSTED_CLIENTS. For untrusted clients it falls through
    // to <UrlViewer>, which shows the client_id URL's host so users can
    // identify the app by its domain rather than a self-declared name
    // (see packages/oauth/oauth-provider-ui/src/components/utils/client-name.tsx
    // in the atproto repo at version 0.4.3).
    //
    // Asserting the host is present is a security-relevant check: it
    // proves the upstream "untrusted → show URL, not name" guard is
    // working and that the PDS is classifying the demo client as
    // untrusted, exactly as the PDS_OAUTH_TRUSTED_CLIENTS allowlist
    // should be doing.
    const host = new URL(testEnv.demoUntrustedUrl).host

    const page = getPage(this)
    await expect(page.getByText(host)).toBeVisible()
  },
)

When(
  'the untrusted demo client initiates an OAuth login',
  async function (this: EpdsWorld) {
    if (!testEnv.demoUntrustedUrl) return 'pending'
    const page = getPage(this)
    await page.goto(testEnv.demoUntrustedUrl)
  },
)

Then(
  'the browser is redirected back to the untrusted demo client with an auth error',
  async function (this: EpdsWorld) {
    if (!testEnv.demoUntrustedUrl) return 'pending'
    // Per RFC 6749 §4.1.2.1, denying consent causes the authorization
    // server to redirect to the client's redirect_uri with
    // `error=access_denied`. The demo client's callback route sees the
    // `error` query param and translates it to its own `auth_failed`
    // code on its landing page (see
    // packages/demo/src/app/api/oauth/callback/route.ts). By the time
    // waitForURL fires, the browser is already on the final landing
    // page, so we assert against that.
    const origin = new URL(testEnv.demoUntrustedUrl).origin

    const page = getPage(this)
    await page.waitForURL(`${origin}/?error=auth_failed*`, {
      timeout: 30_000,
    })
  },
)

Then('no consent screen is shown', async function (this: EpdsWorld) {
  const page = getPage(this)
  // If no consent screen, the user should have landed directly on /welcome.
  // We check the URL rather than asserting the button is absent, because
  // by the time this step runs the page has already navigated away.
  await page.waitForURL('**/welcome', { timeout: 30_000 })
})

// ---------------------------------------------------------------------------
// Sign-up consent-skip scenarios (trusted vs. untrusted demo clients)
// ---------------------------------------------------------------------------

When(
  'a new user signs up via the trusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const email = `trusted-signup-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email, testEnv.demoTrustedUrl)
  },
)

When(
  'a new user starts signing up via the untrusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.demoUntrustedUrl) return 'pending'
    const email = `untrusted-signup-${Date.now()}@example.com`
    await startSignUpAwaitingConsent(this, email, testEnv.demoUntrustedUrl)
  },
)

Then(
  'the browser is redirected back to the trusted demo client with a valid session',
  async function (this: EpdsWorld) {
    await assertDemoClientSession(this, testEnv.demoTrustedUrl)
  },
)

Then(
  'the browser is redirected back to the untrusted demo client with a valid session',
  async function (this: EpdsWorld) {
    if (!testEnv.demoUntrustedUrl) return 'pending'
    await assertDemoClientSession(this, testEnv.demoUntrustedUrl)
  },
)

/**
 * Exercises the HYPER-270 path: sign up via the untrusted demo,
 * reach the real consent screen (because the untrusted client
 * doesn't satisfy the PDS_SIGNUP_ALLOW_CONSENT_SKIP three-condition
 * check and therefore goes through the normal oauth-provider
 * authorize flow), click Authorize explicitly, land on /welcome,
 * then reset the browser context so the next OAuth flow starts
 * without session cookies. After this Given runs, any persistent
 * grant recorded by the PDS during the Authorize click is the only
 * thing that can stop the return login from showing consent again.
 *
 * Distinct from `a returning user has already approved the demo client`
 * (auth.steps.ts) which uses the trusted demo and relies on the
 * sign-up consent-skip path to auto-authorize, papering over any bug
 * in the click-Authorize grant-recording path.
 */
Given(
  'a returning user has already approved the untrusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.demoUntrustedUrl) return 'pending'

    const email = `approved-untrusted-${Date.now()}@example.com`
    await startSignUpAwaitingConsent(this, email, testEnv.demoUntrustedUrl)

    // Explicitly click Authorize — this is the click that HYPER-270
    // claims does not result in a persistent grant being recorded.
    const page = getPage(this)
    await page.getByRole('button', { name: 'Authorize' }).click()

    // Wait for the demo's /welcome page to confirm the flow
    // completed successfully.
    await page.waitForURL('**/welcome', { timeout: 30_000 })

    // Reset the browser context so the next login starts with no
    // demo-app cookies and no PDS session cookies. If the PDS
    // recorded the grant, the return login will still skip consent;
    // if it didn't, the return login will show consent again
    // (reproducing HYPER-270).
    await resetBrowserContext(this, sharedBrowser)
  },
)

Given(
  'a returning user signed up via the trusted demo client with consent skipped',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const email = `carryover-${Date.now()}@example.com`

    // Sign up via the trusted demo — the consent-skip code path fires
    // server-side because all three conditions hold (PDS flag,
    // PDS_OAUTH_TRUSTED_CLIENTS membership, client metadata opt-in).
    // createAccountViaOAuth waits for /welcome, so reaching this point
    // without a consent screen confirms the skip actually happened.
    await createAccountViaOAuth(this, email, testEnv.demoTrustedUrl)

    // Reset browser context so the second OAuth flow (against a different
    // client) starts without cookies from the sign-up — we want to test
    // whether the SCOPE authorisation carries over, not the browser session.
    await resetBrowserContext(this, sharedBrowser)
  },
)

When(
  'the user later initiates an OAuth login via the untrusted demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.demoUntrustedUrl) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No testEmail on world — the "signed up via the trusted demo client" ' +
          'Given must run first',
      )
    }

    const page = getPage(this)
    // Clear stale OTP emails before firing the new send so waitForEmail
    // below reads the code generated by this flow, not a leftover one.
    await clearMailpit(this.testEmail)

    await page.goto(testEnv.demoUntrustedUrl)
    await page.fill('#email', this.testEmail)
    await page.click('button[type=submit]')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })

    const message = await waitForEmail(`to:${this.testEmail}`)
    const otp = await extractOtp(message.ID)
    await page.fill('#code', otp)
    await page.click('#form-verify-otp .btn-primary')
  },
)
