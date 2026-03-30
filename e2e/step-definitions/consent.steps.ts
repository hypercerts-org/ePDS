/**
 * Step definitions for consent-screen.feature.
 *
 * TODO: Scenario 5 (consent page shows client branding) is tagged @manual.
 * Automate once custom CSS injection is merged into the consent route
 * (renderConsent() needs to accept and apply clientBrandingCss from client metadata).
 */

import { Then } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { EpdsWorld } from '../support/world.js'
import { getPage } from '../support/utils.js'

// Note: When('the user clicks {string}') lives in common.steps.ts — it is a
// generic UI interaction step used here for "Approve" and "Deny" buttons.

Then('a consent screen is displayed', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.getByRole('button', { name: 'Approve' })).toBeVisible({
    timeout: 30_000,
  })
})

Then("it shows the demo client's name", async function (this: EpdsWorld) {
  // The consent page renders "<client_name> wants to access your account"
  // in the .subtitle element. Assert it contains non-trivial text (not blank).
  const page = getPage(this)
  const subtitle = page.locator('.subtitle')
  await expect(subtitle).toBeVisible()
  const text = await subtitle.innerText()
  if (!text.trim()) {
    throw new Error('Consent screen subtitle is empty — expected client name')
  }
})

Then(
  'the browser is redirected to the PDS with an access_denied error',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // Deny redirects to <PDS>/oauth/authorize?request_uri=...&error=access_denied
    await page.waitForURL('**/oauth/authorize**error=access_denied**', {
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
