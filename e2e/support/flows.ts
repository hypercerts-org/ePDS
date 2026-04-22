/**
 * Reusable browser-driven flows used by step definitions as setup helpers.
 *
 * These are plain async functions, not Cucumber step definitions. They drive
 * real browser interactions and should only be called from step definitions
 * after checking testEnv.mailpitPass where relevant.
 */

import crypto from 'node:crypto'
import { expect } from '@playwright/test'
import type { EpdsWorld } from './world.js'
import { testEnv } from './env.js'
import { waitForEmail, extractOtp, clearMailpit } from './mailpit.js'

/**
 * Generate a valid handle local part for a new test account.
 *
 * 10 lowercase hex chars: satisfies the server's 5–20 `[a-z0-9-]` rule
 * (no leading/trailing hyphens, since hex has no hyphens at all) and the
 * narrower `[a-z0-9]{4,20}` pattern the e2e tests assert elsewhere.
 * Collision probability across a test run is negligible (40 bits of entropy).
 */
function generateHandleLocalPart(): string {
  return crypto.randomBytes(5).toString('hex')
}

/**
 * Drive the /auth/choose-handle page: wait for it, generate and fill a valid
 * local part, wait for the client-side availability check to confirm
 * "available", then click Create.
 *
 * Exported so that both createAccountViaOAuth (setup-time, inside a Given)
 * and the active-scenario "When the user picks a handle" step (inside the
 * passwordless-authentication "new user" scenario) can share the same
 * implementation without duplication.
 *
 * The availability check is debounced client-side at 500ms, so waiting for
 * the `.status.available` text (not just the submit button state) is the
 * only race-free way to know it's safe to click Create.
 */
export async function pickHandle(world: EpdsWorld): Promise<void> {
  const page = world.page
  if (!page) throw new Error('page is not initialised')

  await page.waitForURL('**/auth/choose-handle', { timeout: 30_000 })
  const localPart = generateHandleLocalPart()
  await page.fill('#handle-input', localPart)
  await expect(page.locator('#handle-status.available')).toBeVisible({
    timeout: 10_000,
  })
  await page.click('#submit-btn')
}

/**
 * Drive the full new-user OAuth sign-up flow through a demo app.
 *
 * The default auth-service config has `handleMode='picker'`, so after OTP
 * verification the user is redirected to /auth/choose-handle and must pick a
 * handle before being returned to the demo /welcome page. Random-handle mode
 * (where the picker is skipped automatically) would need a different auth-
 * service config and is intentionally not exercised here.
 *
 * The `demoUrl` parameter defaults to the trusted demo client so existing
 * callers that pass only (world, email) keep working unchanged. Consent-skip
 * scenarios that need to drive the untrusted demo client pass
 * `testEnv.demoUntrustedUrl` explicitly.
 *
 * Steps:
 *   1. Navigate to demoUrl
 *   2. Fill #email with the provided email, submit
 *   3. Wait for #step-otp.active (30 s)
 *   4. Fetch OTP from Mailpit via waitForEmail + extractOtp
 *   5. Fill #code with OTP, click #form-verify-otp .btn-primary
 *   6. Wait for /auth/choose-handle, fill #handle-input with a generated
 *      local part, wait for the availability check to confirm "available",
 *      then click #submit-btn
 *   7. Wait for URL matching "**\/welcome" (30 s)
 *   8. Capture DID and handle from page body text
 *   9. Store testEmail, userDid, and userHandle on the world
 *  10. Clear Mailpit inbox for the email
 *
 * Callers must check testEnv.mailpitPass before calling this function.
 */
/**
 * Drive the new-user OAuth sign-up flow up to — but not through — the
 * consent screen. Used by consent-screen scenarios that need to assert
 * the consent screen's contents (and then click Authorize themselves)
 * rather than breezing past it via createAccountViaOAuth.
 *
 * Intended for untrusted demo clients: trusted clients skip consent
 * entirely on sign-up (see packages/pds-core/src/index.ts step 5) and
 * would land on /welcome instead of the consent screen, so calling this
 * against a trusted client will time out on the Authorize button wait.
 *
 * Stores testEmail on the world so later steps can refer back to the
 * same user.
 *
 * Callers must check testEnv.mailpitPass before calling this function.
 */
export async function startSignUpAwaitingConsent(
  world: EpdsWorld,
  email: string,
  demoUrl: string,
): Promise<void> {
  const page = world.page
  if (!page) throw new Error('page is not initialised')

  await clearMailpit(email)

  await page.goto(demoUrl)
  await page.fill('#email', email)
  await page.click('button[type=submit]')
  await expect(page.locator('#step-otp.active')).toBeVisible({
    timeout: 30_000,
  })

  const message = await waitForEmail(`to:${email}`)
  const otp = await extractOtp(message.ID)
  await page.fill('#code', otp)
  await page.click('#form-verify-otp .btn-primary')

  await pickHandle(world)

  // Wait for the consent screen's Authorize button. The subsequent
  // "a consent screen is displayed" step will do a stronger assertion
  // (scopes, preamble); this wait is just a sync guard so the caller
  // is guaranteed to be on the consent page before the next step runs.
  await expect(page.getByRole('button', { name: 'Authorize' })).toBeVisible({
    timeout: 30_000,
  })

  world.testEmail = email
}

export async function createAccountViaOAuth(
  world: EpdsWorld,
  email: string,
  demoUrl: string = testEnv.demoTrustedUrl,
): Promise<{ did: string; handle: string | undefined }> {
  const page = world.page
  if (!page) throw new Error('page is not initialised')

  // Clear stale OTP emails so waitForEmail reads the code sent by this submit.
  await clearMailpit(email)

  await page.goto(demoUrl)
  await page.fill('#email', email)
  await page.click('button[type=submit]')
  // Sync guard — wait for OTP form to be visible before fetching email
  await expect(page.locator('#step-otp.active')).toBeVisible({
    timeout: 30_000,
  })

  const message = await waitForEmail(`to:${email}`)
  const otp = await extractOtp(message.ID)
  await page.fill('#code', otp)
  await page.click('#form-verify-otp .btn-primary')

  // Pick a handle on the /auth/choose-handle page. The handle-picking logic
  // is shared with the "When the user picks a handle" step definition.
  await pickHandle(world)

  await page.waitForURL('**/welcome', { timeout: 30_000 })

  const bodyText = await page.locator('body').innerText()
  const didMatch = /did:[a-z0-9:]+/i.exec(bodyText)
  if (!didMatch) {
    throw new Error('Could not find DID on welcome page')
  }

  // Handle is rendered as "@<handle>" on the welcome page
  const handleMatch = /@([\w.-]+)/.exec(bodyText)
  const handle = handleMatch ? handleMatch[1] : undefined

  world.testEmail = email
  world.userDid = didMatch[0]
  world.userHandle = handle

  await clearMailpit(email)

  return { did: didMatch[0], handle }
}
