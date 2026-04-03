/**
 * Reusable browser-driven flows used by step definitions as setup helpers.
 *
 * These are plain async functions, not Cucumber step definitions. They drive
 * real browser interactions and should only be called from step definitions
 * after checking testEnv.mailpitPass where relevant.
 */

import { expect } from '@playwright/test'
import type { EpdsWorld } from './world.js'
import { testEnv } from './env.js'
import { waitForEmail, extractOtp, clearMailpit } from './mailpit.js'

/**
 * Drive the full new-user OAuth sign-up flow through the demo app:
 *   1. Navigate to demoUrl
 *   2. Fill #email with the provided email, submit
 *   3. Wait for #step-otp.active (30 s)
 *   4. Fetch OTP from Mailpit via waitForEmail + extractOtp
 *   5. Fill #code with OTP, click #form-verify-otp .btn-primary
 *   6. Wait for URL matching "**\/welcome" (30 s)
 *   7. Capture DID and handle from page body text
 *   8. Store testEmail, userDid, and userHandle on the world
 *   9. Clear Mailpit inbox for the email
 *
 * Callers must check testEnv.mailpitPass before calling this function.
 */
export async function createAccountViaOAuth(
  world: EpdsWorld,
  email: string,
): Promise<{ did: string; handle: string | undefined }> {
  const page = world.page
  if (!page) throw new Error('page is not initialised')

  // Clear stale OTP emails so waitForEmail reads the code sent by this submit.
  await clearMailpit(email)

  await page.goto(testEnv.demoUrl)
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
