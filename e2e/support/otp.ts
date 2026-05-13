/**
 * Helper for filling the auth-service login page's segmented 6-box OTP input.
 *
 * The login page renders six visible `.otp-box` inputs that feed a hidden
 * `#code` field via JS. The page's input handler auto-submits the verify
 * form once the last digit is entered, so callers should NOT click the
 * verify button after this helper returns.
 */
import type { Page } from '@playwright/test'

export async function fillOtp(page: Page, otp: string): Promise<void> {
  const boxes = page.locator('.otp-box')
  await boxes.first().waitFor({ state: 'visible' })
  // Clear any stale digits first. Otherwise filling box[0] of a populated
  // form leaves boxes 1–5 with old values, and the input handler sees a
  // 6-char hidden value on the very first fill — triggering a premature
  // auto-submit with mixed old+new digits.
  const count = await boxes.count()
  for (let i = 0; i < count; i++) {
    await boxes.nth(i).fill('')
  }
  for (let i = 0; i < otp.length; i++) {
    await boxes.nth(i).fill(otp[i])
  }
}
