/**
 * Fill the auth-service login page's OTP control.
 *
 * The page uses one real `#code` input beneath segmented visual slots. Filling
 * the complete value in one operation matches paste and mobile autofill, and
 * the input handler auto-submits when the configured length is reached.
 */
import type { Page } from '@playwright/test'

export async function fillOtp(page: Page, otp: string): Promise<void> {
  const input = page.locator('#code')
  await input.waitFor({ state: 'visible' })
  await input.fill('')
  await input.fill(otp)
}
