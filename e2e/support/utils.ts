/**
 * Shared utility helpers for step definitions.
 */

import { expect, type Browser } from '@playwright/test'
import type { EpdsWorld } from './world.js'

/**
 * Returns the Playwright Page from the world, throwing a clear error if
 * it has not been initialised. Use this in every step that needs the page
 * instead of non-null asserting `world.page!`.
 */
export function getPage(world: EpdsWorld) {
  const page = world.page
  if (!page) throw new Error('page is not initialised')
  return page
}

/**
 * Closes the current browser context on the world and opens a fresh one.
 *
 * Pass `sharedBrowser` from hooks.ts as the second argument. Accepting it as a
 * parameter keeps this module free of side-effectful imports and makes the
 * dependency explicit at each call site.
 */
export async function resetBrowserContext(
  world: EpdsWorld,
  browser: Browser | undefined,
): Promise<void> {
  await world.context?.close()
  if (!browser) throw new Error('sharedBrowser is not initialised')
  world.context = await browser.newContext()
  world.page = await world.context.newPage()
  world.page.setDefaultNavigationTimeout(30_000)
  world.page.setDefaultTimeout(15_000)
}

/**
 * Asserts that the browser has landed on a demo client's /welcome page
 * with a valid session. Checks: /welcome URL pattern, session_id cookie
 * set, body text indicating signed-in state, visible DID and handle.
 *
 * Pass `expectedDemoUrl` to additionally assert the welcome URL's origin
 * matches that demo client's origin — this is how consent-screen scenarios
 * distinguish "redirected to the trusted demo" from "redirected to the
 * untrusted demo" when both demo services are live in the test env.
 * Omit it to accept any demo origin (back-compat for scenarios that only
 * exercise a single demo client).
 */
export async function assertDemoClientSession(
  world: EpdsWorld,
  expectedDemoUrl?: string,
): Promise<void> {
  const page = getPage(world)

  await page.waitForURL('**/welcome', { timeout: 30_000 })

  if (expectedDemoUrl) {
    const expectedOrigin = new URL(expectedDemoUrl).origin
    const actualOrigin = new URL(page.url()).origin
    if (actualOrigin !== expectedOrigin) {
      throw new Error(
        `Expected redirect to ${expectedOrigin}, got ${actualOrigin}`,
      )
    }
  }

  const cookies = await page.context().cookies()
  const sessionCookie = cookies.find((cookie) => cookie.name === 'session_id')
  if (!sessionCookie?.value) {
    throw new Error('Demo client session cookie was not set after redirect')
  }

  const body = page.locator('body')
  await expect(body).toContainText('You are signed in.')
  await expect(body).toContainText('Sign out')
  await expect(body).toContainText(/@[\w.-]+/)
  await expect(body).toContainText(/did:[a-z0-9:]+/i)
}
