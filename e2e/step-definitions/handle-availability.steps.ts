import { Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import type { EpdsWorld } from '../support/world.js'

When(
  'the handle picker preview reports that {string} is unavailable',
  async function (this: EpdsWorld, handle: string) {
    const page = getPage(this)
    await page.route('**/api/check-handle?*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ available: false }),
      })
    })
    await page.goto(`${testEnv.authUrl}/preview/choose-handle`)
    await page.getByLabel('Handle').fill(handle)
  },
)

Then(
  'the handle picker shows {string}',
  async function (this: EpdsWorld, expected: string) {
    await expect(getPage(this).locator('#handle-status')).toHaveText(
      `✗ ${expected}`,
    )
  },
)

Then(
  'the handle picker does not show {string}',
  async function (this: EpdsWorld, unexpected: string) {
    await expect(getPage(this).locator('#handle-status')).not.toContainText(
      unexpected,
    )
  },
)
