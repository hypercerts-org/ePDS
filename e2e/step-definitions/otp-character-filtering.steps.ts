import { Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import type { EpdsWorld } from '../support/world.js'

When(
  'the recovery OTP preview uses the {string} character policy',
  async function (this: EpdsWorld, charset: string) {
    await getPage(this).goto(
      `${testEnv.authUrl}/preview/recovery-otp?otp_charset=${encodeURIComponent(charset)}`,
    )
  },
)

When(
  'the user types {string} into the recovery OTP input',
  async function (this: EpdsWorld, value: string) {
    await getPage(this).getByLabel('One-time code').fill(value)
  },
)

Then(
  'the recovery OTP input contains {string}',
  async function (this: EpdsWorld, expected: string) {
    await expect(getPage(this).getByLabel('One-time code')).toHaveValue(
      expected,
    )
  },
)

// ---------------------------------------------------------------------------
// Segmented sign-in grid
//
// The grid is a different code path from the two single-input forms: its
// filtering lives in JS input/paste handlers rather than an oninput
// attribute, and the paste handler additionally spreads the cleaned
// characters across boxes. Neither behaviour is observable in the rendered
// HTML, so only a browser-level test can catch a regression there.
// ---------------------------------------------------------------------------

When(
  'the sign-in OTP preview uses the {string} character policy',
  async function (this: EpdsWorld, charset: string) {
    const page = getPage(this)
    await page.goto(
      `${testEnv.authUrl}/preview/login-otp?otp_charset=${encodeURIComponent(charset)}`,
    )
    // The handlers under test are attached by the page's inline script, so
    // wait for the boxes rather than racing the script with the first fill.
    await page.locator('.otp-box').first().waitFor({ state: 'visible' })
  },
)

When(
  'the user types {string} into the first sign-in OTP box',
  async function (this: EpdsWorld, value: string) {
    await getPage(this).locator('.otp-box').first().fill(value)
  },
)

When(
  'the user pastes {string} into the first sign-in OTP box',
  async function (this: EpdsWorld, value: string) {
    // Playwright cannot portably seed the system clipboard, and the handler
    // reads only event.clipboardData, so synthesise the event directly. This
    // still drives the real listener, including its filtering and spreading.
    await getPage(this)
      .locator('.otp-box')
      .first()
      .evaluate((box, pasted) => {
        const data = new DataTransfer()
        data.setData('text/plain', pasted)
        box.dispatchEvent(
          new ClipboardEvent('paste', {
            clipboardData: data,
            bubbles: true,
            cancelable: true,
          }),
        )
      }, value)
  },
)

Then(
  'the sign-in OTP boxes spell {string}',
  async function (this: EpdsWorld, expected: string) {
    const boxes = getPage(this).locator('.otp-box')
    const count = await boxes.count()
    if (count < expected.length) {
      throw new Error(
        `Expected at least ${expected.length} OTP boxes, found ${count}`,
      )
    }
    // Assert on every box rather than just the filled prefix: a spreading
    // bug that scattered characters into later boxes would otherwise pass.
    const padded = expected.padEnd(count, ' ')
    for (let index = 0; index < count; index += 1) {
      const character = padded[index]
      await expect(boxes.nth(index)).toHaveValue(
        character === ' ' ? '' : character,
      )
    }
  },
)
