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
// filtering lives in a JS input/paste handler rather than an oninput
// attribute, and the paste handler additionally normalizes the whole value
// before it is rendered across the slots. Neither behaviour is observable in
// the rendered HTML, so only a browser-level test can catch a regression.
//
// The grid is one real `#code` input behind non-interactive `.otp-box` divs
// (needed for mobile long-press paste and one-time-code autofill), so these
// steps drive `#code` and assert on what each slot displays.
// ---------------------------------------------------------------------------

const SIGN_IN_OTP_INPUT = '#code'

When(
  'the sign-in OTP preview uses the {string} character policy',
  async function (this: EpdsWorld, charset: string) {
    const page = getPage(this)
    await page.goto(
      `${testEnv.authUrl}/preview/login-otp?otp_charset=${encodeURIComponent(charset)}`,
    )
    // The handlers under test are attached by the page's inline script, so
    // wait for the input rather than racing the script with the first fill.
    await page.locator(SIGN_IN_OTP_INPUT).waitFor({ state: 'visible' })
  },
)

When(
  'the user types {string} into the first sign-in OTP box',
  async function (this: EpdsWorld, value: string) {
    // pressSequentially, not fill: typing one character at a time is what a
    // user does, and it drives the input handler once per character the way
    // the old per-box grid did.
    const input = getPage(this).locator(SIGN_IN_OTP_INPUT)
    await input.focus()
    await input.pressSequentially(value)
  },
)

When(
  'the user pastes {string} into the first sign-in OTP box',
  async function (this: EpdsWorld, value: string) {
    // Playwright cannot portably seed the system clipboard, and the handler
    // reads only event.clipboardData, so synthesise the event directly. This
    // still drives the real listener, including its normalization.
    await getPage(this)
      .locator(SIGN_IN_OTP_INPUT)
      .evaluate((input, pasted) => {
        const data = new DataTransfer()
        data.setData('text/plain', pasted)
        input.dispatchEvent(
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
    const page = getPage(this)
    const boxes = page.locator('.otp-box')
    const count = await boxes.count()
    if (count < expected.length) {
      throw new Error(
        `Expected at least ${expected.length} OTP boxes, found ${count}`,
      )
    }
    // The input holds the value the form actually submits, so pin it directly
    // rather than inferring it from the slots alone.
    await expect(page.locator(SIGN_IN_OTP_INPUT)).toHaveValue(expected)
    // Then assert every slot renders it, including that the trailing slots
    // stayed empty — a normalization bug that leaked extra characters into
    // later slots would otherwise pass. An empty slot still shows a
    // placeholder character, so `empty` is the class, not the text.
    for (let index = 0; index < count; index += 1) {
      const box = boxes.nth(index)
      if (index >= expected.length) {
        await expect(box).toHaveClass(/\bempty\b/)
      } else {
        await expect(box).not.toHaveClass(/\bempty\b/)
        await expect(box.locator('.otp-character')).toHaveText(expected[index])
      }
    }
  },
)
