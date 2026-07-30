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
