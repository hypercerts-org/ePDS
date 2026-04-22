import { Then } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import { waitForEmail, extractOtp } from '../support/mailpit.js'

Then(
  'an OTP email arrives in the mail trap for the test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — "unique test email" step must run first',
      )
    }
    const message = await waitForEmail(`to:${this.testEmail}`)
    this.lastEmailSubject = message.Subject
    this.otpCode = await extractOtp(message.ID)
  },
)

Then(
  'an OTP email arrives in the mail trap for {string}',
  async function (this: EpdsWorld, email: string) {
    if (!testEnv.mailpitPass) return 'pending'
    const message = await waitForEmail(`to:${email}`)
    this.lastEmailSubject = message.Subject
    this.otpCode = await extractOtp(message.ID)
  },
)

Then('an OTP email arrives in the mail trap', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  if (!this.testEmail) {
    throw new Error('No test email set — account creation step must run first')
  }
  const message = await waitForEmail(`to:${this.testEmail}`)
  this.lastEmailSubject = message.Subject
  this.otpCode = await extractOtp(message.ID)
})

// "Welcome" for new users, "Sign-in" for returning users
Then(
  'the email subject contains {string}',
  function (this: EpdsWorld, expected: string) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.lastEmailSubject) {
      throw new Error(
        'No email subject available — email arrival step must run first',
      )
    }
    if (!this.lastEmailSubject.toLowerCase().includes(expected.toLowerCase())) {
      throw new Error(
        `Expected subject to contain "${expected}" but got: "${this.lastEmailSubject}"`,
      )
    }
  },
)
