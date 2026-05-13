import { Given, Then } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import {
  waitForEmail,
  extractOtp,
  fetchEmailBody,
  mailpitAuthHeader,
} from '../support/mailpit.js'

Given(
  'a mail trap is capturing outbound emails',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const mailpitInfoUrl = `${testEnv.mailpitUrl}/api/v1/info`
    let res: Response
    try {
      res = await fetch(mailpitInfoUrl, {
        headers: { Authorization: mailpitAuthHeader() },
        signal: AbortSignal.timeout(5_000),
      })
    } catch (err) {
      throw new Error(
        `Mailpit health check failed to reach ${mailpitInfoUrl}`,
        { cause: err },
      )
    }
    if (!res.ok) {
      throw new Error(
        `Mailpit health check failed: ${res.status} at ${mailpitInfoUrl}`,
      )
    }
  },
)

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

Then(
  'a verification email arrives in the mail trap for the backup email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.backupEmail) {
      throw new Error(
        'No backup email set — "the user adds a unique backup email" step must run first',
      )
    }
    const message = await waitForEmail(`to:${this.backupEmail}`)
    this.lastEmailSubject = message.Subject
    this.lastEmailBody = await fetchEmailBody(message.ID)
  },
)

Then('the email contains a verification link', function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  if (!this.lastEmailBody) {
    throw new Error(
      'No email body captured — verification email arrival step must run first',
    )
  }
  const linkPattern = /https?:\/\/\S*\/account\/backup-email\/verify\?token=\S+/
  if (!linkPattern.test(this.lastEmailBody)) {
    throw new Error(
      'Verification email body does not contain a /account/backup-email/verify link',
    )
  }
})

Then(
  'the email body contains an OTP code matching the configured charset',
  function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.otpCode) {
      throw new Error(
        'No OTP code extracted — email arrival step must run first',
      )
    }
    const pattern =
      testEnv.otpCharset === 'alphanumeric' ? /^[A-Z0-9]+$/ : /^\d+$/
    if (!pattern.test(this.otpCode)) {
      throw new Error(
        `OTP does not match configured charset "${testEnv.otpCharset}"`,
      )
    }
  },
)
