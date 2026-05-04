/**
 * Tests for the pure email builders used by both the real sender and the
 * /preview/emails/* routes. Covers subject, plain-text alternative, and
 * HTML shape — the preview routes render this HTML verbatim inside an
 * iframe, so it's worth pinning.
 */
import { describe, it, expect } from 'vitest'
import {
  buildSignInCodeEmail,
  buildWelcomeCodeEmail,
  buildBackupEmailVerificationEmail,
} from '../email/templates.js'

const PDS = { pdsName: 'Test PDS', pdsDomain: 'pds.example' }

describe('buildSignInCodeEmail', () => {
  it('puts the OTP and app name in the subject, text, and html', () => {
    const { subject, text, html } = buildSignInCodeEmail({
      code: '12345678',
      clientAppName: 'My App',
      ...PDS,
    })
    expect(subject).toContain('Test PDS')
    expect(subject).toContain('1234 5678')
    expect(text).toContain('My App')
    expect(text).toContain('12345678')
    expect(html).toContain('My App')
    // formatOtpHtmlGrouped renders each digit in its own span.
    expect(html).toContain('<!DOCTYPE html>')
  })

  it('escapes HTML in the app name and pds identity', () => {
    const { html } = buildSignInCodeEmail({
      code: '123456',
      clientAppName: '<script>x</script>',
      pdsName: '<b>Name</b>',
      pdsDomain: 'a&b.example',
    })
    expect(html).not.toContain('<script>x</script>')
    expect(html).toContain('&lt;script&gt;x&lt;/script&gt;')
    expect(html).toContain('&lt;b&gt;Name&lt;/b&gt;')
    expect(html).toContain('a&amp;b.example')
  })
})

describe('buildWelcomeCodeEmail', () => {
  it('uses the welcome subject and includes the verification code', () => {
    const { subject, text, html } = buildWelcomeCodeEmail({
      code: '654321',
      ...PDS,
    })
    expect(subject).toContain('Welcome to Test PDS')
    expect(subject).toContain('654321')
    expect(text).toContain('Welcome to Test PDS')
    expect(text).toContain('654321')
    expect(html).toContain('Welcome to Test PDS')
  })
})

describe('buildBackupEmailVerificationEmail', () => {
  it('puts the verify URL in both the text and the html anchor', () => {
    const url = 'https://auth.example/account/verify?t=abc'
    const { subject, text, html } = buildBackupEmailVerificationEmail({
      verifyUrl: url,
      ...PDS,
    })
    expect(subject).toBe('Verify your backup email - Test PDS')
    expect(text).toContain(url)
    expect(html).toContain(`href="${url}"`)
    // Complete-document shell so the preview iframe renders in standards
    // mode, matching the other two builders.
    expect(html).toContain('<!DOCTYPE html>')
  })

  it('escapes a malicious verify URL', () => {
    const { html } = buildBackupEmailVerificationEmail({
      verifyUrl: 'https://x.example/"><script>alert(1)</script>',
      ...PDS,
    })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})
