/**
 * Tests for email template rendering logic in sender.ts.
 *
 * The renderTemplate and renderSubjectTemplate functions are private,
 * so we test them indirectly through the EmailSender.sendOtpCode method
 * using a jsonTransport (no real SMTP). We also test the fetchTemplate
 * logic indirectly via sendOtpCode with seeded caches (the SSRF-hardened
 * safeFetch uses an undici dispatcher that bypasses globalThis.fetch,
 * so we seed caches instead of mocking fetch).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  EmailSender,
  _seedTemplateCacheForTest,
  _clearTemplateCacheForTest,
} from '../email/sender.js'
import {
  formatOtpHtmlGrouped,
  clearClientMetadataCache,
  _seedClientMetadataCacheForTest,
} from '@certified-app/shared'
import type { EmailConfig } from '@certified-app/shared'

beforeEach(() => {
  clearClientMetadataCache()
  _clearTemplateCacheForTest()
})

/** Create an EmailSender with jsonTransport (captures sent mail as JSON). */
function makeSender(): EmailSender {
  const config: EmailConfig = {
    // Use an invalid provider to trigger jsonTransport fallback
    provider: 'none' as EmailConfig['provider'],
    from: 'noreply@pds.example',
    fromName: 'Test PDS',
  }
  return new EmailSender(config)
}

describe('EmailSender', () => {
  describe('sendOtpCode (default template)', () => {
    it('sends a sign-in OTP email with default template', async () => {
      const sender = makeSender()
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'user@test.com',
        code: '12345678',
        clientAppName: 'Test App',
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      expect(sendMailSpy).toHaveBeenCalledOnce()
      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        html: string
        text: string
        subject: string
      }
      expect(mailOpts.subject).toContain('Test PDS')
      expect(mailOpts.html).toContain(formatOtpHtmlGrouped('12345678'))
      expect(mailOpts.text).toContain('12345678')
    })

    it('sends a sign-up OTP email with default template', async () => {
      const sender = makeSender()
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'newuser@test.com',
        code: '87654321',
        isNewUser: true,
        clientAppName: 'Test App',
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      expect(sendMailSpy).toHaveBeenCalledOnce()
      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        html: string
        subject: string
      }
      expect(mailOpts.html).toContain(formatOtpHtmlGrouped('87654321'))
    })
  })

  describe('sendOtpCode (client template)', () => {
    it('uses client template when available', async () => {
      // Seed caches so no real HTTP fetch is needed
      _seedClientMetadataCacheForTest(
        'https://branded.app/client-metadata.json',
        {
          client_name: 'Branded App',
          email_template_uri: 'https://branded.app/email-template.html',
          logo_uri: 'https://branded.app/logo.png',
        },
      )
      _seedTemplateCacheForTest(
        'https://branded.app/email-template.html',
        '<html><body>Your code is {{code}} for {{app_name}}</body></html>',
      )

      const sender = makeSender()
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'branded@test.com',
        code: '99999999',
        clientAppName: 'Fallback Name',
        clientId: 'https://branded.app/client-metadata.json',
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      expect(sendMailSpy).toHaveBeenCalledOnce()
      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        html: string
        subject: string
        from: string
      }
      expect(mailOpts.html).toContain('Your code is 99999999 for Branded App')
      expect(mailOpts.subject).toContain('Branded App')
      expect(mailOpts.from).toContain('Branded App')
    })

    it('falls back to default when no template URI in metadata', async () => {
      // Seed metadata without email_template_uri
      _seedClientMetadataCacheForTest(
        'https://plain.app/client-metadata.json',
        {
          client_name: 'Plain App',
        },
      )

      const sender = makeSender()
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'fallback@test.com',
        code: '44444444',
        clientAppName: 'Fallback App',
        clientId: 'https://plain.app/client-metadata.json',
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      expect(sendMailSpy).toHaveBeenCalledOnce()
      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        html: string
        subject: string
        from: string
      }
      // Default template uses pdsName in subject, not client name
      expect(mailOpts.subject).toContain('Test PDS')
      expect(mailOpts.html).toContain(formatOtpHtmlGrouped('44444444'))
      expect(mailOpts.from).toContain('Test PDS')
    })
  })

  describe('sendBackupEmailVerification', () => {
    it('sends verification email', async () => {
      const sender = makeSender()
      await expect(
        sender.sendBackupEmailVerification({
          to: 'backup@test.com',
          verifyUrl: 'https://pds.example/verify?token=abc123',
          pdsName: 'Test PDS',
          pdsDomain: 'pds.example',
        }),
      ).resolves.toBeUndefined()
    })
  })
})
