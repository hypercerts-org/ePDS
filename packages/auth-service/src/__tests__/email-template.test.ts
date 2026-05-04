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
function makeSender(trustedClients: string[] = []): EmailSender {
  const config: EmailConfig = {
    // Use an invalid provider to trigger jsonTransport fallback
    provider: 'none' as EmailConfig['provider'],
    from: 'noreply@pds.example',
    fromName: 'Test PDS',
  }
  return new EmailSender(config, trustedClients)
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
    const TRUSTED_ID = 'https://branded.app/client-metadata.json'

    it('uses client template when client is trusted', async () => {
      // Seed caches so no real HTTP fetch is needed
      _seedClientMetadataCacheForTest(TRUSTED_ID, {
        client_name: 'Branded App',
        email_template_uri: 'https://branded.app/email-template.html',
        logo_uri: 'https://branded.app/logo.png',
      })
      _seedTemplateCacheForTest(
        'https://branded.app/email-template.html',
        '<html><body>Your code is {{code}} for {{app_name}}</body></html>',
      )

      const sender = makeSender([TRUSTED_ID])
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'branded@test.com',
        code: '99999999',
        clientAppName: 'Fallback Name',
        clientId: TRUSTED_ID,
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

      const sender = makeSender(['https://plain.app/client-metadata.json'])
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

    it('ignores email_template_uri from untrusted clients', async () => {
      // An untrusted client advertises a full set of branding fields.
      // The gate must drop all of them — the metadata resolver must
      // not even be called (no outbound fetch on the hot path), and
      // the sent mail must use the default PDS template with the
      // default From name. `clientAppName` is a *caller*-supplied
      // string (not from the client's own metadata), so the default
      // template is still free to mention it: the attack we're
      // blocking is metadata-derived content, not the caller's label.
      const resolveSpy = vi
        .spyOn(
          await import('../lib/client-metadata.js'),
          'resolveClientMetadata',
        )
        .mockResolvedValue({
          client_name: 'Evil App (from metadata)',
          email_template_uri: 'https://evil.example/pwn.html',
          email_subject_template: '{{code}} — pwned',
          logo_uri: 'https://evil.example/logo.png',
        })

      const sender = makeSender([
        // A *different* client_id is trusted. The one in the request is not.
        'https://other-trusted.app/client-metadata.json',
      ])
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'victim@test.com',
        code: '77777777',
        clientAppName: 'Caller App Name',
        clientId: 'https://evil.example/client-metadata.json',
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      expect(resolveSpy).not.toHaveBeenCalled()
      expect(sendMailSpy).toHaveBeenCalledOnce()
      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        html: string
        subject: string
        from: string
      }
      // Default subject uses pdsName, not metadata.client_name.
      expect(mailOpts.subject).toContain('Test PDS')
      expect(mailOpts.subject).not.toContain('pwned')
      // From display name stays as the PDS default.
      expect(mailOpts.from).toContain('Test PDS')
      expect(mailOpts.from).not.toContain('from metadata')
      // No metadata-derived HTML — the attacker's template never rendered.
      expect(mailOpts.html).not.toContain('from metadata')
      expect(mailOpts.html).toContain(formatOtpHtmlGrouped('77777777'))

      resolveSpy.mockRestore()
    })
  })

  describe('sendOtpCode — header-injection hardening', () => {
    const TRUSTED_ID = 'https://hdr.app/client-metadata.json'

    it('strips CR/LF from client_name (From) and email_subject_template (Subject)', async () => {
      // Even for trusted clients, metadata can be compromised upstream.
      // A CR/LF in Subject or the From display-name would let an attacker
      // inject extra SMTP headers (Bcc, Reply-To, …) after it.
      _seedClientMetadataCacheForTest(TRUSTED_ID, {
        client_name: 'Evil\r\nBcc: attacker@evil.example',
        email_template_uri: 'https://hdr.app/email-template.html',
        email_subject_template: '{{code}}\r\nBcc: leak@evil.example',
      })
      _seedTemplateCacheForTest(
        'https://hdr.app/email-template.html',
        '<html><body>{{code}}</body></html>',
      )

      const sender = makeSender([TRUSTED_ID])
      const sendMailSpy = vi.spyOn(sender['transporter'], 'sendMail')

      await sender.sendOtpCode({
        to: 'u@test.com',
        code: '11112222',
        clientAppName: 'Fallback',
        clientId: TRUSTED_ID,
        pdsName: 'Test PDS',
        pdsDomain: 'pds.example',
      })

      const mailOpts = sendMailSpy.mock.calls[0][0] as {
        subject: string
        from: string
      }
      // Key guarantee: no CR/LF in any value that lands in an SMTP
      // header — that's what an injection attack needs. The literal
      // string "Bcc:" surviving as *body text in the Subject* is
      // harmless; SMTP parses headers by line, not by substring.
      expect(mailOpts.subject).not.toMatch(/[\r\n]/)
      expect(mailOpts.from).not.toMatch(/[\r\n]/)
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
