import * as nodemailer from 'nodemailer'
import { createLogger } from '@certified-app/shared'
import type { Transporter } from 'nodemailer'
import type { EmailConfig } from '@certified-app/shared'
import {
  buildSignInCodeEmail,
  buildWelcomeCodeEmail,
  buildBackupEmailVerificationEmail,
} from './templates.js'
import { buildClientBrandedEmail } from './client-template.js'

const logger = createLogger('auth:email')

// Re-exports so existing tests that reach for the template cache still
// resolve through sender.js. New code should import directly from
// ./client-template.js.
export {
  _seedTemplateCacheForTest,
  _clearTemplateCacheForTest,
} from './client-template.js'

export class EmailSender {
  private transporter: Transporter

  /**
   * @param config  SMTP / provider config.
   * @param trustedClients  OAuth client_id URLs (from
   *   `PDS_OAUTH_TRUSTED_CLIENTS`) for which we will honour
   *   `email_template_uri`, `email_subject_template`, and the
   *   `client_name`-derived From display name. Any other `client_id`
   *   falls back to the default PDS templates regardless of what its
   *   metadata advertises — an untrusted third party must not be able
   *   to cause outbound fetches or put attacker-controlled HTML
   *   alongside the PDS's own From address.
   */
  constructor(
    private readonly config: EmailConfig,
    private readonly trustedClients: readonly string[] = [],
  ) {
    this.transporter = this.createTransporter()
  }

  private createTransporter(): Transporter {
    switch (this.config.provider) {
      case 'smtp':
        return nodemailer.createTransport({
          host: this.config.smtpHost,
          port: this.config.smtpPort || 587,
          secure: (this.config.smtpPort || 587) === 465,
          auth: this.config.smtpUser
            ? { user: this.config.smtpUser, pass: this.config.smtpPass }
            : undefined,
        })

      case 'sendgrid':
        return nodemailer.createTransport({
          host: 'smtp.sendgrid.net',
          port: 587,
          secure: false,
          auth: {
            user: 'apikey',
            pass: this.config.smtpPass || process.env.SENDGRID_API_KEY || '',
          },
        })

      case 'ses':
        return nodemailer.createTransport({
          host:
            this.config.smtpHost ||
            `email-smtp.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com`,
          port: 587,
          secure: false,
          auth: {
            user: this.config.smtpUser || process.env.AWS_SES_SMTP_USER || '',
            pass: this.config.smtpPass || process.env.AWS_SES_SMTP_PASS || '',
          },
        })

      case 'postmark':
        return nodemailer.createTransport({
          host: 'smtp.postmarkapp.com',
          port: 587,
          secure: false,
          auth: {
            user:
              this.config.smtpPass || process.env.POSTMARK_SERVER_TOKEN || '',
            pass:
              this.config.smtpPass || process.env.POSTMARK_SERVER_TOKEN || '',
          },
        })

      default:
        logger.warn('No email provider configured, using console logging')
        return nodemailer.createTransport({ jsonTransport: true })
    }
  }

  async sendOtpCode(opts: {
    to: string
    code: string
    clientAppName: string
    clientId?: string
    pdsName: string
    pdsDomain: string
    isNewUser?: boolean
  }): Promise<void> {
    const { to, code, clientAppName, pdsName, pdsDomain, isNewUser } = opts

    // Try the client-branded path first. `buildClientBrandedEmail`
    // enforces the trusted-clients gate and returns null if the client
    // is untrusted, has no `email_template_uri`, or the template fetch /
    // validation fails. The /preview/emails/* routes go through the
    // same helper so what the browser previews matches what the real
    // sender puts in the envelope.
    if (opts.clientId) {
      const branded = await buildClientBrandedEmail({
        clientId: opts.clientId,
        code,
        isNewUser: isNewUser ?? false,
        toEmail: to,
        fallbackAppName: clientAppName,
        fallbackFromName: this.config.fromName,
        pdsName,
        pdsDomain,
        trustedClients: this.trustedClients,
      })
      if (branded) {
        await this.transporter.sendMail({
          from: `"${branded.fromName}" <${this.config.from}>`,
          to,
          subject: branded.subject,
          text: branded.text,
          html: branded.html,
        })
        logger.info(
          { to, clientId: opts.clientId },
          'Sent client-branded OTP email',
        )
        return
      }
    }

    // Fall back to default Certified templates
    if (isNewUser) {
      await this.sendWelcomeCode({ to, code, pdsName, pdsDomain })
    } else {
      await this.sendSignInCode({ to, code, clientAppName, pdsName, pdsDomain })
    }
  }

  private async sendSignInCode(opts: {
    to: string
    code: string
    clientAppName: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, ...rest } = opts
    const { subject, text, html } = buildSignInCodeEmail(rest)

    await this.transporter.sendMail({
      from: `"${this.config.fromName}" <${this.config.from}>`,
      to,
      subject,
      text,
      html,
    })
  }

  private async sendWelcomeCode(opts: {
    to: string
    code: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, ...rest } = opts
    const { subject, text, html } = buildWelcomeCodeEmail(rest)

    await this.transporter.sendMail({
      from: `"${this.config.fromName}" <${this.config.from}>`,
      to,
      subject,
      text,
      html,
    })
  }

  async sendBackupEmailVerification(opts: {
    to: string
    verifyUrl: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, ...rest } = opts
    const { subject, text, html } = buildBackupEmailVerificationEmail(rest)

    await this.transporter.sendMail({
      from: `"${this.config.fromName}" <${this.config.from}>`,
      to,
      subject,
      text,
      html,
    })
  }
}
