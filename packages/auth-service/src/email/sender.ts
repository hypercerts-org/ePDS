import * as nodemailer from 'nodemailer'
import { createLogger } from '@certified-app/shared'
import type { SendMailOptions, SentMessageInfo, Transporter } from 'nodemailer'
import type { EmailConfig } from '@certified-app/shared'
import {
  buildSignInCodeEmail,
  buildWelcomeCodeEmail,
  buildBackupEmailVerificationEmail,
} from './templates.js'
import { buildClientBrandedEmail } from './client-template.js'

const logger = createLogger('auth:email')

// Exposed for tests that assert the structured fields on the per-send
// completion line (elapsedMs / messageId / smtpResponse). Production
// code must not import this.
export const _loggerForTest: ReturnType<typeof createLogger> = logger

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

  /**
   * Send one message, measuring how long the SMTP handoff takes and
   * folding the elapsed time plus the provider's `messageId` / server
   * `response` into a single structured completion line. `messageId`
   * lets these app logs be joined to Resend's per-message delivery
   * events (see #183 / #198) so provider-side latency can be told apart
   * from users submitting stale codes.
   *
   * On failure the error is re-thrown after stamping it with
   * `elapsedMs`, so the caller's existing error log can carry the
   * duration without adding a second line per failure.
   */
  private async timedSendMail(
    mail: SendMailOptions,
    message: string,
    extra: Record<string, unknown> = {},
  ): Promise<void> {
    const startedAt = performance.now()
    try {
      const info: SentMessageInfo = await this.transporter.sendMail(mail)
      const elapsedMs = Math.round(performance.now() - startedAt)
      logger.info(
        {
          email: mail.to,
          ...extra,
          elapsedMs,
          messageId: info.messageId,
          smtpResponse: info.response,
        },
        message,
      )
    } catch (err) {
      const elapsedMs = Math.round(performance.now() - startedAt)
      if (err instanceof Error) {
        // Stamp the duration so the caller's error log carries it.
        ;(err as Error & { elapsedMs?: number }).elapsedMs = elapsedMs
      }
      throw err
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
        await this.timedSendMail(
          {
            from: `"${branded.fromName}" <${this.config.from}>`,
            to,
            subject: branded.subject,
            text: branded.text,
            html: branded.html,
          },
          'Sent client-branded OTP email',
          { clientId: opts.clientId },
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

    await this.timedSendMail(
      {
        from: `"${this.config.fromName}" <${this.config.from}>`,
        to,
        subject,
        text,
        html,
      },
      'Sent sign-in OTP email',
    )
  }

  private async sendWelcomeCode(opts: {
    to: string
    code: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, ...rest } = opts
    const { subject, text, html } = buildWelcomeCodeEmail(rest)

    await this.timedSendMail(
      {
        from: `"${this.config.fromName}" <${this.config.from}>`,
        to,
        subject,
        text,
        html,
      },
      'Sent welcome OTP email',
    )
  }

  async sendBackupEmailVerification(opts: {
    to: string
    verifyUrl: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, ...rest } = opts
    const { subject, text, html } = buildBackupEmailVerificationEmail(rest)

    await this.timedSendMail(
      {
        from: `"${this.config.fromName}" <${this.config.from}>`,
        to,
        subject,
        text,
        html,
      },
      'Sent backup email verification',
    )
  }
}
