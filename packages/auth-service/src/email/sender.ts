import * as nodemailer from 'nodemailer'
import { createLogger } from '@magic-pds/shared'
import type { Transporter } from 'nodemailer'
import type SMTPTransport from 'nodemailer/lib/smtp-transport'
import type { EmailConfig } from '@magic-pds/shared'

const logger = createLogger('auth:email')

export class EmailSender {
  private transporter: Transporter<SMTPTransport.SentMessageInfo>

  constructor(private readonly config: EmailConfig) {
    this.transporter = this.createTransporter()
  }

  private createTransporter(): Transporter<SMTPTransport.SentMessageInfo> {
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
        // SendGrid SMTP relay - requires SENDGRID_API_KEY env var
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
        // AWS SES SMTP interface - requires SES SMTP credentials
        // Generate SMTP credentials in AWS Console > SES > SMTP Settings
        return nodemailer.createTransport({
          host: this.config.smtpHost || `email-smtp.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com`,
          port: 587,
          secure: false,
          auth: {
            user: this.config.smtpUser || process.env.AWS_SES_SMTP_USER || '',
            pass: this.config.smtpPass || process.env.AWS_SES_SMTP_PASS || '',
          },
        })

      case 'postmark':
        // Postmark SMTP - requires server API token
        return nodemailer.createTransport({
          host: 'smtp.postmarkapp.com',
          port: 587,
          secure: false,
          auth: {
            user: this.config.smtpPass || process.env.POSTMARK_SERVER_TOKEN || '',
            pass: this.config.smtpPass || process.env.POSTMARK_SERVER_TOKEN || '',
          },
        })

      default:
        // For dev/testing: JSON transport (logs to console)
        logger.warn('No email provider configured, using console logging')
        return nodemailer.createTransport({ jsonTransport: true })
    }
  }

  async sendMagicLink(opts: {
    to: string
    magicLinkUrl: string
    clientAppName: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, magicLinkUrl, clientAppName, pdsName, pdsDomain } = opts

    const subject = `Sign in to ${clientAppName} via ${pdsName}`

    const text = [
      `You requested to sign in to ${clientAppName}.`,
      '',
      `Click the link below to continue:`,
      magicLinkUrl,
      '',
      `This link expires in 10 minutes and can only be used once.`,
      '',
      `If you didn't request this, you can safely ignore this email.`,
      '',
      `--`,
      `${pdsName} (${pdsDomain})`,
    ].join('\n')

    const html = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
  <p>You requested to sign in to <strong>${this.escapeHtml(clientAppName)}</strong>.</p>
  <p>Click the button below to continue:</p>
  <p style="margin: 30px 0;">
    <a href="${this.escapeHtml(magicLinkUrl)}"
       style="background-color: #0f1828; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; display: inline-block;">
      Sign in to ${this.escapeHtml(clientAppName)}
    </a>
  </p>
  <p style="color: #666; font-size: 14px;">This link expires in 10 minutes and can only be used once.</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${this.escapeHtml(pdsName)} (${this.escapeHtml(pdsDomain)})</p>
</body>
</html>`

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
    const { to, verifyUrl, pdsName, pdsDomain } = opts

    await this.transporter.sendMail({
      from: `"${this.config.fromName}" <${this.config.from}>`,
      to,
      subject: `Verify your backup email - ${pdsName}`,
      text: `Verify your backup email by clicking this link:\n\n${verifyUrl}\n\nThis link expires in 24 hours.\n\n--\n${pdsName} (${pdsDomain})`,
      html: `
<p>Verify your backup email by clicking the link below:</p>
<p style="margin: 20px 0;"><a href="${this.escapeHtml(verifyUrl)}" style="background-color: #0f1828; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none;">Verify Email</a></p>
<p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
<hr style="border: none; border-top: 1px solid #eee;"><p style="color: #999; font-size: 12px;">${this.escapeHtml(pdsName)} (${this.escapeHtml(pdsDomain)})</p>`,
    })
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  }
}
