import * as nodemailer from 'nodemailer'
import { createLogger } from '@certified-app/shared'
import type { Transporter } from 'nodemailer'
import type { EmailConfig } from '@certified-app/shared'
import { escapeHtml } from '@certified-app/shared'
import { resolveClientMetadata } from '../lib/client-metadata.js'

const logger = createLogger('auth:email')

// Template cache (separate from client metadata cache)
const templateCache = new Map<string, { html: string; fetchedAt: number }>()
const TEMPLATE_CACHE_TTL = 10 * 60 * 1000 // 10 minutes

const MAX_TEMPLATE_SIZE = 100_000 // 100KB

async function fetchTemplate(uri: string): Promise<string | null> {
  // Only allow HTTPS
  if (!uri.startsWith('https://')) return null

  // Optional domain allowlist via env var (comma-separated)
  const allowedDomains = process.env.EMAIL_TEMPLATE_ALLOWED_DOMAINS
  if (allowedDomains) {
    try {
      const domains = allowedDomains.split(',').map((d) => d.trim())
      const hostname = new URL(uri).hostname
      if (!domains.includes(hostname)) {
        logger.warn(
          { uri, hostname },
          'Email template domain not in allowlist, ignoring',
        )
        return null
      }
    } catch {
      return null
    }
  }

  const cached = templateCache.get(uri)
  if (cached && Date.now() - cached.fetchedAt < TEMPLATE_CACHE_TTL) {
    return cached.html
  }
  try {
    const res = await fetch(uri, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) return null

    // Reject oversized responses
    const contentLength = res.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > MAX_TEMPLATE_SIZE) {
      logger.warn({ uri, contentLength }, 'Email template too large, ignoring')
      return null
    }

    const html = await res.text()
    if (html.length > MAX_TEMPLATE_SIZE) {
      logger.warn(
        { uri, size: html.length },
        'Email template too large, ignoring',
      )
      return null
    }

    // Basic validation: must contain {{code}} placeholder
    if (!html.includes('{{code}}')) {
      logger.warn(
        { uri },
        'Email template missing {{code}} placeholder, ignoring',
      )
      return null
    }
    templateCache.set(uri, { html, fetchedAt: Date.now() })
    return html
  } catch (err) {
    logger.warn({ err, uri }, 'Failed to fetch email template')
    return null
  }
}

function renderTemplate(
  template: string,
  vars: Record<string, string | boolean>,
): string {
  let html = template

  // Handle conditional sections first: {{#key}}...{{/key}} and {{^key}}...{{/key}}
  for (const [key, value] of Object.entries(vars)) {
    if (typeof value === 'boolean') {
      const showRegex = new RegExp(
        `\\{\\{#${key}\\}\\}([\\s\\S]*?)\\{\\{/${key}\\}\\}`,
        'g',
      )
      const hideRegex = new RegExp(
        `\\{\\{\\^${key}\\}\\}([\\s\\S]*?)\\{\\{/${key}\\}\\}`,
        'g',
      )
      html = html.replace(showRegex, value ? '$1' : '')
      html = html.replace(hideRegex, value ? '' : '$1')
    }
  }

  // Then replace string variables (HTML-escaped)
  for (const [key, value] of Object.entries(vars)) {
    if (typeof value === 'string') {
      html = html.replaceAll(`{{${key}}}`, escapeHtml(value))
    }
  }

  return html
}

function renderSubjectTemplate(
  template: string,
  vars: Record<string, string>,
): string {
  let subject = template
  for (const [key, value] of Object.entries(vars)) {
    subject = subject.replaceAll(`{{${key}}}`, value)
  }
  return subject
}

export class EmailSender {
  private transporter: Transporter

  constructor(private readonly config: EmailConfig) {
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

    // Try to use a client-provided email template
    if (opts.clientId) {
      try {
        const metadata = await resolveClientMetadata(opts.clientId)
        if (metadata.email_template_uri) {
          const template = await fetchTemplate(metadata.email_template_uri)
          if (template) {
            const appName = metadata.client_name || clientAppName

            const customHtml = renderTemplate(template, {
              code,
              app_name: appName,
              logo_uri: metadata.logo_uri || '',
              is_new_user: isNewUser ?? false,
              email: to,
            })

            let subject: string
            if (metadata.email_subject_template) {
              subject = renderSubjectTemplate(metadata.email_subject_template, {
                code,
                app_name: appName,
              })
            } else if (isNewUser) {
              subject = `${code} — Welcome to ${appName}`
            } else {
              subject = `${code} is your sign-in code for ${appName}`
            }

            const fromName = metadata.client_name || this.config.fromName

            await this.transporter.sendMail({
              from: `"${fromName}" <${this.config.from}>`,
              to,
              subject,
              text: `Your code for ${appName} is: ${code}\n\nThis code expires in 10 minutes.\n\nIf you didn't request this, you can safely ignore this email.`,
              html: customHtml,
            })

            logger.info(
              {
                to,
                clientId: opts.clientId,
                templateUri: metadata.email_template_uri,
              },
              'Sent client-branded OTP email',
            )
            return
          }
        }
      } catch (err) {
        logger.warn(
          { err, clientId: opts.clientId },
          'Failed to use client email template, falling back to default',
        )
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
    const { to, code, clientAppName, pdsName, pdsDomain } = opts

    const subject = `${code} is your sign-in code for ${pdsName}`

    const text = [
      `Your sign-in code for ${clientAppName}:`,
      '',
      code,
      '',
      `This code expires in 10 minutes.`,
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
  <p>Your sign-in code for <strong>${escapeHtml(clientAppName)}</strong>:</p>
  <p style="margin: 30px 0; text-align: center;">
    <span style="font-size: 32px; font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; letter-spacing: 6px; background: #f5f5f5; padding: 16px 24px; border-radius: 8px; display: inline-block; font-weight: 600; color: #0f1828;">
      ${escapeHtml(code)}
    </span>
  </p>
  <p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>
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

  private async sendWelcomeCode(opts: {
    to: string
    code: string
    pdsName: string
    pdsDomain: string
  }): Promise<void> {
    const { to, code, pdsName, pdsDomain } = opts

    const subject = `${code} — Welcome to ${pdsName}`

    const text = [
      `Welcome to ${pdsName}!`,
      '',
      `Your verification code:`,
      '',
      code,
      '',
      `Enter this code to confirm your email and create your account.`,
      '',
      `This code expires in 10 minutes.`,
      '',
      `If you didn't sign up, you can safely ignore this email.`,
      '',
      `--`,
      `${pdsName} (${pdsDomain})`,
    ].join('\n')

    const html = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
  <h2 style="color: #0f1828; margin-bottom: 8px;">Welcome to ${escapeHtml(pdsName)}</h2>
  <p>Enter this code to confirm your email and create your account:</p>
  <p style="margin: 30px 0; text-align: center;">
    <span style="font-size: 32px; font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; letter-spacing: 6px; background: #f5f5f5; padding: 16px 24px; border-radius: 8px; display: inline-block; font-weight: 600; color: #0f1828;">
      ${escapeHtml(code)}
    </span>
  </p>
  <p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 14px;">If you didn't sign up, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>
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
<p style="margin: 20px 0;"><a href="${escapeHtml(verifyUrl)}" style="background-color: #0f1828; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none;">Verify Email</a></p>
<p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
<hr style="border: none; border-top: 1px solid #eee;"><p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>`,
    })
  }
}
