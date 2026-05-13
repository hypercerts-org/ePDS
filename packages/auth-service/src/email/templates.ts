/**
 * Pure email-template builders. Each function takes the minimal
 * identity/variable inputs it needs and returns `{ subject, text, html }`.
 * The EmailSender calls these to produce the payload it passes to
 * nodemailer; the preview routes call them to render the same HTML
 * inside a sandboxed iframe without touching SMTP.
 *
 * Keeping these pure (no I/O, no sender state) is what lets
 * /preview/emails/* render exactly what production would send.
 */
import {
  escapeHtml,
  formatOtpPlain,
  formatOtpHtmlGrouped,
} from '@certified-app/shared'

export interface RenderedEmail {
  subject: string
  text: string
  html: string
}

export function buildSignInCodeEmail(opts: {
  code: string
  clientAppName: string
  pdsName: string
  pdsDomain: string
}): RenderedEmail {
  const { code, clientAppName, pdsName, pdsDomain } = opts

  const subject = `${formatOtpPlain(code)} is your sign-in code for ${pdsName}`

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
      ${formatOtpHtmlGrouped(code)}
    </span>
  </p>
  <p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>
</body>
</html>`

  return { subject, text, html }
}

export function buildWelcomeCodeEmail(opts: {
  code: string
  pdsName: string
  pdsDomain: string
}): RenderedEmail {
  const { code, pdsName, pdsDomain } = opts

  const subject = `${formatOtpPlain(code)} — Welcome to ${pdsName}`

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
      ${formatOtpHtmlGrouped(code)}
    </span>
  </p>
  <p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
  <p style="color: #666; font-size: 14px;">If you didn't sign up, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>
</body>
</html>`

  return { subject, text, html }
}

export function buildBackupEmailVerificationEmail(opts: {
  verifyUrl: string
  pdsName: string
  pdsDomain: string
}): RenderedEmail {
  const { verifyUrl, pdsName, pdsDomain } = opts

  const subject = `Verify your backup email - ${pdsName}`

  const text = `Verify your backup email by clicking this link:\n\n${verifyUrl}\n\nThis link expires in 24 hours.\n\n--\n${pdsName} (${pdsDomain})`

  const html = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
  <p>Verify your backup email by clicking the link below:</p>
  <p style="margin: 20px 0;"><a href="${escapeHtml(verifyUrl)}" style="background-color: #0f1828; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none;">Verify Email</a></p>
  <p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">${escapeHtml(pdsName)} (${escapeHtml(pdsDomain)})</p>
</body>
</html>`

  return { subject, text, html }
}
