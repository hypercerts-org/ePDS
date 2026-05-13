/**
 * Branded OTP email template served to the auth-service as
 * `email_template_uri`. The auth-service fetches this URL
 * (SSRF-hardened, HTTPS-only, 100 KB / 5 s caps) on behalf of
 * trusted clients and substitutes the following Mustache-like
 * placeholders before sending:
 *
 *   {{code}}                       the OTP code (HTML-escaped)
 *   {{app_name}}                   `client_name` from this metadata
 *                                  (HTML-escaped)
 *   {{logo_uri}}                   `logo_uri` from this metadata
 *                                  (HTML-escaped)
 *   {{email}}                      the recipient's email (HTML-escaped)
 *   {{#is_new_user}}…{{/is_new_user}}  shown only on welcome emails
 *   {{^is_new_user}}…{{/is_new_user}}  shown only on sign-in emails
 *
 * Styling is deliberately inline (no `<style>` block): several
 * popular email clients strip or mangle `<style>`, and inline
 * `style="…"` is the lowest common denominator.
 *
 * When EPDS_CLIENT_THEME is set, colours follow the same palette as
 * the rest of the demo (injected CSS on the login page, page
 * backgrounds in the React app, etc.), so an operator flipping the
 * theme gets a visually coherent login + email experience with one
 * env var.
 */

import { NextResponse } from 'next/server'
import { getPageTheme } from '@/lib/theme'

export const runtime = 'nodejs'

export function GET() {
  const theme = getPageTheme()
  const bg = theme?.bg ?? '#f8f9fa'
  const surface = theme?.surface ?? '#ffffff'
  const text = theme?.text ?? '#0f1828'
  const textMuted = theme?.textMuted ?? '#555555'
  const textHint = theme?.textHint ?? '#888888'
  const primary = theme?.primary ?? '#2563eb'
  const border = theme?.inputBorder ?? '#e5e7eb'

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:${bg};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:${text};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${bg};padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;background:${surface};border:1px solid ${border};border-radius:10px;overflow:hidden;">
          <tr>
            <td style="padding:28px 32px 12px;text-align:center;">
              <img src="{{logo_uri}}" alt="{{app_name}}" width="56" height="56" style="display:inline-block;border:0;border-radius:12px;">
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 8px;text-align:center;">
              <h1 style="margin:0;font-size:20px;font-weight:600;color:${text};">{{#is_new_user}}Welcome to {{app_name}}{{/is_new_user}}{{^is_new_user}}Sign in to {{app_name}}{{/is_new_user}}</h1>
            </td>
          </tr>
          <tr>
            <td style="padding:4px 32px 20px;text-align:center;">
              <p style="margin:0;font-size:14px;color:${textMuted};">{{#is_new_user}}Confirm your email to finish creating your account.{{/is_new_user}}{{^is_new_user}}Enter this code on the sign-in page to continue.{{/is_new_user}}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 28px;text-align:center;">
              <div style="display:inline-block;padding:16px 24px;background:${bg};border:1px solid ${border};border-radius:8px;font-family:'SF Mono',Menlo,Consolas,monospace;font-size:30px;letter-spacing:6px;color:${primary};font-weight:600;">{{code}}</div>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 24px;">
              <p style="margin:0;font-size:13px;color:${textMuted};line-height:1.5;">This code expires in 10 minutes. If you didn't request it, you can safely ignore this email — someone likely typed your address by mistake.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px 24px;border-top:1px solid ${border};">
              <p style="margin:0;font-size:11px;color:${textHint};line-height:1.5;">Sent to {{email}} by {{app_name}}.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`

  return new NextResponse(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
      'Access-Control-Allow-Origin': '*',
    },
  })
}
