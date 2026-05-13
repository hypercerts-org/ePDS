/**
 * In-browser email previews.
 *
 * Renders each of the transactional emails the auth-service sends
 * (new-user welcome/verify, returning-user sign-in OTP, backup-email
 * verification) inside a sandboxed iframe so operators and client-app
 * developers can see exactly what users will receive without hitting
 * SMTP or walking a real flow.
 *
 * The email HTML comes from the same pure builders the real sender uses
 * (`packages/auth-service/src/email/templates.ts`), so what's rendered
 * here is bit-for-bit what production would put in the envelope.
 *
 * Gated by `AUTH_PREVIEW_ROUTES=1` along with the rest of /preview/*.
 *
 * Query params (all optional):
 *   ?otp=<code>        override the fixture OTP (default: 123456).
 *   ?app=<name>        override the fallback app name for the
 *                      returning-user template (default: Preview Client).
 *   ?to=<email>        override the rendered "To:" header.
 *   ?client_id=<URL>   render a client-branded template for the
 *                      new-user / returning-user routes. Gated on the
 *                      real trusted-clients list (`PDS_OAUTH_TRUSTED_CLIENTS`)
 *                      and the client's `email_template_uri`. Falls
 *                      back to the default template if the client is
 *                      untrusted, advertises no `email_template_uri`,
 *                      or the template fetch fails — mirrors real-
 *                      sender behaviour bit-for-bit.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { escapeHtml } from '@certified-app/shared'
import {
  buildSignInCodeEmail,
  buildWelcomeCodeEmail,
  buildBackupEmailVerificationEmail,
  type RenderedEmail,
} from '../email/templates.js'
import { buildClientBrandedEmail } from '../email/client-template.js'

const FAKE_OTP = '123456'
const FAKE_TO = 'alice@example.com'
const FAKE_APP_NAME = 'Preview Client'
const FAKE_VERIFY_URL =
  'https://auth.preview.example/account/verify-backup?token=preview-token-0000'

function queryString(req: Request, name: string): string | undefined {
  const v = req.query[name]
  return typeof v === 'string' ? v : undefined
}

function sendHtml(res: Response, html: string): void {
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.setHeader('Cache-Control', 'no-store')
  res.send(html)
}

function pdsIdentity(ctx: AuthServiceContext): {
  pdsName: string
  pdsDomain: string
} {
  // Mirror better-auth.ts: the real sender uses SMTP_FROM_NAME (which
  // config.email.fromName is built from), not the auth-service hostname.
  // Using config.hostname here would diverge the preview subject/footer
  // from what production actually delivers.
  return {
    pdsName: ctx.config.email.fromName,
    pdsDomain: ctx.config.pdsHostname,
  }
}

/**
 * Wrap a rendered email in a preview shell: from/to/subject headers and
 * an iframe with `srcdoc` so the email's CSS cannot bleed into — or read
 * from — the outer preview page.
 */
function renderEmailPreview(opts: {
  kind: string
  description: string
  fromName: string
  fromAddress: string
  to: string
  email: RenderedEmail
  backHref: string
}): string {
  const { kind, description, fromName, fromAddress, to, email, backHref } = opts
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
  <title>Email preview — ${escapeHtml(kind)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 820px; margin: 24px auto; padding: 0 16px; color: #222; }
    h1 { font-size: 20px; margin: 0 0 4px; }
    .desc { color: #555; margin: 0 0 16px; }
    .back { font-size: 13px; }
    .headers { border: 1px solid #e5e7eb; border-radius: 8px 8px 0 0; background: #f8f9fa; padding: 12px 16px; }
    .headers dl { display: grid; grid-template-columns: max-content 1fr; column-gap: 12px; row-gap: 4px; margin: 0; font-size: 14px; }
    .headers dt { color: #666; font-weight: 500; }
    .headers dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
    iframe { width: 100%; height: 640px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; background: white; }
    details { margin-top: 16px; }
    summary { cursor: pointer; font-size: 14px; color: #0b5ed7; }
    pre { background: #f0f0f0; padding: 10px 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
  </style>
</head>
<body>
  <p class="back"><a href="${escapeHtml(backHref)}">&larr; Back to previews</a></p>
  <h1>${escapeHtml(kind)}</h1>
  <p class="desc">${escapeHtml(description)}</p>
  <div class="headers">
    <dl>
      <dt>From</dt><dd>${escapeHtml(fromName)} &lt;${escapeHtml(fromAddress)}&gt;</dd>
      <dt>To</dt><dd>${escapeHtml(to)}</dd>
      <dt>Subject</dt><dd>${escapeHtml(email.subject)}</dd>
    </dl>
  </div>
  <iframe
    title="Rendered email body"
    sandbox=""
    srcdoc="${escapeHtml(email.html)}"></iframe>
  <details>
    <summary>Plain-text alternative</summary>
    <pre>${escapeHtml(email.text)}</pre>
  </details>
</body>
</html>`
}

export function createPreviewEmailsRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  // Match the gate in createPreviewRouter: /preview/* is 404 unless the
  // flag is on. Checked per-request so the flag can flip without a restart.
  router.use('/preview/emails', (_req, res, next) => {
    if (process.env.AUTH_PREVIEW_ROUTES !== '1') {
      res.status(404).send('Not Found')
      return
    }
    next()
  })

  const defaultFromName = ctx.config.email.fromName
  const fromAddress = ctx.config.email.from

  const render = (
    req: Request,
    kind: string,
    description: string,
    email: RenderedEmail,
    fromNameOverride?: string,
  ): string =>
    renderEmailPreview({
      kind,
      description,
      fromName: fromNameOverride ?? defaultFromName,
      fromAddress,
      to: queryString(req, 'to') ?? FAKE_TO,
      email,
      backHref: '/preview',
    })

  /**
   * If `?client_id=` is present and the client is trusted, render the
   * branded template it advertises; otherwise (untrusted / no template
   * / fetch failure) fall through to `fallback`. Mirrors the real
   * sender's gating exactly.
   */
  async function brandedOrFallback(
    req: Request,
    code: string,
    isNewUser: boolean,
    fallback: RenderedEmail,
  ): Promise<{ email: RenderedEmail; fromName?: string }> {
    const clientId = queryString(req, 'client_id')
    if (!clientId) return { email: fallback }
    const { pdsName, pdsDomain } = pdsIdentity(ctx)
    const branded = await buildClientBrandedEmail({
      clientId,
      code,
      isNewUser,
      toEmail: queryString(req, 'to') ?? FAKE_TO,
      fallbackAppName: queryString(req, 'app') ?? FAKE_APP_NAME,
      fallbackFromName: defaultFromName,
      pdsName,
      pdsDomain,
      trustedClients: ctx.config.trustedClients,
    })
    if (!branded) return { email: fallback }
    return {
      email: {
        subject: branded.subject,
        text: branded.text,
        html: branded.html,
      },
      fromName: branded.fromName,
    }
  }

  router.get(
    '/preview/emails/new-user',
    async (req: Request, res: Response) => {
      const code = queryString(req, 'otp') ?? FAKE_OTP
      const fallback = buildWelcomeCodeEmail({ code, ...pdsIdentity(ctx) })
      const { email, fromName } = await brandedOrFallback(
        req,
        code,
        true,
        fallback,
      )
      sendHtml(
        res,
        render(
          req,
          'New user — welcome / email verification',
          'Sent when a user signs up. Contains the OTP they enter to confirm their email and finish creating their account.',
          email,
          fromName,
        ),
      )
    },
  )

  router.get(
    '/preview/emails/returning-user',
    async (req: Request, res: Response) => {
      const code = queryString(req, 'otp') ?? FAKE_OTP
      const fallback = buildSignInCodeEmail({
        code,
        clientAppName: queryString(req, 'app') ?? FAKE_APP_NAME,
        ...pdsIdentity(ctx),
      })
      const { email, fromName } = await brandedOrFallback(
        req,
        code,
        false,
        fallback,
      )
      sendHtml(
        res,
        render(
          req,
          'Returning user — sign-in OTP',
          'Sent when an existing user signs in to a client app. Contains the OTP they enter to complete the sign-in.',
          email,
          fromName,
        ),
      )
    },
  )

  router.get('/preview/emails/recovery', (req: Request, res: Response) => {
    const email = buildBackupEmailVerificationEmail({
      verifyUrl: queryString(req, 'verify_url') ?? FAKE_VERIFY_URL,
      ...pdsIdentity(ctx),
    })
    sendHtml(
      res,
      render(
        req,
        'Account recovery — backup email verification',
        'Sent when a user adds a backup email to their account. Contains the link they click to prove they control the address.',
        email,
      ),
    )
  })

  return router
}
