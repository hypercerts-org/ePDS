import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { escapeHtml, maskEmail } from '@magic-pds/shared'

const logger = createLogger('auth:recovery')

export function createRecoveryRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.get('/auth/recover', (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string | undefined

    if (!requestUri) {
      res.status(400).send(renderError('Missing request_uri parameter'))
      return
    }

    res.type('html').send(renderRecoveryForm({
      requestUri,
      csrfToken: res.locals.csrfToken,
    }))
  })

  router.post('/auth/recover', async (req: Request, res: Response) => {
    const email = (req.body.email as string || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    if (!email || !requestUri) {
      res.status(400).send(renderRecoveryForm({
        requestUri: requestUri || '',
        csrfToken: res.locals.csrfToken,
        error: 'Email and request URI are required.',
      }))
      return
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).send(renderRecoveryForm({
        requestUri,
        csrfToken: res.locals.csrfToken,
        error: 'Please enter a valid email address.',
      }))
      return
    }

    const ip = req.ip || req.socket.remoteAddress || null
    const rateLimitError = ctx.rateLimiter.check(email, ip)
    if (rateLimitError) {
      // Anti-enumeration: show OTP form even if rate limited
      res.send(renderOtpForm({ email, sessionId: '', csrfToken: res.locals.csrfToken, requestUri, error: 'Too many requests. Please wait a moment.' }))
      return
    }

    // Look up backup email - ALWAYS show OTP form (anti-enumeration)
    const did = ctx.db.getDidByBackupEmail(email)

    if (did) {
      try {
        const deviceInfo = req.headers['user-agent'] || null
        const { code, sessionId } = ctx.tokenService.create({
          email,
          authRequestId: requestUri,
          clientId: null,
          deviceInfo,
        })

        await ctx.emailSender.sendOtpCode({
          to: email,
          code,
          clientAppName: 'account recovery',
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
        })

        ctx.rateLimiter.record(email, ip)

        res.send(renderOtpForm({
          email,
          sessionId,
          csrfToken: res.locals.csrfToken,
          requestUri,
        }))
      } catch (err) {
        logger.error({ err }, 'Failed to send recovery OTP')
        res.status(500).send(renderOtpForm({
          email,
          sessionId: '',
          csrfToken: res.locals.csrfToken,
          requestUri,
          error: 'Failed to send code. Please try again.',
        }))
      }
    } else {
      // No backup email found, but show OTP form anyway (anti-enumeration)
      res.send(renderOtpForm({
        email,
        sessionId: '',
        csrfToken: res.locals.csrfToken,
        requestUri,
      }))
    }
  })

  // POST /auth/recover/verify - verify recovery OTP
  router.post('/auth/recover/verify', async (req: Request, res: Response) => {
    const sessionId = req.body.session_id as string
    const code = (req.body.code as string || '').trim()
    const email = (req.body.email as string || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    if (!sessionId || !code || !email || !requestUri) {
      res.status(400).send('<p>Missing required fields.</p>')
      return
    }

    const result = ctx.tokenService.verifyCode(sessionId, code)

    if ('error' in result) {
      res.send(renderOtpForm({
        email,
        sessionId,
        csrfToken: res.locals.csrfToken,
        requestUri,
        error: result.error,
      }))
      return
    }

    // Recovery verified - redirect to consent
    const consentUrl = `/auth/consent?request_uri=${encodeURIComponent(result.authRequestId)}&email=${encodeURIComponent(result.email)}&new=0`
    res.redirect(303, consentUrl)
  })

  return router
}

function renderRecoveryForm(opts: {
  requestUri: string
  csrfToken: string
  error?: string
}): string {
  const encodedUri = encodeURIComponent(opts.requestUri)
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Recovery</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Account Recovery</h1>
    <p class="subtitle">Enter the backup email address associated with your account.</p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/auth/recover">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <div class="field">
        <label for="email">Backup email address</label>
        <input type="email" id="email" name="email" required autofocus
               placeholder="backup@example.com">
      </div>
      <button type="submit" class="btn-primary">Send recovery code</button>
    </form>
    <a href="/oauth/authorize?request_uri=${encodedUri}" class="btn-secondary">Back to sign in</a>
  </div>
</body>
</html>`
}

function renderOtpForm(opts: {
  email: string
  sessionId: string
  csrfToken: string
  requestUri: string
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const encodedUri = encodeURIComponent(opts.requestUri)

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enter recovery code</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Enter recovery code</h1>
    <p class="subtitle">If a backup email matches, we sent a 6-digit code to <strong>${escapeHtml(maskedEmail)}</strong></p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/auth/recover/verify">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="session_id" value="${escapeHtml(opts.sessionId)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <div class="field">
        <input type="text" id="code" name="code" required autofocus
               maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="one-time-code"
               placeholder="000000" class="otp-input">
      </div>
      <button type="submit" class="btn-primary">Verify</button>
    </form>
    <form method="POST" action="/auth/recover" style="margin-top: 12px;">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <button type="submit" class="btn-secondary">Resend code</button>
    </form>
    <a href="/oauth/authorize?request_uri=${encodedUri}" class="btn-secondary">Back to sign in</a>
  </div>
</body>
</html>`
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title><style>${CSS}</style></head>
<body><div class="container"><h1>Error</h1><p class="error">${escapeHtml(message)}</p></div></body>
</html>`
}



const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
  .subtitle { color: #666; margin-bottom: 20px; font-size: 15px; line-height: 1.5; }
  .field { margin-bottom: 20px; text-align: left; }
  .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; }
  .field input:focus { border-color: #0f1828; }
  .otp-input { font-size: 28px !important; text-align: center; letter-spacing: 8px; font-family: 'SF Mono', Menlo, Consolas, monospace !important; padding: 14px !important; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: #1a2a40; }
  .btn-secondary { display: inline-block; margin-top: 12px; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
`
