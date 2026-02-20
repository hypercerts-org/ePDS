/**
 * Account recovery via backup email.
 *
 * Flow:
 *   1. User enters their backup email address
 *   2. We look up the DID via backup_email table (auth-service-owned data)
 *   3. If found, send OTP to backup email via better-auth emailOTP plugin
 *   4. User enters OTP; we verify via better-auth
 *   5. Redirect to /auth/complete to complete the AT Protocol flow
 *
 * This follows the same bridge pattern as the main login flow:
 *   better-auth session → /auth/complete → HMAC-signed magic-callback
 *
 * Note: recovery uses the backup email as the verified identity. The auth_flow
 * table threads request_uri through the flow via magic_auth_flow cookie.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { escapeHtml, maskEmail } from '@magic-pds/shared'

const logger = createLogger('auth:recovery')

const AUTH_FLOW_COOKIE = 'magic_auth_flow'

export function createRecoveryRouter(ctx: AuthServiceContext, auth: any): Router {
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

    // Look up backup email - ALWAYS show OTP form (anti-enumeration)
    const did = ctx.db.getDidByBackupEmail(email)

    if (did) {
      try {
        // Ensure the auth_flow cookie is set so /auth/complete can thread the request_uri.
        // If one already exists from a previous step, we keep it; otherwise create a new one.
        let flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
        if (!flowId || !ctx.db.getAuthFlow(flowId)) {
          const { randomBytes } = await import('node:crypto')
          flowId = randomBytes(16).toString('hex')
          ctx.db.createAuthFlow({
            flowId,
            requestUri,
            clientId: null,
            expiresAt: Date.now() + 10 * 60 * 1000,
          })
          res.cookie(AUTH_FLOW_COOKIE, flowId, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'development',
            sameSite: 'lax',
            maxAge: 10 * 60 * 1000,
          })
        }

        // Send OTP via better-auth emailOTP plugin
        await auth.api.sendVerificationOTP({
          body: { email, type: 'sign-in' },
        })

        logger.info({ email }, 'Recovery OTP sent via better-auth')
        res.send(renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
        }))
      } catch (err) {
        logger.error({ err }, 'Failed to send recovery OTP')
        res.status(500).send(renderOtpForm({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          error: 'Failed to send code. Please try again.',
        }))
      }
    } else {
      // No backup email found, but show OTP form anyway (anti-enumeration)
      res.send(renderOtpForm({
        email,
        csrfToken: res.locals.csrfToken,
        requestUri,
      }))
    }
  })

  // POST /auth/recover/verify - verify recovery OTP via better-auth
  router.post('/auth/recover/verify', async (req: Request, res: Response) => {
    const code = (req.body.code as string || '').trim()
    const email = (req.body.email as string || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string

    if (!code || !email || !requestUri) {
      res.status(400).send('<p>Missing required fields.</p>')
      return
    }

    try {
      // Verify OTP via better-auth — this creates/updates a session
      const response = await auth.api.signInEmailOTP({
        body: { email, otp: code },
        asResponse: true,
      })

      // Forward better-auth's session cookie
      if (response instanceof Response || (response && typeof response.headers?.get === 'function')) {
        const setCookie = response.headers.get('set-cookie')
        if (setCookie) {
          res.setHeader('Set-Cookie', setCookie)
        }
      }

      // Redirect to /auth/complete which will read the better-auth session
      // and issue the HMAC-signed callback to pds-core
      logger.info({ email }, 'Recovery OTP verified, redirecting to /auth/complete')
      res.redirect(303, '/auth/complete')
    } catch (err: any) {
      logger.warn({ err, email }, 'Recovery OTP verification failed')
      const errMsg = err?.message?.includes('invalid') || err?.message?.includes('expired')
        ? 'Invalid or expired code. Please try again.'
        : 'Verification failed. Please try again.'
      res.send(renderOtpForm({
        email,
        csrfToken: res.locals.csrfToken,
        requestUri,
        error: errMsg,
      }))
    }
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
    <p class="subtitle">If a backup email matches, we sent an 8-digit code to <strong>${escapeHtml(maskedEmail)}</strong></p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/auth/recover/verify">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <div class="field">
        <input type="text" id="code" name="code" required autofocus
               maxlength="8" pattern="[0-9]{8}" inputmode="numeric" autocomplete="one-time-code"
               placeholder="00000000" class="otp-input">
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
