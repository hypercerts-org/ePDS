import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { escapeHtml, maskEmail } from '@magic-pds/shared'
import { setAccountSessionCookie, type AuthenticatedRequest } from '../middleware/account-auth.js'
import { autoProvisionAccount } from '../lib/auto-provision.js'
import * as crypto from 'node:crypto'

const logger = createLogger('auth:account-login')

export function createAccountLoginRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  // GET /account/login - show email form
  router.get('/account/login', (req: AuthenticatedRequest, res: Response) => {
    if (req.accountSession) {
      res.redirect(303, '/account')
      return
    }
    res.type('html').send(renderLoginForm({ csrfToken: res.locals.csrfToken }))
  })

  // POST /account/login - send OTP code, render code input form
  router.post('/account/login', async (req: Request, res: Response) => {
    const email = (req.body.email as string || '').trim().toLowerCase()

    if (!email) {
      res.status(400).send(renderLoginForm({ csrfToken: res.locals.csrfToken, error: 'Email is required.' }))
      return
    }

    const ip = req.ip || req.socket.remoteAddress || null
    const rateLimitError = ctx.rateLimiter.check(email, ip)
    if (rateLimitError) {
      res.send(renderOtpForm({ email, sessionId: '', csrfToken: res.locals.csrfToken, error: 'Too many requests. Please wait a moment.' }))
      return
    }

    try {
      const deviceInfo = req.headers['user-agent'] || null
      const authRequestId = 'account-settings:' + crypto.randomBytes(16).toString('hex')
      const { code, sessionId } = ctx.tokenService.create({
        email,
        authRequestId,
        clientId: null,
        deviceInfo,
      })

      const isNewUser = !ctx.db.hasClientLogin(email, 'account-settings')

      await ctx.emailSender.sendOtpCode({
        to: email,
        code,
        clientAppName: 'Account Settings',
        pdsName: ctx.config.hostname,
        pdsDomain: ctx.config.pdsHostname,
        isNewUser,
      })

      ctx.rateLimiter.record(email, ip)
      res.send(renderOtpForm({ email, sessionId, csrfToken: res.locals.csrfToken }))
    } catch (err) {
      logger.error({ err }, 'Failed to send account login OTP')
      res.status(500).send(renderOtpForm({ email, sessionId: '', csrfToken: res.locals.csrfToken, error: 'Failed to send code.' }))
    }
  })

  // POST /account/verify-code - verify OTP and create account session
  router.post('/account/verify-code', async (req: Request, res: Response) => {
    const sessionId = req.body.session_id as string
    const code = (req.body.code as string || '').trim()
    const email = (req.body.email as string || '').trim().toLowerCase()

    if (!sessionId || !code || !email) {
      res.status(400).send('<p>Missing required fields.</p>')
      return
    }

    const result = ctx.tokenService.verifyCode(sessionId, code)

    if ('error' in result) {
      res.send(renderOtpForm({
        email,
        sessionId,
        csrfToken: res.locals.csrfToken,
        error: result.error,
      }))
      return
    }

    // Look up or auto-provision account
    let did = ctx.db.getDidByEmail(result.email)
    if (!did) did = ctx.db.getDidByBackupEmail(result.email)

    if (!did) {
      // Check PDS (source of truth) for existing account
      try {
        const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl
        const checkRes = await fetch(`${pdsUrl}/_magic/check-email?email=${encodeURIComponent(result.email)}`, { signal: AbortSignal.timeout(3000) })
        if (checkRes.ok) {
          const data = await checkRes.json() as { exists: boolean; did?: string }
          if (data.exists && data.did) {
            did = data.did
            // Sync the mapping to auth DB
            ctx.db.setAccountEmail(result.email, did)
          }
        }
      } catch { /* fall through to auto-provision */ }
    }

    if (!did) {
      did = await autoProvisionAccount(ctx, result.email) ?? undefined
      if (!did) {
        res.status(500).send('<p>Failed to create your account. Please try again.</p>')
        return
      }
    }

    // Record this client login (for per-client welcome vs sign-in emails)
    ctx.db.recordClientLogin(result.email, 'account-settings')

    // Create account session
    const accountSessionId = crypto.randomBytes(32).toString('hex')
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
    ctx.db.createAccountSession({
      sessionId: accountSessionId,
      did,
      email: result.email,
      expiresAt,
      userAgent: req.headers['user-agent'] || null,
      ipAddress: req.ip || req.socket.remoteAddress || null,
    })

    setAccountSessionCookie(res, accountSessionId)
    res.redirect(303, '/account')
  })

  // POST /account/logout
  router.post('/account/logout', (req: AuthenticatedRequest, res: Response) => {
    if (req.accountSession) {
      ctx.db.deleteAccountSession(req.accountSession.sessionId)
    }
    res.clearCookie('magic_account_session')
    res.redirect(303, '/account/login')
  })

  return router
}

function renderLoginForm(opts: {
  csrfToken: string
  error?: string
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account Settings - Sign In</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Account Settings</h1>
    <p class="subtitle">Sign in to manage your account</p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/account/login">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <div class="field">
        <label for="email">Email address</label>
        <input type="email" id="email" name="email" required autofocus
               placeholder="you@example.com">
      </div>
      <button type="submit" class="btn-primary"><img src="/static/certified_brandmark_white.png" alt="" style="height: 18px; vertical-align: middle; margin-right: 10px;"><span style="vertical-align: middle;">Sign in with Certified</span></button>
    </form>
  </div>
</body>
</html>`
}

function renderOtpForm(opts: {
  email: string
  sessionId: string
  csrfToken: string
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enter your code</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>Enter your code</h1>
    <p class="subtitle">We sent a 6-digit code to <strong>${escapeHtml(maskedEmail)}</strong></p>
    ${opts.error ? '<p class="error">' + escapeHtml(opts.error) + '</p>' : ''}
    <form method="POST" action="/account/verify-code">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="session_id" value="${escapeHtml(opts.sessionId)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <div class="field">
        <input type="text" id="code" name="code" required autofocus
               maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="one-time-code"
               placeholder="000000" class="otp-input">
      </div>
      <button type="submit" class="btn-primary">Verify</button>
    </form>
    <form method="POST" action="/account/login" style="margin-top: 12px;">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <button type="submit" class="btn-secondary">Resend code</button>
    </form>
  </div>
</body>
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
  .btn-secondary { display: inline-block; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
`
