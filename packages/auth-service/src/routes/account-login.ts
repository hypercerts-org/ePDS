import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { setSessionCookie } from '../middleware/session.js'
import { setAccountSessionCookie, type AuthenticatedRequest } from '../middleware/account-auth.js'
import * as crypto from 'node:crypto'

const logger = createLogger('auth:account-login')

export function createAccountLoginRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  // GET /account/login - show email form to log in for account management
  router.get('/account/login', (req: AuthenticatedRequest, res: Response) => {
    if (req.accountSession) {
      res.redirect(303, '/account')
      return
    }
    res.type('html').send(renderLoginForm({ csrfToken: res.locals.csrfToken }))
  })

  // POST /account/login - send magic link for account management
  router.post('/account/login', async (req: Request, res: Response) => {
    const email = (req.body.email as string || '').trim().toLowerCase()

    if (!email) {
      res.status(400).send(renderLoginForm({ csrfToken: res.locals.csrfToken, error: 'Email is required.' }))
      return
    }

    const ip = req.ip || req.socket.remoteAddress || null
    const rateLimitError = ctx.rateLimiter.check(email, ip)
    if (rateLimitError) {
      res.send(renderCheckEmail({ email, csrfToken: res.locals.csrfToken }))
      return
    }

    // Check if account exists (primary or backup email)
    let did = ctx.db.getDidByEmail(email)
    if (!did) did = ctx.db.getDidByBackupEmail(email)

    if (did) {
      try {
        const deviceInfo = req.headers['user-agent'] || null
        // Use a special auth request ID for account management sessions
        const authRequestId = 'account-settings:' + crypto.randomBytes(16).toString('hex')
        const { token, csrf } = ctx.tokenService.create({
          email,
          authRequestId,
          clientId: null,
          deviceInfo,
        })

        // Build URL pointing to /account/verify-session instead of /auth/verify
        const verifyBase = ctx.config.magicLink.baseUrl.replace('/auth/verify', '/account/verify-session')
        const verifyUrl = new URL(verifyBase)
        verifyUrl.searchParams.set('token', token)
        verifyUrl.searchParams.set('csrf', csrf)
        const magicLinkUrl = verifyUrl.toString()
        setSessionCookie(res, csrf)

        await ctx.emailSender.sendMagicLink({
          to: email,
          magicLinkUrl,
          clientAppName: 'Account Settings',
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
        })

        ctx.rateLimiter.record(email, ip)
        res.send(renderCheckEmail({ email, csrf, csrfToken: res.locals.csrfToken }))
      } catch (err) {
        logger.error({ err }, 'Failed to send account login magic link')
        res.status(500).send(renderCheckEmail({ email, csrfToken: res.locals.csrfToken, error: 'Failed to send email.' }))
      }
    } else {
      // No account found, still show check email (anti-enumeration)
      res.send(renderCheckEmail({ email, csrfToken: res.locals.csrfToken }))
    }
  })

  // GET /account/verify-session - verify magic link and create account session
  router.get('/account/verify-session', async (req: Request, res: Response) => {
    const token = req.query.token as string | undefined
    const csrfParam = req.query.csrf as string | undefined

    if (!token || !csrfParam) {
      res.status(400).send('<p>Invalid link.</p>')
      return
    }

    const sessionCsrf = req.cookies['magic_session']
    const result = ctx.tokenService.verify(token, sessionCsrf)

    if ('error' in result) {
      res.status(400).send('<p>' + result.error + '</p>')
      return
    }

    const { email } = result

    // Look up the DID
    let did = ctx.db.getDidByEmail(email)
    if (!did) did = ctx.db.getDidByBackupEmail(email)

    if (!did) {
      res.status(400).send('<p>No account found for this email.</p>')
      return
    }

    // Create an account session
    const sessionId = crypto.randomBytes(32).toString('hex')
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
    ctx.db.createAccountSession({
      sessionId,
      did,
      email,
      expiresAt,
      userAgent: req.headers['user-agent'] || null,
      ipAddress: req.ip || req.socket.remoteAddress || null,
    })

    setAccountSessionCookie(res, sessionId)
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

  // GET /account/status?csrf=... - polling for account login verification
  router.get('/account/status', (req: Request, res: Response) => {
    const csrf = req.query.csrf as string | undefined
    if (!csrf) {
      res.json({ status: 'expired' })
      return
    }

    const status = ctx.tokenService.checkStatus(csrf)

    if (status === 'verified') {
      const row = ctx.db.getMagicLinkTokenByCsrf(csrf)
      if (row) {
        // Token was verified (by clicking magic link on another device)
        // Create account session for THIS device too
        let did = ctx.db.getDidByEmail(row.email)
        if (!did) did = ctx.db.getDidByBackupEmail(row.email)

        if (did) {
          const sessionId = crypto.randomBytes(32).toString('hex')
          const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000
          ctx.db.createAccountSession({
            sessionId,
            did,
            email: row.email,
            expiresAt,
            userAgent: req.headers['user-agent'] || null,
            ipAddress: req.ip || req.socket.remoteAddress || null,
          })
          setAccountSessionCookie(res, sessionId)
          res.json({ status: 'verified', redirect: '/account' })
          return
        }
      }
    }

    res.json({ status })
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

function renderCheckEmail(opts: {
  email: string
  csrf?: string
  csrfToken: string
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const pollScript = opts.csrf ? `
    <script>
      (function() {
        var csrf = ${JSON.stringify(opts.csrf)};
        var attempts = 0;

        function poll() {
          if (attempts++ >= 300) return;
          fetch('/account/status?csrf=' + encodeURIComponent(csrf))
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.status === 'verified') {
                window.location.href = data.redirect || '/account';
              } else if (data.status === 'expired') {
                document.getElementById('poll-status').textContent = 'Link expired. Please try again.';
              } else {
                setTimeout(poll, 2000);
              }
            })
            .catch(function() { setTimeout(poll, 2000); });
        }
        poll();
      })();
    </script>` : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
<title>Check your email</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <div class="check-icon">&#9993;</div>
    <h1>Check your email</h1>
    ${opts.error
      ? '<p class="error">' + escapeHtml(opts.error) + '</p>'
      : '<p class="subtitle">We sent a sign-in link to <strong>' + escapeHtml(maskedEmail) + '</strong></p>'
    }
    <p class="info" id="poll-status">Waiting for you to click the link...</p>
  </div>
  ${pollScript}
</body>
</html>`
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@')
  if (!local || !domain) return email
  if (local.length <= 2) return local[0] + '***@' + domain
  return local[0] + '***' + local[local.length - 1] + '@' + domain
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
  .subtitle { color: #666; margin-bottom: 16px; font-size: 15px; line-height: 1.5; }
  .field { margin-bottom: 20px; text-align: left; }
  .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; }
  .field input:focus { border-color: #0f1828; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
  .btn-primary:hover { background: #1a2a40; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
  .info { color: #999; font-size: 14px; }
  .check-icon { font-size: 48px; margin-bottom: 16px; }
`
