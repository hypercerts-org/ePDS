import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { setSessionCookie } from '../middleware/session.js'

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
      res.send(renderCheckRecoveryEmail({ email, csrfToken: res.locals.csrfToken, requestUri }))
      return
    }

    // Look up backup email - ALWAYS show "check your email" (anti-enumeration)
    const did = ctx.db.getDidByBackupEmail(email)

    if (did) {
      try {
        const deviceInfo = req.headers['user-agent'] || null
        const { token, csrf } = ctx.tokenService.create({
          email,
          authRequestId: requestUri,
          clientId: null,
          deviceInfo,
        })

        const magicLinkUrl = ctx.tokenService.buildUrl(token, csrf)
        setSessionCookie(res, csrf)

        await ctx.emailSender.sendMagicLink({
          to: email,
          magicLinkUrl,
          clientAppName: 'account recovery',
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
        })

        ctx.rateLimiter.record(email, ip)

        res.send(renderCheckRecoveryEmail({
          email,
          csrf,
          csrfToken: res.locals.csrfToken,
          requestUri,
        }))
      } catch (err) {
        logger.error({ err }, 'Failed to send recovery magic link')
        res.status(500).send(renderCheckRecoveryEmail({
          email,
          csrfToken: res.locals.csrfToken,
          requestUri,
          error: 'Failed to send email. Please try again.',
        }))
      }
    } else {
      res.send(renderCheckRecoveryEmail({
        email,
        csrfToken: res.locals.csrfToken,
        requestUri,
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
      <button type="submit" class="btn-primary">Send recovery link</button>
    </form>
    <a href="/oauth/authorize?request_uri=${encodedUri}" class="btn-secondary">Back to sign in</a>
  </div>
</body>
</html>`
}

function renderCheckRecoveryEmail(opts: {
  email: string
  csrf?: string
  csrfToken: string
  requestUri: string
  error?: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const encodedUri = encodeURIComponent(opts.requestUri)
  const pollScript = opts.csrf ? `
    <script>
      (function() {
        var csrf = ${JSON.stringify(opts.csrf)};
        var attempts = 0;
        var maxAttempts = 300;

        function poll() {
          if (attempts++ >= maxAttempts) return;
          fetch('/auth/status?csrf=' + encodeURIComponent(csrf))
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.status === 'verified' && data.redirect) {
                window.location.href = data.redirect;
              } else if (data.status === 'expired') {
                document.getElementById('poll-status').textContent = 'Link expired. Please request a new one.';
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
    <h1>Check your backup email</h1>
    ${opts.error
      ? '<p class="error">' + escapeHtml(opts.error) + '</p>'
      : '<p class="subtitle">If a backup email matches, we sent a recovery link to <strong>' + escapeHtml(maskedEmail) + '</strong></p>'
    }
    <p class="info" id="poll-status">Waiting for you to click the link...</p>
    <form method="POST" action="/auth/recover" style="margin-top: 20px">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <button type="submit" class="btn-secondary">Resend link</button>
    </form>
    <a href="/oauth/authorize?request_uri=${encodedUri}" class="btn-secondary">Back to sign in</a>
  </div>
  ${pollScript}
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
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; transition: border-color 0.15s; }
  .field input:focus { border-color: #0f1828; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.15s; }
  .btn-primary:hover { background: #1a2a40; }
  .btn-secondary { display: inline-block; margin-top: 12px; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; }
  .info { color: #999; font-size: 14px; }
  .check-icon { font-size: 48px; margin-bottom: 16px; }
`
