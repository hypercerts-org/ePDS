import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { resolveClientName } from '../lib/client-metadata.js'
import { setSessionCookie } from '../middleware/session.js'

/**
 * POST /auth/send-magic-link
 *
 * Sends a magic link email. Responds with the "check your email" page.
 */
const logger = createLogger('auth:send-link')

export function createSendLinkRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.post('/auth/send-magic-link', async (req: Request, res: Response) => {
    const email = (req.body.email as string || '').trim().toLowerCase()
    const requestUri = req.body.request_uri as string
    const isSignup = req.body.is_signup === '1'
    const isRecovery = req.body.is_recovery === '1'
    const clientId = req.body.client_id as string || ''

    if (!email || !requestUri) {
      res.status(400).send(renderCheckEmail({
        email,
        error: 'Email and request URI are required.',
        csrfToken: res.locals.csrfToken,
        requestUri,
        clientId,
      }))
      return
    }

    // Basic email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).send(renderCheckEmail({
        email,
        error: 'Please enter a valid email address.',
        csrfToken: res.locals.csrfToken,
        requestUri,
        clientId,
      }))
      return
    }

    // Rate limit check
    const ip = req.ip || req.socket.remoteAddress || null
    const rateLimitError = ctx.rateLimiter.check(email, ip)
    if (rateLimitError) {
      // Same response whether rate limited or not (anti-enumeration)
      res.send(renderCheckEmail({
        email,
        csrfToken: res.locals.csrfToken,
        requestUri,
        clientId,
      }))
      return
    }

    // If not signup and not recovery, check if account exists.
    // But DON'T reveal this to the user (anti-enumeration).
    // Always show the same "check your email" page.
    let shouldSend = true
    if (!isSignup && !isRecovery) {
      const did = ctx.db.getDidByEmail(email)
      if (!did) {
        // No account, but we'll still show "check your email" (anti-enumeration)
        // For signup flows or if account doesn't exist, we still send the link
        // and create the account on verification
        shouldSend = true // Send anyway - account will be created on verify
      }
    }

    if (shouldSend) {
      try {
        // Create magic link token
        const deviceInfo = req.headers['user-agent'] || null
        const { token, csrf } = ctx.tokenService.create({
          email,
          authRequestId: requestUri,
          clientId: clientId || null,
          deviceInfo,
        })

        // Build the magic link URL
        const magicLinkUrl = ctx.tokenService.buildUrl(token, csrf)

        // Set session cookie for same-device detection
        setSessionCookie(res, csrf)

        // Send the email
        await ctx.emailSender.sendMagicLink({
          to: email,
          magicLinkUrl,
          clientAppName: clientId ? await resolveClientName(clientId) : 'your application',
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
        })

        // Record the send for rate limiting
        ctx.rateLimiter.record(email, ip)

        // Render check email page with polling
        res.send(renderCheckEmail({
          email,
          csrf,
          csrfToken: res.locals.csrfToken,
          requestUri,
          clientId,
        }))
      } catch (err) {
        logger.error({ err }, 'Failed to send magic link')
        res.status(500).send(renderCheckEmail({
          email,
          error: 'Failed to send email. Please try again.',
          csrfToken: res.locals.csrfToken,
          requestUri,
          clientId,
        }))
      }
    } else {
      // Still show "check your email" to prevent enumeration
      res.send(renderCheckEmail({
        email,
        csrfToken: res.locals.csrfToken,
        requestUri,
        clientId,
      }))
    }
  })

  return router
}

function renderCheckEmail(opts: {
  email: string
  csrf?: string
  error?: string
  csrfToken: string
  requestUri: string
  clientId: string
}): string {
  const maskedEmail = maskEmail(opts.email)
  const pollScript = opts.csrf ? `
    <script>
      (function() {
        const csrf = ${JSON.stringify(opts.csrf)};
        let attempts = 0;
        const maxAttempts = 300; // 10 minutes at 2s intervals

        function poll() {
          if (attempts++ >= maxAttempts) return;
          fetch('/auth/status?csrf=' + encodeURIComponent(csrf))
            .then(r => r.json())
            .then(data => {
              if (data.status === 'verified' && data.redirect) {
                window.location.href = data.redirect;
              } else if (data.status === 'expired') {
                document.getElementById('poll-status').textContent = 'Link expired. Please request a new one.';
              } else {
                setTimeout(poll, 2000);
              }
            })
            .catch(() => setTimeout(poll, 2000));
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
    <form method="POST" action="/auth/send-magic-link" style="margin-top: 20px;">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="client_id" value="${escapeHtml(opts.clientId)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <button type="submit" class="btn-secondary">Resend link</button>
    </form>
    <a href="/oauth/authorize?request_uri=${encodeURIComponent(opts.requestUri)}&client_id=${encodeURIComponent(opts.clientId)}" class="btn-secondary">Use a different email</a>
    <a href="/auth/recover?request_uri=${encodeURIComponent(opts.requestUri)}" class="btn-secondary">Can&#39;t access your email?</a>
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
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin: 12px 0; text-align: left; }
  .info { color: #999; font-size: 14px; }
  .check-icon { font-size: 48px; margin-bottom: 16px; }
  .btn-secondary { display: inline-block; margin-top: 8px; color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
`
