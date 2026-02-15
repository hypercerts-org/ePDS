import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { resolveClientName, resolveClientMetadata } from '../lib/client-metadata.js'
import { escapeHtml, createLogger } from '@magic-pds/shared'
import { renderOtpForm } from './send-code.js'

const logger = createLogger('auth:authorize')

/**
 * GET /oauth/authorize
 *
 * This is the authorization endpoint. The OAuth provider redirects here
 * after PAR. We show the email input form (or signup variant).
 */
export function createAuthorizeRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.get('/oauth/authorize', async (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string | undefined
    const clientId = req.query.client_id as string | undefined
    const prompt = req.query.prompt as string | undefined
    const loginHint = req.query.login_hint as string | undefined

    if (!requestUri) {
      res.status(400).send(renderError('Missing request_uri parameter'))
      return
    }

    // If login_hint contains an email, send OTP directly and show code entry form
    if (loginHint && loginHint.includes('@')) {
      const email = loginHint.trim().toLowerCase()
      const cid = clientId || ''
      const clientMeta = cid ? await resolveClientMetadata(cid) : {}

      const ip = req.ip || req.socket.remoteAddress || null
      const rateLimitError = ctx.rateLimiter.check(email, ip)
      if (rateLimitError) {
        res.send(renderOtpForm({
          email,
          sessionId: '',
          requestUri,
          clientId: cid,
          csrfToken: res.locals.csrfToken,
          error: 'Too many requests. Please wait a moment.',
          branding: clientMeta,
        }))
        return
      }

      try {
        const deviceInfo = req.headers['user-agent'] || null
        const { code, sessionId } = ctx.tokenService.create({
          email,
          authRequestId: requestUri,
          clientId: cid || null,
          deviceInfo,
        })

        const isNewUser = !ctx.db.hasClientLogin(email, cid || 'account-settings')
        const clientName = clientMeta.client_name || 'your application'

        await ctx.emailSender.sendOtpCode({
          to: email,
          code,
          clientAppName: clientName,
          clientId: cid || undefined,
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
          isNewUser,
        })

        ctx.rateLimiter.record(email, ip)

        res.send(renderOtpForm({
          email,
          sessionId,
          requestUri,
          clientId: cid,
          csrfToken: res.locals.csrfToken,
          branding: clientMeta,
        }))
      } catch (err) {
        logger.error({ err }, 'Failed to send OTP via login_hint')
        res.status(500).send(renderOtpForm({
          email,
          sessionId: '',
          requestUri,
          clientId: cid,
          csrfToken: res.locals.csrfToken,
          error: 'Failed to send code. Please try again.',
          branding: clientMeta,
        }))
      }
      return
    }

    const isSignup = prompt === 'create'
    const clientName = clientId ? await resolveClientName(clientId) : 'an application'

    res.type('html').send(renderEmailForm({
      requestUri,
      clientId: clientId || '',
      clientName,
      isSignup,
      csrfToken: res.locals.csrfToken,
      authBaseUrl: ctx.config.pdsPublicUrl,
    }))
  })

  return router
}

function renderEmailForm(opts: {
  requestUri: string
  clientId: string
  clientName: string
  isSignup: boolean
  csrfToken: string
  authBaseUrl: string
}): string {
  const title = opts.isSignup ? 'Create your account' : 'Sign in'
  const subtitle = opts.isSignup
    ? `Create an account to use with <strong>${escapeHtml(opts.clientName)}</strong>`
    : `Sign in to <strong>${escapeHtml(opts.clientName)}</strong>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p class="subtitle">${subtitle}</p>
    <form method="POST" action="/auth/send-code">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="client_id" value="${escapeHtml(opts.clientId)}">
      <input type="hidden" name="is_signup" value="${opts.isSignup ? '1' : '0'}">
      <div class="field">
        <label for="email">Email address</label>
        <input type="email" id="email" name="email" required autofocus
               placeholder="you@example.com">
      </div>
      <button type="submit" class="btn-primary">${opts.isSignup ? 'Create account' : 'Continue with email'}</button>
    </form>
    
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
  .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
  h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
  .subtitle { color: #666; margin-bottom: 24px; font-size: 15px; line-height: 1.5; }
  .field { margin-bottom: 20px; }
  .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
  .field input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; outline: none; transition: border-color 0.15s; }
  .field input:focus { border-color: #0f1828; }
  .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.15s; }
  .btn-primary:hover { background: #1a2a40; }
  .btn-secondary { display: inline-block; margin-top: 12px; color: #0f1828; text-decoration: none; font-size: 14px; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin-top: 12px; }
  .info { color: #666; font-size: 14px; margin-top: 16px; line-height: 1.5; }
  .check-icon { font-size: 48px; margin-bottom: 16px; }
`
