import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { resolveClientName } from '../lib/client-metadata.js'
import { escapeHtml, signCallback } from '@magic-pds/shared'

/**
 * GET /auth/consent
 * POST /auth/consent
 *
 * Shows the consent screen and handles the approve/deny decision.
 */
export function createConsentRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.get('/auth/consent', async (req: Request, res: Response) => {
    const requestUri = req.query.request_uri as string
    const email = req.query.email as string
    const isNew = req.query.new === '1'
    const clientId = req.query.client_id as string | undefined

    if (!requestUri || !email) {
      res.status(400).send('<p>Missing parameters</p>')
      return
    }

    const clientName = clientId ? await resolveClientName(clientId) : 'the application'

    res.type('html').send(renderConsent({
      requestUri,
      email,
      isNew,
      clientId: clientId || '',
      clientName,
      csrfToken: res.locals.csrfToken,
    }))
  })

  router.post('/auth/consent', async (req: Request, res: Response) => {
    const requestUri = req.body.request_uri as string
    const email = req.body.email as string
    const isNew = req.body.is_new === '1'
    const action = req.body.action as string

    if (!requestUri || !email) {
      res.status(400).send('<p>Missing parameters</p>')
      return
    }

    if (action === 'deny') {
      // Redirect back to client with access_denied error
      // The PDS oauth provider will handle this via the request_uri
      res.redirect(303, `${ctx.config.pdsPublicUrl}/oauth/authorize?request_uri=${encodeURIComponent(requestUri)}&error=access_denied`)
      return
    }

    // action === 'approve'
    // At this point we need to:
    // 1. Create the account if new
    // 2. Signal to the PDS oauth-provider that the user is authenticated
    // 3. The PDS will issue the authorization code and redirect back to the client

    // Redirect to the PDS with HMAC-signed auth info so pds-core can verify
    // the redirect was produced by a legitimate auth-service flow.
    const callbackParams = {
      request_uri: requestUri,
      email,
      approved: '1',
      new_account: isNew ? '1' : '0',
    }
    const { sig, ts } = signCallback(callbackParams, ctx.config.magicCallbackSecret)
    const params = new URLSearchParams({ ...callbackParams, ts, sig })

    res.redirect(303, `${ctx.config.pdsPublicUrl}/oauth/magic-callback?${params.toString()}`)
  })

  return router
}

function renderConsent(opts: {
  requestUri: string
  email: string
  isNew: boolean
  clientId: string
  clientName: string
  csrfToken: string
}): string {
  const title = opts.isNew ? 'Create Account & Authorize' : 'Authorize Application'

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
    .subtitle { color: #666; margin-bottom: 24px; font-size: 15px; line-height: 1.5; }
    .permissions { background: #f8f9fa; border-radius: 8px; padding: 16px; margin-bottom: 24px; }
    .permissions h3 { font-size: 14px; color: #333; margin-bottom: 8px; }
    .permissions li { color: #555; font-size: 14px; line-height: 1.8; list-style: none; padding-left: 20px; position: relative; }
    .permissions li::before { content: "\\2713"; position: absolute; left: 0; color: #28a745; }
    .account-info { background: #f0f7ff; border-radius: 8px; padding: 12px; margin-bottom: 24px; font-size: 14px; color: #0056b3; }
    .actions { display: flex; gap: 12px; }
    .btn { flex: 1; padding: 12px; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
    .btn-approve { background: #0f1828; color: white; }
    .btn-approve:hover { background: #1a2a40; }
    .btn-deny { background: #f0f0f0; color: #333; }
    .btn-deny:hover { background: #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p class="subtitle"><strong>${escapeHtml(opts.clientName)}</strong> wants to access your account</p>

    ${opts.isNew ? '<div class="account-info">A new account will be created for <strong>' + escapeHtml(opts.email) + '</strong></div>' : ''}

    <div class="permissions">
      <h3>Requested permissions:</h3>
      <ul>
        <li>Read and write posts</li>
        <li>Access your profile</li>
        <li>Manage your follows</li>
      </ul>
    </div>

    <form method="POST" action="/auth/consent">
      <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
      <input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <input type="hidden" name="is_new" value="${opts.isNew ? '1' : '0'}">
      <div class="actions">
        <button type="submit" name="action" value="deny" class="btn btn-deny">Deny</button>
        <button type="submit" name="action" value="approve" class="btn btn-approve">Approve</button>
      </div>
    </form>
  </div>
</body>
</html>`
}

