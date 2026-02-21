import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { resolveClientName } from '../lib/client-metadata.js'
import { escapeHtml, signCallback } from '@certified-app/shared'
import { createLogger } from '@certified-app/shared'

const logger = createLogger('auth:consent')

const AUTH_FLOW_COOKIE = 'magic_auth_flow'

/**
 * GET /auth/consent
 * POST /auth/consent
 *
 * Shows the consent screen and handles the approve/deny decision.
 *
 * Supports two modes:
 * 1. flow_id mode (new): reads request_uri/client_id from auth_flow table.
 *    The complete.ts bridge passes flow_id when consent is needed so that
 *    we can maintain a single source of truth and avoid long URLs.
 * 2. Legacy mode: reads request_uri/email/client_id from query params directly
 *    (used by the old magic-link OTP path which is still active).
 */
export function createConsentRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.get('/auth/consent', async (req: Request, res: Response) => {
    const flowId = req.query.flow_id as string | undefined

    if (flowId) {
      // New mode: look up auth_flow by flow_id
      const flow = ctx.db.getAuthFlow(flowId)
      if (!flow) {
        logger.warn({ flowId }, 'auth_flow not found or expired on consent GET')
        res
          .status(400)
          .send('<p>Authentication session expired. Please try again.</p>')
        return
      }

      const email = req.query.email as string | undefined
      const isNew = req.query.new === '1'
      const clientId = flow.clientId ?? ''
      const clientName = clientId
        ? await resolveClientName(clientId)
        : 'the application'

      res.type('html').send(
        renderConsent({
          flowId,
          requestUri: flow.requestUri,
          email: email ?? '',
          isNew,
          clientId,
          clientName,
          csrfToken: res.locals.csrfToken,
        }),
      )
      return
    }

    // Legacy mode: request_uri passed directly in query params
    const requestUri = req.query.request_uri as string
    const email = req.query.email as string
    const isNew = req.query.new === '1'
    const clientId = req.query.client_id as string | undefined

    if (!requestUri || !email) {
      res.status(400).send('<p>Missing parameters</p>')
      return
    }

    const clientName = clientId
      ? await resolveClientName(clientId)
      : 'the application'

    res.type('html').send(
      renderConsent({
        flowId: undefined,
        requestUri,
        email,
        isNew,
        clientId: clientId || '',
        clientName,
        csrfToken: res.locals.csrfToken,
      }),
    )
  })

  router.post('/auth/consent', async (req: Request, res: Response) => {
    const flowId = req.body.flow_id as string | undefined
    const action = req.body.action as string

    let requestUri: string
    let email: string
    let isNew: boolean
    let clientId: string

    if (flowId) {
      // New mode: look up auth_flow by flow_id
      const flow = ctx.db.getAuthFlow(flowId)
      if (!flow) {
        logger.warn(
          { flowId },
          'auth_flow not found or expired on consent POST',
        )
        res
          .status(400)
          .send('<p>Authentication session expired. Please try again.</p>')
        return
      }

      requestUri = flow.requestUri
      email = ((req.body.email as string) || '').trim().toLowerCase()
      isNew = req.body.is_new === '1'
      clientId = flow.clientId ?? ''

      if (!email) {
        res.status(400).send('<p>Missing email parameter</p>')
        return
      }

      // Cleanup the auth_flow row and cookie after reading it
      ctx.db.deleteAuthFlow(flowId)
      res.clearCookie(AUTH_FLOW_COOKIE)
    } else {
      // Legacy mode: direct params
      requestUri = req.body.request_uri as string
      email = req.body.email as string
      isNew = req.body.is_new === '1'
      clientId = (req.body.client_id as string) || ''

      if (!requestUri || !email) {
        res.status(400).send('<p>Missing parameters</p>')
        return
      }
    }

    if (action === 'deny') {
      // Redirect back to client with access_denied error via the PDS oauth provider
      res.redirect(
        303,
        `${ctx.config.pdsPublicUrl}/oauth/authorize?request_uri=${encodeURIComponent(requestUri)}&error=access_denied`,
      )
      return
    }

    // action === 'approve'
    // Record first-time consent for this email+client combination
    if (clientId) {
      ctx.db.recordClientLogin(email, clientId)
    }

    // Build HMAC-signed redirect URL to pds-core /oauth/magic-callback
    const callbackParams = {
      request_uri: requestUri,
      email,
      approved: '1',
      new_account: isNew ? '1' : '0',
    }
    const { sig, ts } = signCallback(
      callbackParams,
      ctx.config.magicCallbackSecret,
    )
    const params = new URLSearchParams({ ...callbackParams, ts, sig })

    logger.info(
      { email, isNew, clientId },
      'Consent approved, redirecting to magic-callback',
    )
    res.redirect(
      303,
      `${ctx.config.pdsPublicUrl}/oauth/magic-callback?${params.toString()}`,
    )
  })

  return router
}

function renderConsent(opts: {
  flowId: string | undefined
  requestUri: string
  email: string
  isNew: boolean
  clientId: string
  clientName: string
  csrfToken: string
}): string {
  const title = opts.isNew
    ? 'Create Account & Authorize'
    : 'Authorize Application'

  // Hidden fields: use flow_id if available, otherwise fall back to direct params
  const hiddenFields = opts.flowId
    ? `<input type="hidden" name="flow_id" value="${escapeHtml(opts.flowId)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <input type="hidden" name="is_new" value="${opts.isNew ? '1' : '0'}">`
    : `<input type="hidden" name="request_uri" value="${escapeHtml(opts.requestUri)}">
      <input type="hidden" name="email" value="${escapeHtml(opts.email)}">
      <input type="hidden" name="client_id" value="${escapeHtml(opts.clientId)}">
      <input type="hidden" name="is_new" value="${opts.isNew ? '1' : '0'}">`

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
      ${hiddenFields}
      <div class="actions">
        <button type="submit" name="action" value="deny" class="btn btn-deny">Deny</button>
        <button type="submit" name="action" value="approve" class="btn btn-approve">Approve</button>
      </div>
    </form>
  </div>
</body>
</html>`
}
