import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'
import { renderOtpForm } from './send-code.js'

const logger = createLogger('auth:verify-code')

export function createVerifyCodeRouter(ctx: AuthServiceContext): Router {
  const router = Router()

  router.post('/auth/verify-code', async (req: Request, res: Response) => {
    const sessionId = req.body.session_id as string
    const code = (req.body.code as string || '').trim()
    const requestUri = req.body.request_uri as string
    const clientId = req.body.client_id as string || ''
    const email = (req.body.email as string || '').trim().toLowerCase()

    if (!sessionId || !code || !requestUri || !email) {
      res.status(400).send('<p>Missing required fields.</p>')
      return
    }

    const result = ctx.tokenService.verifyCode(sessionId, code)

    if ('error' in result) {
      res.send(renderOtpForm({
        email,
        sessionId,
        requestUri,
        clientId,
        csrfToken: res.locals.csrfToken,
        error: result.error,
      }))
      return
    }

    // Check if account exists (for the magic callback)
    let did = ctx.db.getDidByEmail(result.email)
    if (!did) did = ctx.db.getDidByBackupEmail(result.email)
    const isNewAccount = !did

    // Existing user + first time on this client: show consent screen
    const needsConsent = !isNewAccount && clientId && !ctx.db.hasClientLogin(result.email, clientId)

    // Record this client login (for per-client welcome vs sign-in emails)
    ctx.db.recordClientLogin(result.email, clientId || 'account-settings')

    if (needsConsent) {
      const consentUrl = `/auth/consent?request_uri=${encodeURIComponent(result.authRequestId)}&email=${encodeURIComponent(result.email)}&new=0&client_id=${encodeURIComponent(clientId)}`
      res.redirect(303, consentUrl)
      return
    }

    // New user: skip consent — account creation implies consent.
    // Account creation (if new) is handled by the PDS magic callback.
    const params = new URLSearchParams({
      request_uri: result.authRequestId,
      email: result.email,
      approved: '1',
      new_account: isNewAccount ? '1' : '0',
    })
    res.redirect(303, `${ctx.config.pdsPublicUrl}/oauth/magic-callback?${params.toString()}`)
  })

  return router
}
