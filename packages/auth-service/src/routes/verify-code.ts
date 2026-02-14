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

    // Check if account exists (for display purposes only)
    // Account creation is handled by the PDS magic callback
    let did = ctx.db.getDidByEmail(result.email)
    if (!did) did = ctx.db.getDidByBackupEmail(result.email)

    const isNewAccount = !did

    // Redirect to consent screen
    const consentUrl = `/auth/consent?request_uri=${encodeURIComponent(result.authRequestId)}&email=${encodeURIComponent(result.email)}&new=${isNewAccount ? '1' : '0'}${result.clientId ? '&client_id=' + encodeURIComponent(result.clientId) : ''}`
    res.redirect(303, consentUrl)
  })

  return router
}
