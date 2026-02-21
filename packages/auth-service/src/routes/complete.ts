/**
 * GET /auth/complete
 *
 * Bridge route: called by better-auth after successful authentication
 * (this is the `callbackURL` passed to better-auth sign-in methods).
 *
 * Translates a better-auth session into an HMAC-signed redirect to
 * pds-core's /oauth/magic-callback, threading the AT Protocol request_uri
 * through the flow via the auth_flow table.
 *
 * Flow:
 *   1. Read magic_auth_flow cookie → get flow_id
 *   2. Look up auth_flow row → get request_uri, client_id
 *   3. Get better-auth session → extract verified email
 *   4. Check if consent needed (first-time client login for existing accounts)
 *   5a. Needs consent → redirect to /auth/consent?flow_id=...
 *   5b. No consent needed → build HMAC-signed redirect to pds-core /oauth/magic-callback
 *   6. Delete auth_flow row + clear cookie
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger, signCallback } from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'

const logger = createLogger('auth:complete')

const AUTH_FLOW_COOKIE = 'magic_auth_flow'

export function createCompleteRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()

  router.get('/auth/complete', async (req: Request, res: Response) => {
    // Step 1: Get flow_id from cookie
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    if (!flowId) {
      logger.warn('No magic_auth_flow cookie found on /auth/complete')
      res
        .status(400)
        .send('<p>Authentication session expired. Please try again.</p>')
      return
    }

    // Step 2: Look up auth_flow row
    const flow = ctx.db.getAuthFlow(flowId)
    if (!flow) {
      logger.warn({ flowId }, 'auth_flow not found or expired')
      res.clearCookie(AUTH_FLOW_COOKIE)
      res
        .status(400)
        .send('<p>Authentication session expired. Please try again.</p>')
      return
    }

    // Step 3: Get better-auth session to extract verified email
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let session: any
    try {
      session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
    } catch (err) {
      logger.error({ err }, 'Failed to get better-auth session')
      res.status(500).send('<p>Authentication failed. Please try again.</p>')
      return
    }

    if (!session?.user?.email) {
      logger.warn(
        { flowId },
        'No authenticated session found on /auth/complete',
      )
      // Redirect back to auth flow with error — user needs to authenticate
      const authUrl =
        `/oauth/authorize?request_uri=${encodeURIComponent(flow.requestUri)}` +
        (flow.clientId ? `&client_id=${encodeURIComponent(flow.clientId)}` : '')
      res.redirect(303, authUrl)
      return
    }

    const email = session.user.email.toLowerCase()

    // Step 4: Check whether this is a new account and whether consent is needed.
    // Consent is required for existing accounts logging into a new client for the first time.
    // New accounts (no PDS account yet) skip consent since account creation implies consent.
    let isNewAccount = false
    try {
      const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl
      const internalSecret = process.env.MAGIC_INTERNAL_SECRET
      const checkRes = await fetch(
        `${pdsUrl}/_internal/account-by-email?email=${encodeURIComponent(email)}`,
        {
          headers: { 'x-internal-secret': internalSecret ?? '' },
          signal: AbortSignal.timeout(3000),
        },
      )
      if (checkRes.ok) {
        const data = (await checkRes.json()) as { did: string | null }
        isNewAccount = !data.did
      }
    } catch (err) {
      logger.warn(
        { err, email },
        'Failed to check PDS account existence, assuming existing account',
      )
    }

    const clientId = flow.clientId ?? ''
    const needsConsent =
      !isNewAccount && clientId && !ctx.db.hasClientLogin(email, clientId)

    if (needsConsent) {
      // Step 5a: Redirect to consent screen, passing flow_id so consent can
      // look up request_uri and perform cleanup itself.
      // Do NOT delete auth_flow or clear cookie here — consent does it.
      const consentUrl = new URL(
        '/auth/consent',
        `https://${ctx.config.hostname}`,
      )
      consentUrl.searchParams.set('flow_id', flowId)
      consentUrl.searchParams.set('email', email)
      consentUrl.searchParams.set('new', '0')
      res.redirect(303, consentUrl.pathname + consentUrl.search)
      return
    }

    // Step 5: Record client login before redirecting (no consent needed)
    ctx.db.recordClientLogin(email, clientId || 'better-auth')

    // Cleanup: remove auth_flow row and cookie
    ctx.db.deleteAuthFlow(flowId)
    res.clearCookie(AUTH_FLOW_COOKIE)

    // Step 5b: Build HMAC-signed redirect to pds-core /oauth/magic-callback
    const callbackParams = {
      request_uri: flow.requestUri,
      email,
      approved: '1',
      new_account: isNewAccount ? '1' : '0',
    }
    const { sig, ts } = signCallback(
      callbackParams,
      ctx.config.magicCallbackSecret,
    )
    const params = new URLSearchParams({ ...callbackParams, ts, sig })
    const redirectUrl = `${ctx.config.pdsPublicUrl}/oauth/magic-callback?${params.toString()}`

    logger.info(
      { email, flowId, isNewAccount },
      'Bridge: redirecting to magic-callback',
    )
    res.redirect(303, redirectUrl)
  })

  return router
}
