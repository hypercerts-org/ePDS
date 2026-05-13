/**
 * GET /auth/ping
 *
 * Server-mediated heartbeat used by the OTP and recovery forms to slide
 * the upstream PAR (request_uri) inactivity timer while the user is on
 * the page. Without this, a user who reads their email for >5 minutes
 * (atproto's AUTHORIZATION_INACTIVITY_TIMEOUT) trips the dead-PAR path
 * downstream when they finally submit. See
 * `docs/design/par-expiry-and-clean-exits.md` for the broader context.
 *
 * The browser cannot call pds-core's /_internal/ping-request directly
 * (that endpoint requires EPDS_INTERNAL_SECRET, which never leaves the
 * server), so this route reads the user's `epds_auth_flow` cookie,
 * looks up the auth_flow row, and proxies the existing
 * `pingParRequest()` call server-side.
 *
 * Security boundary: the heartbeat does *not* extend OTP, auth_flow, or
 * any session — it only refreshes the PAR row's sliding `expiresAt`
 * field upstream. Bounded by the auth_flow's own 60-min TTL: once the
 * auth_flow row is gone, the ping returns `flow_expired` and the
 * browser stops pinging. No new tokens are issued.
 */
import { Router, type Request, type Response } from 'express'
import { createLogger } from '@certified-app/shared'
import type { AuthServiceContext } from '../context.js'
import { cleanExit } from '../lib/clean-exit.js'
import { pingParRequest } from '../lib/ping-par-request.js'
import { requireInternalEnv } from '../lib/require-internal-env.js'

const logger = createLogger('auth:heartbeat')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

export type HeartbeatResponse =
  | { ok: true }
  | {
      ok: false
      reason:
        | 'no_cookie'
        | 'flow_expired'
        | 'par_expired'
        /**
         * Transient — pds-core returned a non-OK status that wasn't
         * 404 (e.g. 5xx, gateway timeout, network blip). The browser
         * MUST keep heartbeating; the next tick may succeed. Do NOT
         * treat as terminal.
         */
        | 'transient'
    }

export function createHeartbeatRouter(ctx: AuthServiceContext): Router {
  const router = Router()
  const { pdsUrl, internalSecret } = requireInternalEnv()

  router.get('/auth/ping', async (req: Request, res: Response) => {
    // Cache-Control: no-store so an intermediary doesn't cache one
    // user's response and serve it to a different in-flight flow.
    res.setHeader('Cache-Control', 'no-store')

    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    if (!flowId) {
      const body: HeartbeatResponse = { ok: false, reason: 'no_cookie' }
      res.status(200).json(body)
      return
    }

    const flow = ctx.db.getAuthFlow(flowId)
    if (!flow) {
      const body: HeartbeatResponse = { ok: false, reason: 'flow_expired' }
      res.status(200).json(body)
      return
    }

    const ping = await pingParRequest(flow.requestUri, pdsUrl, internalSecret)
    if (!ping.ok) {
      // Only a 404 from pds-core (`request_uri` deleted/unknown) is
      // terminal — that's `requestManager.get()` having thrown and
      // swept the row in the same call. Anything else (5xx, network
      // timeout, no-status thrown error) is transient: a momentary
      // upstream blip should not stop the browser from polling, or a
      // single dropped packet during otherwise-healthy operation
      // would terminate keepalive permanently and re-introduce the
      // very dead-end the heartbeat exists to prevent.
      const isTerminal = ping.status === 404
      logger.debug(
        { status: ping.status, err: ping.err, flowId, isTerminal },
        'heartbeat: PAR ping failed',
      )
      const body: HeartbeatResponse = isTerminal
        ? { ok: false, reason: 'par_expired' }
        : { ok: false, reason: 'transient' }
      res.status(200).json(body)
      return
    }

    const okBody: HeartbeatResponse = { ok: true }
    res.status(200).json(okBody)
  })

  /**
   * GET /auth/abort
   *
   * Browser-driven clean exit. The OTP / recovery forms hit this URL
   * when they know the flow can no longer complete (typically after
   * /auth/ping returned `par_expired`). The route runs the same
   * cleanExit() helper as the unrecoverable-error paths in
   * /auth/complete and /auth/choose-handle: redirect to the OAuth
   * client's redirect_uri with `error=access_denied` per RFC 6749
   * §4.1.2.1, or fall back to a styled "Return to sign in" page when
   * the client is unknown.
   *
   * The point: avoid the dishonest cycle where Resend issues a fresh
   * OTP that cannot complete the flow because the upstream PAR is
   * dead. Better to bail to the OAuth client immediately than
   * mislead the user into typing a code that will fail.
   */
  router.get('/auth/abort', async (req: Request, res: Response) => {
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    const flow = flowId ? ctx.db.getAuthFlow(flowId) : undefined
    // Always clear the cookie — the flow is being abandoned.
    if (flowId) res.clearCookie(AUTH_FLOW_COOKIE)
    logger.info(
      { flowId, hasFlow: !!flow, clientId: flow?.clientId ?? null },
      'auth-abort: clean-exiting per browser request',
    )
    await cleanExit({
      res,
      clientId: flow?.clientId ?? null,
      pdsUrl,
      code: 'access_denied',
      description:
        'Your sign-in took too long to complete. Please start sign-in again.',
    })
  })

  return router
}
