/**
 * GET /auth/complete
 *
 * Bridge route: called by better-auth after successful authentication
 * (this is the `callbackURL` passed to better-auth sign-in methods).
 *
 * Translates a better-auth session into an HMAC-signed redirect to
 * pds-core's /oauth/epds-callback, threading the AT Protocol request_uri
 * through the flow via the auth_flow table.
 *
 * Flow:
 *   1. Read epds_auth_flow cookie → get flow_id
 *   2. Look up auth_flow row → get request_uri, client_id
 *   3. Get better-auth session → extract verified email
 *   4. Check if this is a new user (no PDS account for email)
 *   5a. New user, handle_mode='random' → HMAC-signed redirect to pds-core (random handle generated server-side)
 *   5b. New user, handle_mode=null|'picker'|'picker-with-random' → redirect to /auth/choose-handle
 *   5c. Existing user → build HMAC-signed redirect to pds-core /oauth/epds-callback
 *   6. Delete auth_flow row + clear cookie (only for 5c path)
 *
 * Note: consent is handled by the stock @atproto/oauth-provider middleware
 * after pds-core's epds-callback redirects through /oauth/authorize.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import {
  createLogger,
  signCallback,
  type CallbackParams,
} from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import { cleanExit } from '../lib/clean-exit.js'
import { getDidByEmail } from '../lib/get-did-by-email.js'
import { pingParRequest } from '../lib/ping-par-request.js'
import { requireInternalEnv } from '../lib/require-internal-env.js'
import { resolveRecoveryEmail } from '../lib/resolve-recovery-email.js'

const logger = createLogger('auth:complete')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/**
 * Build the HMAC-signed `/oauth/epds-callback` redirect URL the
 * /auth/complete route emits to bridge the user from auth-service to
 * pds-core once the OTP / handle steps are done. Carries `client_id`
 * alongside the rest of the signed params so pds-core's catch block
 * can mount a clean-exit redirect to the client even when the PAR
 * row has died and Step 2 itself throws (the row is gone before its
 * `.parameters.client_id` can be read). client_id is signed too, so
 * an attacker cannot tamper to redirect at a different client.
 *
 * `handle` is intentionally omitted on the random-mode path: an
 * absent `handle` in the signed payload (serialised as '' by
 * signCallback's `?? ''` sentinel) is the agreed signal to pds-core
 * that it should call generateRandomHandle() instead of using a
 * caller-supplied value. Both signCallback and verifyCallback use
 * the same `params.handle ?? ''` shape; the sentinel is pinned by
 * tests in packages/shared/src/__tests__/crypto.test.ts.
 *
 * Exported so it can be unit-tested without standing up the full
 * /auth/complete route.
 */
export function buildEpdsCallbackUrl(args: {
  flowRequestUri: string
  flowClientId: string | null
  email: string
  isNewAccount: boolean
  pdsPublicUrl: string
  epdsCallbackSecret: string
}): string {
  const callbackParams: CallbackParams = {
    request_uri: args.flowRequestUri,
    email: args.email,
    approved: '1',
    new_account: args.isNewAccount ? '1' : '0',
  }
  if (args.flowClientId) callbackParams.client_id = args.flowClientId
  const { sig, ts } = signCallback(callbackParams, args.epdsCallbackSecret)
  const params = new URLSearchParams({ ...callbackParams, ts, sig })
  return `${args.pdsPublicUrl}/oauth/epds-callback?${params.toString()}`
}

export function createCompleteRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()

  const { pdsUrl, internalSecret } = requireInternalEnv()

  /**
   * Clean-exit shorthands for the three cleanExit() shapes this route
   * uses. Lifted out of the handler to keep its branch density below
   * Sonar's cognitive-complexity gate; the bodies are still trivial
   * enough to inline-read at the call sites.
   */
  const exitWithSignInTimeout = (res: Response): Promise<void> =>
    cleanExit({
      res,
      clientId: null,
      pdsUrl,
      code: 'access_denied',
      description:
        'Your sign-in took too long to complete. Please start sign-in again.',
    })

  const exitWithServerError = (
    res: Response,
    clientId: string | null,
  ): Promise<void> =>
    cleanExit({
      res,
      clientId,
      pdsUrl,
      code: 'server_error',
      description:
        'Authentication failed because of a server error. Please try again.',
      fallbackStatus: 500,
    })

  /**
   * New-user random-mode bridge: skip the handle picker, ping the
   * PAR to reset the inactivity timer (non-fatal — pds-core will
   * surface any expiry it sees), and redirect to /oauth/epds-callback.
   * Lifted out of the handler to keep its branch count down.
   */
  async function redirectNewUserRandomMode(
    res: Response,
    flow: { requestUri: string; clientId: string | null },
    email: string,
    flowId: string,
  ): Promise<void> {
    const ping = await pingParRequest(flow.requestUri, pdsUrl, internalSecret)
    if (!ping.ok) {
      logger.warn(
        { status: ping.status, err: ping.err, requestUri: flow.requestUri },
        'PAR ping returned non-OK on random mode complete — proceeding anyway',
      )
    }
    const url = buildEpdsCallbackUrl({
      flowRequestUri: flow.requestUri,
      flowClientId: flow.clientId,
      email,
      isNewAccount: true,
      pdsPublicUrl: ctx.config.pdsPublicUrl,
      epdsCallbackSecret: ctx.config.epdsCallbackSecret,
    })
    logger.info(
      { email, flowId },
      'New user (random mode): skipping handle picker, redirecting to epds-callback',
    )
    res.redirect(303, url)
  }

  router.get('/auth/complete', async (req: Request, res: Response) => {
    // Step 1: Get flow_id from cookie
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    if (!flowId) {
      logger.warn('No epds_auth_flow cookie found on /auth/complete')
      // No clientId in scope (no cookie → no flow → no client), so the
      // helper falls through to the styled Start Over page with no
      // button. The user has no recoverable context here; this is the
      // best we can do.
      await exitWithSignInTimeout(res)
      return
    }

    // Step 2: Look up auth_flow row
    const flow = ctx.db.getAuthFlow(flowId)
    if (!flow) {
      logger.warn({ flowId }, 'auth_flow not found or expired')
      res.clearCookie(AUTH_FLOW_COOKIE)
      await exitWithSignInTimeout(res)
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
      // Internal failure rather than a user-paced timeout — server_error
      // per RFC 6749 §4.1.2.1. Flow has a clientId so the user gets
      // bounced cleanly back to the OAuth client.
      await exitWithServerError(res, flow.clientId)
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

    let email = session.user.email.toLowerCase()

    // Step 4: Check whether this is a new user (no PDS account for email).
    let did = await getDidByEmail(email, pdsUrl, internalSecret)

    // Recovery path: session email is a backup email, not a primary. Resolve
    // the backup-email → DID mapping (auth-service-owned) and then DID →
    // primary email via pds-core's internal API, so the downstream callback
    // signs the user's real account email, not the recovery address.
    if (!did) {
      const recovered = await resolveRecoveryEmail(
        email,
        ctx,
        pdsUrl,
        internalSecret,
      )
      if (recovered) {
        logger.info(
          { flowId, did: recovered.did },
          'Recovery: translated backup email to primary email via DID',
        )
        email = recovered.email
        did = recovered.did
      }
    }

    const isNewAccount = !did

    if (isNewAccount && flow.handleMode === 'random') {
      // Step 5a: skip the handle picker, let pds-core call
      // generateRandomHandle() (signalled by the absent `handle`
      // field in the signed callback).
      await redirectNewUserRandomMode(res, flow, email, flowId)
      return
    }

    if (isNewAccount) {
      // Step 5b (new user, picker/picker-with-random/null mode): Redirect to handle picker.
      // Default (null) preserves existing behavior — picker is always shown.
      // Do NOT delete auth_flow or clear cookie here — TTL cleanup handles expiry.
      // If pds-core redirects back with ?error=handle_taken, the user can retry.
      logger.info(
        { email, flowId, handleMode: flow.handleMode },
        'New user: redirecting to choose-handle',
      )
      res.redirect(303, '/auth/choose-handle')
      return
    }

    // Step 5c (existing user): Build HMAC-signed redirect to pds-core /oauth/epds-callback.
    // Consent is handled by the stock @atproto/oauth-provider middleware —
    // pds-core's epds-callback redirects through /oauth/authorize which shows
    // the upstream consent UI with actual OAuth scopes if needed.
    ctx.db.deleteAuthFlow(flowId)
    res.clearCookie(AUTH_FLOW_COOKIE)
    const redirectUrl = buildEpdsCallbackUrl({
      flowRequestUri: flow.requestUri,
      flowClientId: flow.clientId,
      email,
      isNewAccount: false,
      pdsPublicUrl: ctx.config.pdsPublicUrl,
      epdsCallbackSecret: ctx.config.epdsCallbackSecret,
    })
    logger.info(
      { email, flowId, isNewAccount },
      'Bridge: redirecting to epds-callback',
    )
    res.redirect(303, redirectUrl)
  })

  return router
}
