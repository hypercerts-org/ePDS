/**
 * Error response logic for /oauth/epds-callback.
 *
 * Lives in its own module so the branching can be unit-tested without
 * spinning up the full pds-core stack. The handler in index.ts catches
 * any failure inside the callback and delegates to handleCallbackError
 * with the captured redirect_uri/state from Step 2's requestManager.get().
 *
 * Two response paths:
 *   1. RFC 6749 §4.1.2.1 redirect to the OAuth client's redirect_uri,
 *      with error / error_description / iss / state query params. This
 *      is the preferred path because the user lands on the client's
 *      own UI which can offer a retry that fits the app.
 *   2. Styled HTML fallback when no redirect_uri is recoverable
 *      (Step 2 itself threw before populating the captures — the PAR
 *      was already dead on entry).
 *
 * Two error classifications:
 *   - "expired": user-paced timeout. error=access_denied to match
 *     @atproto/oauth-provider's own choice on parallel paths, with a
 *     timeout-explaining error_description; HTTP 400 on the HTML
 *     fallback (4xx because it's a recoverable client problem, not a
 *     server bug).
 *   - other: generic server failure. error=server_error per spec, 500
 *     on the HTML fallback.
 */
import type { Response } from 'express'
import type { Logger } from 'pino'

/** Decoded view of a thrown error for response shaping. */
export interface CallbackErrorClassification {
  /** RFC 6749 §4.1.2.1 error code to surface on the redirect / page. */
  code: 'access_denied' | 'server_error'
  /** Human-readable copy intended for direct display to the user. */
  description: string
  /** True when the failure is a recognised dead-PAR signal. */
  isExpired: boolean
}

/**
 * The dead-PAR pattern we recognise. Matches the upstream-thrown
 * messages for both flavours of dead PAR:
 *   - "This request has expired" (AccessDeniedError, row was alive at
 *     request time but past its expiresAt)
 *   - "Unknown request_uri" (InvalidRequestError, row was already
 *     gone — what /_internal/test/delete-par produces, and what
 *     happens after a second callback hit since the first call's
 *     deleteRequest swept the row)
 * We also keep a generic "expired" / "invalid_grant" catch-all in
 * case upstream rewords its messages in a future patch release.
 *
 * Exported as a constant so tests can import the same regex they're
 * verifying without re-typing it.
 */
export const EXPIRED_PAR_MESSAGE_PATTERN =
  /request has expired|unknown request_uri|invalid_grant|expired/i

const EXPIRED_DESCRIPTION =
  'Your sign-in took too long to complete and timed out. Please start sign-in again.'
const SERVER_ERROR_DESCRIPTION = 'Authentication failed.'

export function classifyCallbackError(
  err: unknown,
): CallbackErrorClassification {
  const message = err instanceof Error ? err.message : String(err)
  const isExpired = EXPIRED_PAR_MESSAGE_PATTERN.test(message)
  return {
    code: isExpired ? 'access_denied' : 'server_error',
    description: isExpired ? EXPIRED_DESCRIPTION : SERVER_ERROR_DESCRIPTION,
    isExpired,
  }
}

export interface HandleCallbackErrorOpts {
  res: Response
  err: unknown
  /** redirect_uri stashed from Step 2's requestManager.get(); empty when
   * Step 2 itself threw. */
  capturedRedirectUri: string | undefined
  /** state stashed from Step 2's requestManager.get(); preserved on the
   * redirect for CSRF round-trip. */
  capturedState: string | undefined
  /** Issuer identifier per RFC 9207, set on the redirect. */
  pdsUrl: string
  logger: Pick<Logger, 'error' | 'warn'>
  /** Renders the styled HTML fallback page. Injected so tests can
   * assert on the rendered string without pulling in the real
   * renderer. */
  renderError: (message: string) => string
}

export function handleCallbackError(opts: HandleCallbackErrorOpts): void {
  const {
    res,
    err,
    capturedRedirectUri,
    capturedState,
    pdsUrl,
    logger,
    renderError,
  } = opts

  const { code, description, isExpired } = classifyCallbackError(err)

  // PAR-expiry is an expected user-paced timeout, not a server fault.
  // Log it at `warn` so it stays visible in operational logs without
  // tripping error-level alerting once expiry becomes routine in
  // production. Anything else (account creation failed, store down,
  // etc.) is genuinely server-side and stays at `error`.
  if (isExpired) {
    logger.warn({ err }, 'ePDS callback: sign-in timed out')
  } else {
    logger.error({ err }, 'ePDS callback error')
  }

  if (!res.headersSent && capturedRedirectUri) {
    // The redirect_uri was captured from a successful Step-2 read of
    // the upstream PAR row, and @atproto/oauth-provider validates the
    // URL at PAR creation, so this is essentially defensive — but the
    // catch block exists precisely to spare the user a 500. If
    // `new URL()` ever does throw (upstream invariant changes,
    // test-only hook injects garbage, etc.), log it and fall through
    // to the HTML fallback rather than crashing the error handler
    // itself.
    let errorUrl: URL | null = null
    try {
      errorUrl = new URL(capturedRedirectUri)
    } catch (urlErr) {
      logger.error(
        { err: urlErr, capturedRedirectUri },
        'ePDS callback: captured redirect_uri is not a valid URL — falling back to HTML error page',
      )
    }
    if (errorUrl) {
      // Cache-Control: no-store on the redirect so a browser or
      // intermediary doesn't preserve the per-attempt `state` /
      // error_description query params (would leak across users on a
      // shared cache) and doesn't replay a stale 303 on refresh,
      // which would skip the user past a fresh sign-in attempt.
      res.setHeader('Cache-Control', 'no-store')
      errorUrl.searchParams.set('error', code)
      errorUrl.searchParams.set('error_description', description)
      errorUrl.searchParams.set('iss', pdsUrl)
      if (capturedState) errorUrl.searchParams.set('state', capturedState)
      res.redirect(303, errorUrl.toString())
      return
    }
  }

  if (!res.headersSent) {
    // Cache-Control: no-store on the HTML page too — the page is
    // produced from per-request state, so a cached copy is at best
    // misleading on a later attempt.
    res.setHeader('Cache-Control', 'no-store')
    res
      .status(isExpired ? 400 : 500)
      .type('html')
      .send(renderError(description))
  }
}
