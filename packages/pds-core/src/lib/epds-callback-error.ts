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
import {
  resolveClientMetadata,
  resolveStartOverHref,
  type RenderErrorOptions,
} from '@certified-app/shared'

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
  /**
   * OAuth client_id, signed and forwarded by auth-service in the
   * /oauth/epds-callback URL. Used as a last-resort fallback when
   * `capturedRedirectUri` is absent — the catch block resolves the
   * client's published metadata to recover `redirect_uris[0]` so the
   * user can still bounce back to the OAuth client (with `error` and
   * `error_description`) instead of stranding them on a static page.
   * The original `state` lives in the dead PAR and is unrecoverable
   * here; clients treat the missing `state` as an anonymous error.
   */
  signedClientId?: string
  /** Issuer identifier per RFC 9207, set on the redirect. */
  pdsUrl: string
  logger: Pick<Logger, 'error' | 'warn'>
  /** Renders the styled HTML fallback page. Injected so tests can
   * assert on the rendered string without pulling in the real
   * renderer. Accepts the same options object the shared
   * `renderError` exports so the HTML fallback can render a
   * "Return to sign in" button when we know which OAuth client the
   * user came from but couldn't construct a valid redirect target
   * (metadata missing, redirect_uris empty / unparseable). */
  renderError: (message: string, options?: RenderErrorOptions) => string
}

/**
 * Tier 1a: try to issue an RFC 6749 §4.1.2.1 redirect using the
 * `redirect_uri` captured from a successful Step-2 read of the
 * upstream PAR row. Preserves the original `state`. Returns true
 * when a redirect was emitted; false when `capturedRedirectUri` is
 * absent or unparseable (caller should fall through to Tier 1b).
 */
function tryRedirectFromCapturedUri(args: {
  res: Response
  capturedRedirectUri: string | undefined
  capturedState: string | undefined
  pdsUrl: string
  code: 'access_denied' | 'server_error'
  description: string
  logger: Pick<Logger, 'error' | 'warn'>
}): boolean {
  if (args.res.headersSent || !args.capturedRedirectUri) return false
  // The redirect_uri was captured from a successful Step-2 read of
  // the upstream PAR row, and @atproto/oauth-provider validates the
  // URL at PAR creation, so this is essentially defensive — but the
  // catch block exists precisely to spare the user a 500. If
  // `new URL()` ever does throw (upstream invariant changes,
  // test-only hook injects garbage, etc.), log it and let the caller
  // fall through to the next tier rather than crashing the error
  // handler itself.
  let errorUrl: URL
  try {
    errorUrl = new URL(args.capturedRedirectUri)
  } catch (urlErr) {
    args.logger.error(
      { err: urlErr, capturedRedirectUri: args.capturedRedirectUri },
      'ePDS callback: captured redirect_uri is not a valid URL — falling back to HTML error page',
    )
    return false
  }
  // Cache-Control: no-store on the redirect so a browser or
  // intermediary doesn't preserve the per-attempt `state` /
  // error_description query params (would leak across users on a
  // shared cache) and doesn't replay a stale 303 on refresh, which
  // would skip the user past a fresh sign-in attempt.
  args.res.setHeader('Cache-Control', 'no-store')
  errorUrl.searchParams.set('error', args.code)
  errorUrl.searchParams.set('error_description', args.description)
  errorUrl.searchParams.set('iss', args.pdsUrl)
  if (args.capturedState) errorUrl.searchParams.set('state', args.capturedState)
  args.res.redirect(303, errorUrl.toString())
  return true
}

/**
 * Tier 1b: try to issue an RFC 6749 §4.1.2.1 redirect using
 * `redirect_uris[0]` resolved from the signed `client_id`'s
 * published OAuth metadata. Used when Step 2 itself threw so we
 * never captured the PAR's redirect_uri / state.
 *
 * RFC 6749 §4.1.2.1 *requires* `state` in the error response when it
 * was present in the authorization request. We omit it here because
 * the original `state` value lived in the now-deleted PAR row and
 * is unrecoverable — this is a pragmatic degradation, not
 * spec-permitted behaviour. Spec-compliant OAuth clients have to
 * tolerate uncorrelated error responses anyway (cross-device resume,
 * browser session loss), so an "anonymous error, restart" outcome
 * is universally recoverable on the client side. We chose redirect
 * over stranding on a static page because the user gets back to the
 * client's UI in either case, and the client at least sees the
 * specific error code and description.
 *
 * `signedClientId` rode along on the HMAC-signed callback URL so a
 * tampered value cannot redirect a victim's flow at a different
 * OAuth client. Returns true when a redirect was emitted; false
 * when no redirect could be constructed (caller should fall through
 * to the styled HTML page).
 */
async function tryRedirectFromSignedClient(args: {
  res: Response
  signedClientId: string | undefined
  pdsUrl: string
  code: 'access_denied' | 'server_error'
  description: string
  logger: Pick<Logger, 'error' | 'warn'>
}): Promise<boolean> {
  if (args.res.headersSent || !args.signedClientId) return false
  let fallbackRedirect: string | undefined
  try {
    const metadata = await resolveClientMetadata(args.signedClientId)
    fallbackRedirect = metadata.redirect_uris?.[0]
  } catch (lookupErr) {
    args.logger.warn(
      { err: lookupErr, signedClientId: args.signedClientId },
      'ePDS callback: client metadata lookup failed — falling back to HTML error page',
    )
    return false
  }
  if (!fallbackRedirect) {
    args.logger.warn(
      { signedClientId: args.signedClientId },
      'ePDS callback: client metadata has no usable redirect_uris — falling back to HTML error page',
    )
    return false
  }
  let errorUrl: URL
  try {
    errorUrl = new URL(fallbackRedirect)
  } catch (urlErr) {
    args.logger.error(
      {
        err: urlErr,
        signedClientId: args.signedClientId,
        fallbackRedirect,
      },
      'ePDS callback: client metadata redirect_uri is not a valid URL — falling back to HTML error page',
    )
    return false
  }
  args.res.setHeader('Cache-Control', 'no-store')
  errorUrl.searchParams.set('error', args.code)
  errorUrl.searchParams.set('error_description', args.description)
  errorUrl.searchParams.set('iss', args.pdsUrl)
  args.res.redirect(303, errorUrl.toString())
  return true
}

export async function handleCallbackError(
  opts: HandleCallbackErrorOpts,
): Promise<void> {
  const {
    res,
    err,
    capturedRedirectUri,
    capturedState,
    signedClientId,
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

  if (
    tryRedirectFromCapturedUri({
      res,
      capturedRedirectUri,
      capturedState,
      pdsUrl,
      code,
      description,
      logger,
    })
  ) {
    return
  }

  if (
    await tryRedirectFromSignedClient({
      res,
      signedClientId,
      pdsUrl,
      code,
      description,
      logger,
    })
  ) {
    return
  }

  if (!res.headersSent) {
    // Cache-Control: no-store on the HTML page too — the page is
    // produced from per-request state, so a cached copy is at best
    // misleading on a later attempt.
    res.setHeader('Cache-Control', 'no-store')
    // Best-effort Start Over CTA: when we know which OAuth client
    // initiated the flow (signedClientId), resolve a sign-in entry
    // URL from its published metadata so the styled fallback isn't
    // a true dead end. Auth-service does the same thing in
    // lib/clean-exit.ts. Returns null when no clientId is in scope
    // or metadata can't be resolved — the page degrades to text-only
    // in that case.
    const startOverHref = signedClientId
      ? await resolveStartOverHref(signedClientId, logger)
      : null
    res
      .status(isExpired ? 400 : 500)
      .type('html')
      .send(
        renderError(description, {
          startOverHref: startOverHref ?? undefined,
          startOverLabel: 'Return to sign in',
        }),
      )
  }
}
