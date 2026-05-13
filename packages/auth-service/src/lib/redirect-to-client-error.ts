/**
 * Build the RFC 6749 §4.1.2.1 error redirect for a clean exit back to
 * the OAuth client. When something inside auth-service fails after the
 * upstream PAR row has died (or never existed in scope), the user
 * should NOT be stranded on a static "session expired" page —
 * RFC 6749 says we should bounce them to the OAuth client's
 * `redirect_uri` with `error`, `error_description`, `iss`, and (when
 * available) `state` query parameters so the client's own UI can
 * surface a retry that fits the app.
 *
 * This helper resolves the client's metadata (independently of any
 * dead PAR row) to recover `redirect_uris[0]`, then formats the
 * redirect URL. It returns `null` when the metadata cannot be
 * resolved or carries no usable redirect URI — callers should fall
 * back to the styled Start Over page in that case.
 *
 * Lives in auth-service rather than `@certified-app/shared` because
 * pds-core has its own redirect-builder in
 * `lib/epds-callback-error.ts` that runs after a successful Step 2
 * `requestManager.get()` (so it has the real PAR's redirect_uri /
 * state in hand) — using this helper there would be needlessly
 * lossier.
 */
import { createLogger, resolveClientMetadata } from '@certified-app/shared'

const logger = createLogger('auth:redirect-to-client-error')

/**
 * RFC 6749 §4.1.2.1 error code. Two values are useful in the
 * dead-PAR / dead-flow context:
 *   - `access_denied`: the user-paced timeout case. Matches the code
 *     @atproto/oauth-provider already uses for PAR expiry on its own
 *     paths and the code already used by pds-core's
 *     handleCallbackError, so clients see one error code regardless
 *     of which surface inside ePDS surfaced the timeout.
 *   - `server_error`: an unexpected internal failure (better-auth
 *     outage, missing better-auth session, etc.). RFC-compliant for
 *     5xx-class problems.
 */
export type ClientErrorCode = 'access_denied' | 'server_error'

export interface RedirectToClientErrorOpts {
  clientId: string
  pdsUrl: string
  code: ClientErrorCode
  description: string
  /**
   * The original request's `state` parameter, if it survives the
   * failure path. Most cluster-A/B sites have lost it because
   * `state` lived in the dead PAR, but include it when available so
   * the client can correlate the error with its in-flight attempt.
   */
  state?: string
}

/**
 * Resolve the client's metadata and return an absolute URL to redirect
 * the user to. Returns null when:
 *   - metadata resolution fails (network blip, unreachable client,
 *     etc.); or
 *   - the metadata declares no usable `redirect_uris[0]`.
 *
 * Callers should treat null as "fall back to the static Start Over
 * page" rather than swallowing it.
 */
export async function buildClientErrorRedirect(
  opts: RedirectToClientErrorOpts,
): Promise<string | null> {
  let metadata
  try {
    metadata = await resolveClientMetadata(opts.clientId)
  } catch (err) {
    logger.warn(
      { err, clientId: opts.clientId },
      'redirectToClientError: client metadata fetch failed',
    )
    return null
  }

  const redirectUri = metadata.redirect_uris?.[0]
  if (!redirectUri) {
    logger.warn(
      { clientId: opts.clientId },
      'redirectToClientError: client metadata has no redirect_uris',
    )
    return null
  }

  let url: URL
  try {
    url = new URL(redirectUri)
  } catch (err) {
    logger.warn(
      { err, clientId: opts.clientId, redirectUri },
      'redirectToClientError: redirect_uri is not a valid URL',
    )
    return null
  }

  // Defence in depth: reject non-web schemes even if the metadata
  // somehow advertises one. atproto's @atproto/oauth-provider already
  // validates redirect_uris at PAR creation, so this branch should be
  // unreachable in practice — but the catch above exists precisely to
  // spare the user a 500, and an unhandled `javascript:` redirect
  // would defeat that. RFC 6749 §3.1.2 requires absolute http/https
  // URIs; `localhost` http is intentionally permitted for the
  // dev-loop case.
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    logger.warn(
      { clientId: opts.clientId, redirectUri, protocol: url.protocol },
      'redirectToClientError: redirect_uri has unsupported scheme',
    )
    return null
  }

  // OAuth clients can only redirect to a pre-registered URI anyway,
  // so using the first one is RFC-compliant. The original `state`
  // is lost on the dead-PAR path — clients treat the response as an
  // anonymous error and restart, which is the right semantics for
  // an expiry.
  url.searchParams.set('error', opts.code)
  url.searchParams.set('error_description', opts.description)
  url.searchParams.set('iss', opts.pdsUrl)
  if (opts.state) url.searchParams.set('state', opts.state)
  return url.toString()
}
