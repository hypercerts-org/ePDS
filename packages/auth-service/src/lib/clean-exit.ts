/**
 * "Clean exit" response helper used by every dead-end path in
 * auth-service that today renders a static "Session expired" page
 * with no recovery option. Two tiers, in priority order:
 *
 *   1. Redirect the user back to the OAuth client's `redirect_uri`
 *      with the RFC 6749 §4.1.2.1 error parameters. The client's own
 *      UI then surfaces a one-click retry. This is the right
 *      semantics whenever we have a `clientId` in scope.
 *
 *   2. When no `clientId` is in scope (the error fired before we
 *      stashed one on the auth_flow row, or the auth_flow row itself
 *      is gone), render a styled HTML page with a "Start over"
 *      button. The button targets the client's `client_uri` when
 *      available, or — as a last resort — does not appear at all
 *      and the user is left to navigate manually. We never strand
 *      the user without explanation.
 *
 * See `docs/design/par-expiry-and-clean-exits.md` for the audit of
 * which call sites use this helper and why.
 */
import type { Response } from 'express'
import { createLogger, resolveStartOverHref } from '@certified-app/shared'
import {
  buildClientErrorRedirect,
  type ClientErrorCode,
} from './redirect-to-client-error.js'
import { renderError } from './render-error.js'

const logger = createLogger('auth:clean-exit')

export interface CleanExitOpts {
  res: Response
  /**
   * The OAuth client this flow belongs to, if known. When present,
   * the helper attempts the RFC 6749 redirect path first.
   */
  clientId: string | null | undefined
  /** PDS issuer URL for the `iss` parameter on the redirect. */
  pdsUrl: string
  /**
   * Spec error code for the redirect path. `access_denied` for
   * user-paced timeouts (matches the upstream code), `server_error`
   * for unexpected internal failures.
   */
  code: ClientErrorCode
  /**
   * Human-readable copy intended for direct display. Used both as
   * `error_description` on the redirect path and as the body text on
   * the Start Over page.
   */
  description: string
  /** HTTP status when the Start Over fallback fires. Default 400. */
  fallbackStatus?: number
  /**
   * Original `state` parameter, if it survives the failure path.
   * Most cluster-A/B sites have lost it (it lived in the dead PAR);
   * pass it when available.
   */
  state?: string
  /**
   * Title for the styled HTML fallback page when the redirect path
   * cannot fire. Default "Sign-in session expired" matches the
   * common user-paced-timeout case (`code: 'access_denied'`); pass
   * an explicit title for `server_error` callers where the body
   * copy describes an internal failure rather than a session
   * timeout. Mismatched title vs body would otherwise mis-diagnose
   * the failure for both users and operators.
   */
  fallbackTitle?: string
}

/**
 * Emit a clean-exit response. Mutates `res` (sends the redirect or
 * the HTML page) and returns once the response is committed.
 */
export async function cleanExit(opts: CleanExitOpts): Promise<void> {
  const fallbackStatus = opts.fallbackStatus ?? 400

  // Cache-Control: no-store on every clean-exit path — the response
  // carries per-request error context and a cached copy is at best
  // misleading on a later attempt.
  opts.res.setHeader('Cache-Control', 'no-store')

  // Tier 1: redirect to the OAuth client.
  if (opts.clientId) {
    const target = await buildClientErrorRedirect({
      clientId: opts.clientId,
      pdsUrl: opts.pdsUrl,
      code: opts.code,
      description: opts.description,
      state: opts.state,
    })
    if (target) {
      opts.res.redirect(303, target)
      return
    }
  }

  // Tier 2: styled page with a Start Over link, when we can resolve
  // the client's home page. The lookup logic lives in
  // @certified-app/shared so pds-core's HTML fallback uses the same
  // resolution / sanitisation rules.
  const startOverHref = opts.clientId
    ? await resolveStartOverHref(opts.clientId, logger)
    : null

  // Default title matches the common timeout case; server_error
  // callers should pass `fallbackTitle: 'Authentication failed'` (or
  // similar) so the heading isn't a mis-diagnosis when the body
  // describes an internal failure.
  const fallbackTitle =
    opts.fallbackTitle ??
    (opts.code === 'server_error'
      ? 'Authentication failed'
      : 'Sign-in session expired')

  opts.res
    .status(fallbackStatus)
    .type('html')
    .send(
      renderError(opts.description, {
        title: fallbackTitle,
        startOverHref: startOverHref ?? undefined,
        startOverLabel: 'Return to sign in',
      }),
    )
}
