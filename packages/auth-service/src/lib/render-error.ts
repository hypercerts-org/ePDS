import { renderError as renderSharedError } from '@certified-app/shared'
import { POWERED_BY_CSS, POWERED_BY_HTML } from './page-helpers.js'

export interface AuthRenderErrorOptions {
  title?: string
  /**
   * Optional URL for a "Start over" button rendered below the error
   * message. Pass when the OAuth flow has failed in a way the user
   * cannot recover from automatically and we have a concrete sign-in
   * page to send them to. See `lib/redirect-to-client-error.ts` for
   * the typical caller pattern.
   */
  startOverHref?: string
  /** Label for the start-over button. Defaults to "Start over". */
  startOverLabel?: string
}

/**
 * Auth-service's error page reuses `@certified-app/shared`'s styled
 * `renderError` and adds the auth-service-specific "Powered by
 * Certified" footer below the error card. Pds-core uses the shared
 * version directly (no footer) — the brand promo only belongs on
 * sign-in-flow surfaces.
 *
 * Backwards-compatible: callers that only pass a message + title
 * still work; the second arg can also be an options object that
 * threads `startOverHref` / `startOverLabel` through to the shared
 * renderer.
 */
export function renderError(
  message: string,
  titleOrOptions: string | AuthRenderErrorOptions = 'Error',
): string {
  const opts: AuthRenderErrorOptions =
    typeof titleOrOptions === 'string'
      ? { title: titleOrOptions }
      : titleOrOptions
  return renderSharedError(message, {
    title: opts.title ?? 'Error',
    extraCss: POWERED_BY_CSS,
    bodyExtra: POWERED_BY_HTML,
    startOverHref: opts.startOverHref,
    startOverLabel: opts.startOverLabel,
  })
}
