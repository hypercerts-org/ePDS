import { renderError as renderSharedError } from '@certified-app/shared'
import { POWERED_BY_CSS, POWERED_BY_HTML } from './page-helpers.js'

/**
 * Auth-service's error page reuses `@certified-app/shared`'s styled
 * `renderError` and adds the auth-service-specific "Powered by
 * Certified" footer below the error card. Pds-core uses the shared
 * version directly (no footer) — the brand promo only belongs on
 * sign-in-flow surfaces.
 */
export function renderError(message: string, title = 'Error'): string {
  return renderSharedError(message, {
    title,
    extraCss: POWERED_BY_CSS,
    bodyExtra: POWERED_BY_HTML,
  })
}
