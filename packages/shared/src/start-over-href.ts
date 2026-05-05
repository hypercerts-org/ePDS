/**
 * Best-effort lookup of an OAuth client's user-facing sign-in entry
 * URL. Used by both auth-service's `lib/clean-exit.ts` and pds-core's
 * `lib/epds-callback-error.ts` to populate the "Return to sign in"
 * button on their respective HTML fallback pages — a single source
 * of truth so the two surfaces don't drift.
 *
 * Resolution order:
 *   1. `client_uri` from the client's published OAuth metadata
 *      (the field is documented for exactly this purpose).
 *   2. The clientId's own origin, when clientId is a URL (the
 *      atproto convention is `client_id` is itself an HTTPS URL
 *      pointing at the metadata document on the client's own host,
 *      so the origin is a reasonable landing page).
 *
 * Returns null when neither resolves to a safe http(s) URL — the
 * caller should then omit the Start Over button entirely rather
 * than shipping a broken or unsafe link.
 *
 * Defence in depth: every URL we'd inline as the button's `href`
 * runs through `sanitiseHttpUrl`, which rejects schemes other than
 * http/https. atproto's upstream OAuth provider already validates
 * these fields at registration, but the HTML-fallback path exists
 * precisely to spare the user a 500 — and an unhandled
 * `javascript:` redirect would defeat that purpose.
 */
import type { Logger } from 'pino'
import { resolveClientMetadata } from './client-metadata.js'

export async function resolveStartOverHref(
  clientId: string,
  logger: Pick<Logger, 'error' | 'warn'>,
): Promise<string | null> {
  try {
    const metadata = await resolveClientMetadata(clientId)
    const fromMetadata = sanitiseHttpUrl(metadata.client_uri)
    if (fromMetadata) return fromMetadata
    return sanitiseHttpUrl(safeOrigin(clientId))
  } catch (err) {
    logger.warn(
      { err, clientId },
      'resolveStartOverHref: client metadata lookup failed',
    )
    return null
  }
}

/**
 * Return `value` only when it parses as an absolute http(s) URL;
 * otherwise null. `escapeHtml` does NOT neutralise `javascript:` URLs
 * because they contain no escape-sensitive characters, so anything
 * we plan to inline as an `href` must be scheme-validated up front.
 *
 * Exported because `resolveStartOverHref` is the typical caller
 * shape but a few sites (e.g. callers that already have a metadata
 * object in hand) want the bare sanitiser.
 */
export function sanitiseHttpUrl(
  value: string | null | undefined,
): string | null {
  if (!value) return null
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  return url.toString()
}

function safeOrigin(value: string): string | null {
  try {
    return new URL(value).origin
  } catch {
    return null
  }
}
