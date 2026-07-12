/**
 * Sanity checks for a client_metadata.json URL, surfaced on the
 * /preview index pages. The goal is "show the dev which fields are
 * missing, *before* they bother walking through a real OAuth flow".
 * This is not a full spec compliance check — it's a pragmatic
 * did-you-remember-X list focused on the fields ePDS actually reads.
 *
 * Organisation: each individual check is a small pure function that
 * returns a `PreviewCheck` (or null/a narrow result type). The top-level
 * `validateClientMetadataForPreview` is pure orchestration — URL shape,
 * fetch, then a flat list of content checks.
 */

import {
  escapeCss,
  MAX_CSS_BYTES,
  type ClientMetadata,
} from './client-metadata.js'
import { escapeHtml } from './html.js'
import { makeSafeFetch } from './safe-fetch.js'

const safeFetch = makeSafeFetch({ timeoutMs: 5_000 })

export type CheckSeverity = 'ok' | 'warn' | 'error'

export interface PreviewCheck {
  /** Stable id so the UI can style or key entries by it */
  id: string
  /** Short human label rendered in the UI */
  label: string
  severity: CheckSeverity
  /** Longer explanation, shown as a hint / tooltip */
  detail: string
  /**
   * Optional pre-escaped HTML for `label` / `detail`. When set, the
   * preview UI renders these verbatim instead of HTML-escaping the
   * plain-text equivalents, so the server can mark URL fragments,
   * query params, and field names with `<code>` without the client
   * having to parse anything. All interpolated user data must already
   * be escaped by the time it lands here — only the surrounding
   * markup is trusted.
   */
  labelHtml?: string
  detailHtml?: string
}

export interface PreviewValidationResult {
  /** The URL the user supplied */
  url: string
  /** Whether we were able to fetch + parse metadata at all */
  fetched: boolean
  checks: PreviewCheck[]
}

/**
 * Wrap `text` (literal, not pre-escaped) in `<code>` after HTML-escaping.
 * Small helper used by the check builders below so each call site can
 * stay readable.
 */
function code(text: string): string {
  return `<code>${escapeHtml(text)}</code>`
}

/**
 * Check for an optional https URL field (tos_uri, policy_uri, ...).
 * Missing → warn (optional). Present + valid https → ok. Present + invalid
 * or non-https → error (the consent page would render a broken link).
 */
function checkUriField(opts: {
  id: string
  field: string
  value: string | undefined
  description: string
}): PreviewCheck {
  const { id, field, value, description } = opts
  const label = `${field} set`
  const labelHtml = `${code(field)} set`

  if (value === undefined || value === '') {
    return {
      id,
      label,
      severity: 'warn',
      detail: `No ${field}. ${description}`,
      labelHtml,
      detailHtml: `No ${code(field)}. ${description}`,
    }
  }

  let parsed: URL | null = null
  try {
    parsed = new URL(value)
  } catch {
    // fall through
  }
  if (parsed?.protocol !== 'https:') {
    return {
      id,
      label,
      severity: 'error',
      detail: `${field}="${value}" is not a valid https URL.`,
      labelHtml,
      detailHtml: `${code(field)}=${code('"' + value + '"')} is not a valid https URL.`,
    }
  }

  return {
    id,
    label,
    severity: 'ok',
    detail: `${field}="${value}".`,
    labelHtml,
    detailHtml: `${code(field)}=${code('"' + value + '"')}.`,
  }
}

/**
 * Parse the supplied URL. `parsedUrl` + null check is returned together
 * so the caller can fast-path on an unparseable input.
 */
function parseClientIdUrl(url: string): {
  parsedUrl: URL | null
  errorCheck: PreviewCheck | null
} {
  try {
    return { parsedUrl: new URL(url), errorCheck: null }
  } catch {
    return {
      parsedUrl: null,
      errorCheck: {
        id: 'url-parseable',
        label: 'URL parseable',
        severity: 'error',
        detail: 'The value supplied is not a valid URL.',
      },
    }
  }
}

/** Non-https URL → error, otherwise null. */
function checkHttpsScheme(parsedUrl: URL): PreviewCheck | null {
  if (parsedUrl.protocol === 'https:') return null
  return {
    id: 'url-https',
    label: 'URL uses https',
    severity: 'error',
    detail: 'client_metadata must be hosted over HTTPS (the spec requires it).',
    detailHtml: `${code('client_metadata')} must be hosted over HTTPS (the spec requires it).`,
  }
}

/**
 * Fetch the metadata JSON. On success returns the parsed metadata plus
 * the "ok" fetch check; on any failure (transport, non-2xx, bad JSON)
 * returns the fatal check with `metadata` unset.
 */
async function fetchMetadata(
  url: string,
): Promise<
  | { metadata: ClientMetadata; fetchCheck: PreviewCheck }
  | { metadata: null; fetchCheck: PreviewCheck }
> {
  try {
    const res = await safeFetch(url, {
      headers: { Accept: 'application/json' },
    })
    if (!res.ok) {
      return {
        metadata: null,
        fetchCheck: {
          id: 'fetch',
          label: 'Metadata fetched',
          severity: 'error',
          detail: `Upstream responded ${res.status}.`,
        },
      }
    }
    try {
      const metadata = (await res.json()) as ClientMetadata
      return {
        metadata,
        fetchCheck: {
          id: 'fetch',
          label: 'Metadata fetched',
          severity: 'ok',
          detail: 'Got a 200 response and parsed the JSON body.',
          detailHtml: `Got a 200 response and parsed <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">the JSON body</a>.`,
        },
      }
    } catch {
      return {
        metadata: null,
        fetchCheck: {
          id: 'fetch-json',
          label: 'Response is valid JSON',
          severity: 'error',
          detail: 'The server returned 200 but the body is not valid JSON.',
        },
      }
    }
  } catch (err) {
    return {
      metadata: null,
      fetchCheck: {
        id: 'fetch',
        label: 'Metadata fetched',
        severity: 'error',
        detail:
          err instanceof Error
            ? `Fetch failed: ${err.message}`
            : 'Fetch failed.',
      },
    }
  }
}

/**
 * The `client_id` field in the JSON should equal the URL it was fetched
 * from — the @atproto/oauth-provider enforces this too, so flagging it
 * here saves a round-trip.
 */
function checkClientIdMatch(
  metadata: ClientMetadata,
  url: string,
): PreviewCheck {
  const clientIdField = (metadata as ClientMetadata & { client_id?: string })
    .client_id
  const label = 'client_id matches URL'
  const labelHtml = `${code('client_id')} matches URL`

  if (!clientIdField) {
    return {
      id: 'client-id-match',
      label,
      severity: 'error',
      detail: 'No client_id field in the JSON.',
      labelHtml,
      detailHtml: `No ${code('client_id')} field in the JSON.`,
    }
  }
  if (clientIdField !== url) {
    return {
      id: 'client-id-match',
      label,
      severity: 'error',
      detail: `JSON has client_id="${clientIdField}" but was fetched from ${url}.`,
      labelHtml,
      detailHtml: `JSON has ${code('client_id')}=${code('"' + clientIdField + '"')} but was fetched from ${code(url)}.`,
    }
  }
  return {
    id: 'client-id-match',
    label,
    severity: 'ok',
    detail: 'client_id field equals the fetched URL.',
    labelHtml,
    detailHtml: `${code('client_id')} field equals the fetched URL.`,
  }
}

function checkRedirectUris(metadata: ClientMetadata): PreviewCheck {
  const redirectUris = (
    metadata as ClientMetadata & { redirect_uris?: unknown }
  ).redirect_uris
  const label = 'redirect_uris non-empty'
  const labelHtml = `${code('redirect_uris')} non-empty`

  if (Array.isArray(redirectUris) && redirectUris.length > 0) {
    return {
      id: 'redirect-uris',
      label,
      severity: 'ok',
      detail: `Found ${redirectUris.length} redirect URI(s).`,
      labelHtml,
      detailHtml: `Found ${redirectUris.length} redirect URI(s).`,
    }
  }
  return {
    id: 'redirect-uris',
    label,
    severity: 'error',
    detail: 'OAuth needs at least one redirect URI.',
    labelHtml,
  }
}

function checkBrandColor(metadata: ClientMetadata): PreviewCheck {
  const label = 'brand_color set'
  const labelHtml = `${code('brand_color')} set`
  if (metadata.brand_color) {
    return {
      id: 'brand-color',
      label,
      severity: 'ok',
      detail: `brand_color="${metadata.brand_color}" — used as the primary accent on auth-service pages.`,
      labelHtml,
      detailHtml: `${code('brand_color')}=${code('"' + metadata.brand_color + '"')} — used as the primary accent on auth-service pages.`,
    }
  }
  return {
    id: 'brand-color',
    label,
    severity: 'warn',
    detail:
      'Optional. Without it, the login / OTP / choose-handle pages fall back to the ePDS default accent.',
    labelHtml,
  }
}

function checkBackgroundColor(metadata: ClientMetadata): PreviewCheck {
  const label = 'background_color set'
  const labelHtml = `${code('background_color')} set`
  if (metadata.background_color) {
    return {
      id: 'background-color',
      label,
      severity: 'ok',
      detail: `background_color="${metadata.background_color}" — page background on auth-service pages.`,
      labelHtml,
      detailHtml: `${code('background_color')}=${code('"' + metadata.background_color + '"')} — page background on auth-service pages.`,
    }
  }
  return {
    id: 'background-color',
    label,
    severity: 'warn',
    detail:
      'Optional. Without it, auth-service pages use the ePDS default page background.',
    labelHtml,
  }
}

function checkBrandingCss(metadata: ClientMetadata): PreviewCheck {
  const cssString = metadata.branding?.css
  const label = 'branding.css present'
  const labelHtml = `${code('branding.css')} present`

  if (typeof cssString === 'string' && cssString.trim().length > 0) {
    // Mirror getClientCss's size check: it measures the escaped form
    // (each `</style>` → `\u003c/style>`, +5 bytes) against
    // MAX_CSS_BYTES and silently returns null when it's over.
    // Reporting the raw byte count here would tell devs their CSS is
    // fine up to 32 KB raw when in fact it gets dropped on real flows.
    const escaped = escapeCss(cssString)
    const bytes = Buffer.byteLength(escaped, 'utf8')
    if (bytes > MAX_CSS_BYTES) {
      return {
        id: 'branding-css',
        label,
        severity: 'error',
        detail: `${bytes.toLocaleString()} bytes (escaped) exceeds the ${MAX_CSS_BYTES.toLocaleString()}-byte limit. getClientCss() will silently drop it on real OAuth flows.`,
        labelHtml,
        detailHtml: `${bytes.toLocaleString()} bytes (escaped) exceeds the ${MAX_CSS_BYTES.toLocaleString()}-byte limit. ${code('getClientCss()')} will silently drop it on real OAuth flows.`,
      }
    }
    return {
      id: 'branding-css',
      label,
      severity: 'ok',
      detail: `${bytes.toLocaleString()} bytes (escaped). Injected into /preview/consent (pds-core) and the auth-service pages when the client is trusted.`,
      labelHtml,
      detailHtml: `${bytes.toLocaleString()} bytes (escaped). Injected into ${code('/preview/consent')} (pds-core) and the auth-service pages when the client is trusted.`,
    }
  }
  if (cssString !== undefined) {
    return {
      id: 'branding-css',
      label,
      severity: 'warn',
      detail: 'branding.css is present but empty.',
      labelHtml,
      detailHtml: `${code('branding.css')} is present but empty.`,
    }
  }
  return {
    id: 'branding-css',
    label,
    severity: 'warn',
    detail:
      'No branding.css — preview will render the page unbranded (beyond brand_color / background_color, if set).',
    labelHtml,
    detailHtml: `No ${code('branding.css')} — preview will render the page unbranded (beyond ${code('brand_color')} / ${code('background_color')}, if set).`,
  }
}

function checkTosUri(metadata: ClientMetadata): PreviewCheck {
  return checkUriField({
    id: 'tos-uri',
    field: 'tos_uri',
    value: metadata.tos_uri,
    description:
      "Terms-of-service URL. Rendered as a link on the consent page so users can review the client's terms before granting access.",
  })
}

/**
 * `epds_handle_login_url` is the hand-off URL for the
 * "Or sign in with ATProto/Bluesky" button on the login page. The
 * real gate in auth-service is `isSafeHttpUrl` — accepts http and
 * https so that localhost dev clients keep working — so this check
 * mirrors that, rather than the stricter https-only check used for
 * tos_uri / policy_uri (which render as consent-page links).
 *
 * Missing → warn (optional; users just see no ATProto/Bluesky
 * button). Present + http(s) → ok. Present + any other scheme or
 * unparseable → error (button silently won't render on real flows).
 */
function checkHandleLoginUrl(metadata: ClientMetadata): PreviewCheck {
  const value = metadata.epds_handle_login_url
  const label = 'epds_handle_login_url set'
  const labelHtml = `${code('epds_handle_login_url')} set`

  if (value === undefined || value === '') {
    return {
      id: 'handle-login-url',
      label,
      severity: 'warn',
      detail:
        'Optional. Without it, the login page doesn\'t render the "Or sign in with ATProto/Bluesky" button, so users coming from a different PDS can\'t hand off to your client.',
      labelHtml,
      detailHtml: `Optional. Without it, the login page doesn't render the "Or sign in with ATProto/Bluesky" button, so users coming from a different PDS can't hand off to your client.`,
    }
  }

  let parsed: URL | null = null
  try {
    parsed = new URL(value)
  } catch {
    // fall through
  }
  if (parsed?.protocol !== 'https:' && parsed?.protocol !== 'http:') {
    return {
      id: 'handle-login-url',
      label,
      severity: 'error',
      detail: `epds_handle_login_url="${value}" is not a valid http(s) URL. The login page rejects it via isSafeHttpUrl and the ATProto/Bluesky button silently won't render on real flows.`,
      labelHtml,
      detailHtml: `${code('epds_handle_login_url')}=${code('"' + value + '"')} is not a valid http(s) URL. The login page rejects it via ${code('isSafeHttpUrl')} and the ATProto/Bluesky button silently won't render on real flows.`,
    }
  }

  return {
    id: 'handle-login-url',
    label,
    severity: 'ok',
    detail: `epds_handle_login_url="${value}". Login page will render the "Or sign in with ATProto/Bluesky" button and hand off to this URL with a handle=<value> query param.`,
    labelHtml,
    detailHtml: `${code('epds_handle_login_url')}=${code('"' + value + '"')}. Login page will render the "Or sign in with ATProto/Bluesky" button and hand off to this URL with a ${code('handle=<value>')} query param.`,
  }
}

function checkPolicyUri(metadata: ClientMetadata): PreviewCheck {
  return checkUriField({
    id: 'policy-uri',
    field: 'policy_uri',
    value: metadata.policy_uri,
    description:
      "Privacy-policy URL. Rendered as a link on the consent page so users can review the client's privacy policy before granting access.",
  })
}

/**
 * Whether the URL appears on the service's trust list. `trustedClients`
 * of null means the caller doesn't know (and we skip the check).
 */
function checkTrustedClient(
  url: string,
  trustedClients: string[] | null,
): PreviewCheck | null {
  if (trustedClients === null) return null
  const trusted = trustedClients.includes(url)
  return {
    id: 'trusted-client',
    label: 'Listed in PDS_OAUTH_TRUSTED_CLIENTS',
    severity: trusted ? 'ok' : 'warn',
    detail: trusted
      ? 'This client is in the trust list, so branding.css is injected on real and preview flows.'
      : "This client is NOT in the trust list on this service — branding.css won't be injected on any flow (real or preview) until it's added. Ask the PDS operator to append your URL to PDS_OAUTH_TRUSTED_CLIENTS.",
    labelHtml: `Listed in ${code('PDS_OAUTH_TRUSTED_CLIENTS')}`,
    detailHtml: trusted
      ? `This client is in the trust list, so ${code('branding.css')} is injected on real and preview flows.`
      : `This client is NOT in the trust list on this service — ${code('branding.css')} won't be injected on any flow (real or preview) until it's added. Ask the PDS operator to append your URL to ${code('PDS_OAUTH_TRUSTED_CLIENTS')}.`,
  }
}

/**
 * Fetch the URL and return one `PreviewCheck` per field we care about.
 * Never throws — transport failures become `error`-severity checks.
 *
 * The `trustedClients` arg is the env-local trust list. Passing `null`
 * skips the trusted-clients check entirely (for contexts where the
 * caller doesn't know it).
 */
export async function validateClientMetadataForPreview(
  url: string,
  trustedClients: string[] | null,
): Promise<PreviewValidationResult> {
  const checks: PreviewCheck[] = []

  // 1. URL shape
  const { parsedUrl, errorCheck: urlParseError } = parseClientIdUrl(url)
  if (!parsedUrl) {
    checks.push(urlParseError!)
    return { url, fetched: false, checks }
  }
  const httpsError = checkHttpsScheme(parsedUrl)
  if (httpsError) {
    checks.push(httpsError)
    // Short-circuit: safeFetch would also reject http: and we'd end up
    // with two overlapping error rows for the same root cause.
    return { url, fetched: false, checks }
  }

  // 2. Fetch
  const fetched = await fetchMetadata(url)
  checks.push(fetched.fetchCheck)
  if (!fetched.metadata) {
    return { url, fetched: false, checks }
  }
  const metadata = fetched.metadata

  // 3. Content checks on the parsed metadata. Legal / discoverability
  // URIs (tos_uri, policy_uri) are technically optional per spec, but
  // their absence is almost always an oversight: without them the
  // consent page has no way to link to the client's terms / privacy
  // policy.
  checks.push(
    checkClientIdMatch(metadata, url),
    checkRedirectUris(metadata),
    checkBrandColor(metadata),
    checkBackgroundColor(metadata),
    checkBrandingCss(metadata),
    checkTosUri(metadata),
    checkPolicyUri(metadata),
    checkHandleLoginUrl(metadata),
  )

  // 4. Trusted-clients membership (optional; caller may skip)
  const trustedCheck = checkTrustedClient(url, trustedClients)
  if (trustedCheck) checks.push(trustedCheck)

  return { url, fetched: true, checks }
}
