/**
 * Resolves OAuth client metadata from client_id URLs.
 *
 * In ATProto, client_id is typically a URL pointing to a JSON metadata
 * document.  The standard @atproto/oauth-provider strips non-standard
 * fields via Zod validation, so this module fetches the raw JSON
 * independently and preserves ePDS extension fields (brand_color,
 * epds_handle_mode, epds_skip_consent_on_signup, etc.).
 *
 * Results are cached for 10 minutes to avoid repeated fetches.
 */

import type { HandleMode } from './handle.js'

export interface ClientBranding {
  css?: string
}

export interface ClientMetadata {
  client_name?: string
  client_uri?: string
  logo_uri?: string
  tos_uri?: string
  policy_uri?: string
  email_template_uri?: string
  email_subject_template?: string
  brand_color?: string
  background_color?: string
  /**
   * ePDS extension — declares the default handle assignment mode for new users.
   * Accepted values: 'random' | 'picker' | 'picker-with-random'.
   * Validated against VALID_HANDLE_MODES by the login-page handler before being
   * stored on the auth_flow row. Invalid values are silently treated as null.
   */
  epds_handle_mode?: HandleMode
  /**
   * ePDS extension — when true, the client requests that consent be
   * skipped on initial sign-up.  Only honoured when BOTH:
   *   1. PDS_SIGNUP_ALLOW_CONSENT_SKIP is truthy on the PDS
   *   2. The client is in PDS_OAUTH_TRUSTED_CLIENTS (isTrusted)
   */
  epds_skip_consent_on_signup?: boolean
  branding?: ClientBranding
}

interface CacheEntry {
  metadata: ClientMetadata
  expiresAt: number
}

const CACHE_TTL_MS = 10 * 60 * 1000 // 10 minutes
const FETCH_TIMEOUT_MS = 5000

const cache = new Map<string, CacheEntry>()

export async function resolveClientName(clientId: string): Promise<string> {
  const metadata = await resolveClientMetadata(clientId)
  return metadata.client_name || extractDomain(clientId) || 'an application'
}

export async function resolveClientMetadata(
  clientId: string,
): Promise<ClientMetadata> {
  // Only fetch if client_id looks like a URL
  if (!clientId.startsWith('http://') && !clientId.startsWith('https://')) {
    return { client_name: clientId }
  }

  // Check cache
  const cached = cache.get(clientId)
  if (cached && cached.expiresAt > Date.now()) {
    return cached.metadata
  }

  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => {
      controller.abort()
    }, FETCH_TIMEOUT_MS)

    const res = await fetch(clientId, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })

    clearTimeout(timeout)

    if (!res.ok) {
      return fallback(clientId)
    }

    const metadata = (await res.json()) as ClientMetadata

    // Cache the result
    cache.set(clientId, {
      metadata,
      expiresAt: Date.now() + CACHE_TTL_MS,
    })

    return metadata
  } catch {
    return fallback(clientId)
  }
}

function fallback(clientId: string): ClientMetadata {
  const name = extractDomain(clientId)
  const metadata = { client_name: name || undefined }
  // Cache failures briefly (1 minute) to avoid hammering
  cache.set(clientId, {
    metadata,
    expiresAt: Date.now() + 60_000,
  })
  return metadata
}

function extractDomain(urlStr: string): string | null {
  try {
    const url = new URL(urlStr)
    return url.hostname
  } catch {
    return null
  }
}

/**
 * Escape CSS for safe embedding in an HTML <style> tag.
 * Replaces `</style>` (case-insensitive) with `\u003c/style>` to prevent
 * premature tag closure / HTML injection. Matches the upstream pattern in
 * oauth-provider/src/lib/html/escapers.ts.
 */
export function escapeCss(css: string): string {
  return css.replace(/<\/style>/gi, '\\u003c/style>')
}

/**
 * Returns escaped CSS for injection if the client is trusted, or null.
 */
export function getClientCss(
  clientId: string,
  metadata: ClientMetadata,
  trustedClients: string[],
): string | null {
  if (!trustedClients.includes(clientId)) return null
  const raw = metadata.branding?.css
  if (!raw) return null
  return escapeCss(raw)
}

// Cleanup expired cache entries periodically
setInterval(
  () => {
    const now = Date.now()
    for (const [key, entry] of cache) {
      if (entry.expiresAt <= now) cache.delete(key)
    }
  },
  5 * 60 * 1000,
).unref()
