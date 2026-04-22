/**
 * Resolves OAuth client metadata from client_id URLs.
 *
 * In ATProto, client_id is typically a URL pointing to a JSON metadata
 * document.  The standard @atproto/oauth-provider strips non-standard
 * fields via Zod validation, so this module fetches the raw JSON
 * independently and preserves ePDS extension fields (brand_color,
 * epds_handle_mode, epds_skip_consent_on_signup, etc.).
 *
 * Shared between pds-core (CSS injection middleware) and auth-service
 * (login/consent page branding).
 *
 * Results are cached for 10 minutes to avoid repeated fetches.
 */

import type { HandleMode } from './handle.js'
import { createLogger } from './logger.js'
import { makeSafeFetch } from './safe-fetch.js'

const logger = createLogger('shared:client-metadata')

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
  branding?: ClientBranding
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
}

interface CacheEntry {
  metadata: ClientMetadata
  expiresAt: number
}

const CACHE_TTL_MS = 10 * 60 * 1000 // 10 minutes

const cache = new Map<string, CacheEntry>()

/** Clears the in-memory cache. Intended for use in tests only. */
export function clearClientMetadataCache(): void {
  cache.clear()
}

/** Seed the metadata cache. Intended for tests only. */
export function _seedClientMetadataCacheForTest(
  clientId: string,
  metadata: ClientMetadata,
): void {
  cache.set(clientId, { metadata, expiresAt: Date.now() + CACHE_TTL_MS })
}

/**
 * Inspect the in-memory client-metadata cache. Returns one entry per
 * cached clientId with its expiry timestamp (ms since epoch). Expired
 * entries are skipped. Read-only; does not mutate the cache.
 *
 * Intended for operators/devs to see "how long until the next real
 * OAuth flow for this client re-fetches its metadata" — exposed by the
 * /preview/cache-status endpoint.
 */
export function getClientMetadataCacheStatus(): Array<{
  clientId: string
  expiresAt: number
}> {
  const now = Date.now()
  const entries: Array<{ clientId: string; expiresAt: number }> = []
  for (const [clientId, entry] of cache) {
    if (entry.expiresAt > now) {
      entries.push({ clientId, expiresAt: entry.expiresAt })
    }
  }
  return entries
}

const safeFetch = makeSafeFetch({ timeoutMs: 5_000 })

export async function resolveClientName(clientId: string): Promise<string> {
  const metadata = await resolveClientMetadata(clientId)
  return metadata.client_name || extractDomain(clientId) || 'an application'
}

export interface ResolveClientMetadataOptions {
  /**
   * When true, ignore any existing cache entry for this clientId and
   * refetch from the network. A successful fetch still populates the
   * cache. Intended for preview/dev loops where the upstream metadata
   * JSON is being edited live.
   */
  noCache?: boolean
}

export async function resolveClientMetadata(
  clientId: string,
  options: ResolveClientMetadataOptions = {},
): Promise<ClientMetadata> {
  // Only attempt a fetch for URL-shaped client IDs
  let parsedUrl: URL
  try {
    parsedUrl = new URL(clientId)
  } catch {
    return { client_name: clientId }
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return { client_name: clientId }
  }

  if (!options.noCache) {
    const cached = cache.get(clientId)
    if (cached && cached.expiresAt > Date.now()) {
      return cached.metadata
    }
  }

  try {
    // safeFetch enforces HTTPS, blocks private/reserved IPs, and applies a
    // timeout — throws for any blocked or failed request
    const res = await safeFetch(clientId, {
      headers: { Accept: 'application/json' },
    })

    if (!res.ok) {
      logger.warn(
        { clientId, status: res.status },
        'Client metadata fetch returned non-OK status; using fallback',
      )
      return fallback(clientId, options.noCache === true)
    }

    const metadata = (await res.json()) as ClientMetadata

    // Cache the result
    cache.set(clientId, {
      metadata,
      expiresAt: Date.now() + CACHE_TTL_MS,
    })

    return metadata
  } catch (err) {
    // Previously swallowed silently — meant a transient boot-time fetch
    // failure would cache a branding-less fallback for 60s with no audit
    // trail. Logging keeps the "don't throw" ergonomics for callers while
    // making the negative cache diagnosable.
    logger.warn(
      { err, clientId },
      'Client metadata fetch failed; using fallback',
    )
    return fallback(clientId, options.noCache === true)
  }
}

function fallback(clientId: string, skipCache: boolean): ClientMetadata {
  const name = extractDomain(clientId)
  const metadata = { client_name: name || undefined }
  // Cache failures briefly (1 minute) to avoid hammering — but only
  // when called from a real flow. `noCache:true` callers (preview
  // flows) skip the cache read and skip writing this degraded
  // fallback entry; a successful fetch further up still writes to the
  // cache, per the `noCache` JSDoc. Without this guard, a failing
  // preview fetch would overwrite a valid 10-minute entry with a
  // branding-less 60-second one, silently dropping CSS on real flows.
  if (!skipCache) {
    cache.set(clientId, {
      metadata,
      expiresAt: Date.now() + 60_000,
    })
  }
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
  return css.replace(/<\/style[^>]*>/gi, '\\u003c/style>')
}

/** Maximum allowed size for injected CSS. Values above this are dropped. */
export const MAX_CSS_BYTES = 32_768 // 32 KB

/**
 * Returns escaped CSS for injection if the client is trusted, or null.
 *
 * TODO: add CSS sanitization to strip dangerous primitives (@import, url(),
 * expression(), javascript:, behavior:, -moz-binding) before injection.
 */
export function getClientCss(
  clientId: string,
  metadata: ClientMetadata,
  trustedClients: string[],
): string | null {
  if (!trustedClients.includes(clientId)) return null
  const raw = metadata.branding?.css
  if (!raw) return null
  const escaped = escapeCss(raw)
  if (Buffer.byteLength(escaped, 'utf8') > MAX_CSS_BYTES) return null
  return escaped
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
