/**
 * Resolves OAuth client metadata from client_id URLs.
 * In ATProto, client_id is typically a URL pointing to a JSON metadata document.
 * Caches results for 10 minutes to avoid repeated fetches.
 */

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
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

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
