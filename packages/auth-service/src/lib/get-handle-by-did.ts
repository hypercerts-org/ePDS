/**
 * Resolve the current handle for a DID via the PDS's public describeRepo
 * XRPC endpoint (`com.atproto.repo.describeRepo`). Returns null if the PDS
 * can't be reached or returns an unexpected shape — callers are expected to
 * degrade gracefully (e.g. show `(unknown)` on the settings page).
 */
import { createLogger } from '@certified-app/shared'

const logger = createLogger('auth:get-handle-by-did')

export async function getHandleByDid(
  did: string,
  pdsUrl: string,
): Promise<string | null> {
  try {
    const res = await fetch(
      `${pdsUrl}/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(did)}`,
      { signal: AbortSignal.timeout(3000) },
    )
    if (!res.ok) return null
    const data = (await res.json()) as { handle?: string }
    return typeof data.handle === 'string' ? data.handle : null
  } catch (err) {
    logger.warn({ err, did }, 'Failed to resolve handle by DID from PDS')
    return null
  }
}
