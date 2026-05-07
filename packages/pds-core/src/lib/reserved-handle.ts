/**
 * Reserved-subdomain check that mirrors @atproto/pds's
 * `ensureHandleServiceConstraints`.
 *
 * Upstream's reserved list lives at
 * `@atproto/pds/dist/handle/reserved.js` and is not part of the
 * public package exports — only `ensureHandleServiceConstraints` is.
 * That helper throws an `HandleNotAvailable` error when the local
 * part is reserved, but we want a cheap boolean for the live
 * availability check on the handle picker (no need to throw + catch
 * just to render a status string).
 *
 * Import the deep path explicitly. Pinned to the installed
 * `@atproto/pds` version, so a major upgrade can break the import —
 * caught immediately at typecheck / build time.
 */

import { reservedSubdomains } from '@atproto/pds/dist/handle/reserved.js'

export function isReservedSubdomain(local: string): boolean {
  return local.toLowerCase() in reservedSubdomains
}
