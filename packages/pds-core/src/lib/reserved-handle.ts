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

/**
 * Compute the `exists` field returned by /_internal/check-handle.
 *
 * The handle picker's live availability check treats "exists" as
 * "this handle is unavailable to claim" — which has two distinct
 * sources:
 *
 *   1. Someone already owns it (DB row in accountManager).
 *   2. It's in the upstream reserved-subdomains list (admin, www,
 *      support, …). createAccount would later throw
 *      HandleUnavailableError; better to flag it here so the picker
 *      disables Submit and shows the same "not available" status as
 *      the already-owned case.
 *
 * Pure function so the route handler can stay thin and unit tests
 * cover the OR-shape directly without standing up the full PDS.
 */
export function handleIsUnavailable(opts: {
  fullHandle: string
  accountExists: boolean
}): boolean {
  if (opts.accountExists) return true
  const local = opts.fullHandle.split('.')[0] ?? ''
  return isReservedSubdomain(local)
}
