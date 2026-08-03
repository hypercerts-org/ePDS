/**
 * Branded-identifier guards for the `/_internal` handle-lookup endpoints.
 *
 * Upstream's account APIs now require branded `HandleString` /
 * `AtIdentifierString` values (oauth-provider-api 0.7 / @atproto/syntax), so
 * each endpoint validates its input before calling accountManager. The guard
 * decision differs by endpoint, and one case is non-obvious (an invalid handle
 * on the availability check must read as *taken*, not *free*). Extracting the
 * decisions here — following the `upstream-favicon.ts` pattern — keeps them
 * unit-testable without standing up the PDS.
 *
 * These are type predicates: a `true` result narrows the argument to the
 * branded type the accountManager call requires, so callers get both the
 * documented decision and the compile-time narrowing.
 */
import {
  isValidHandle,
  isValidAtIdentifier,
  type HandleString,
  type AtIdentifierString,
} from '@atproto/syntax'

/**
 * `/_internal/account-by-handle` accepts a handle OR a DID. An invalid
 * identifier cannot match any account, so a `false` result short-circuits the
 * endpoint to `{ email: null }` (its not-found response).
 */
export function canLookUpAccountByHandle(
  identifier: string,
): identifier is AtIdentifierString {
  return isValidAtIdentifier(identifier)
}

/**
 * `/_internal/check-handle` (signup availability) accepts only a handle. A
 * `false` result means the handle can never be registered, so the endpoint
 * reports it as *unavailable* (`{ exists: true }`) rather than free —
 * otherwise signup proceeds and then fails at account creation.
 */
export function canCheckHandle(handle: string): handle is HandleString {
  return isValidHandle(handle)
}

/**
 * Hosted-domain handle resolution accepts only a handle. A `false` result
 * resolves to 404, the same as an absent account.
 */
export function canResolveHandle(handle: string): handle is HandleString {
  return isValidHandle(handle)
}
