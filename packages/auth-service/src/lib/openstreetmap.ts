/**
 * OpenStreetMap sign-in, configured through better-auth's generic OAuth
 * plugin as an OpenID Connect provider.
 *
 * OpenStreetMap is a different kind of social provider from Google. It
 * never vouches for an email address (its OIDC discovery lists no
 * `email_verified` claim, and the address is only shared with the extra
 * `read_email` scope), while ePDS keys every PDS account by a verified
 * email. So an OpenStreetMap identity is only ever a second way into an
 * account that already proved its address with an email code:
 *
 * - The provider is keyed by the ID token's verified `sub`, qualified
 *   with the issuer's host ({@link osmAccountSubject}), which better-auth
 *   stores as the account's `accountId`. OSM user ids are unique only
 *   within one OSM instance, so without the host a link made against the
 *   dev server would match a production user with the same id if
 *   `OSM_ISSUER` changed over the same database. A returning sign-in finds
 *   its user by `(providerId, accountId)`, never by email.
 * - {@link mapOsmProfileToUser} replaces the email with a random
 *   placeholder in the reserved `.invalid` TLD (RFC 2606), fresh on every
 *   sign-in and marked unverified. better-auth would otherwise link a
 *   trusted provider's sign-in to an existing user with the same verified
 *   email; an unpredictable address can never be such a user's, even one
 *   that somehow holds a `.invalid` address. The user-creation guard in
 *   better-auth.ts refuses it anyway.
 * - `disableSignUp` makes an unconnected sign-in fail with
 *   `signup_disabled` before any user is created.
 * - The only way to connect an OpenStreetMap identity is the explicit
 *   link from account settings, which needs a live session for the
 *   account (see `openStreetMapAccountLinking` in better-auth.ts).
 */
import { randomUUID } from 'node:crypto'
import type { GenericOAuthConfig } from 'better-auth/plugins'

/** better-auth provider id; also the callback path segment. */
export const OSM_PROVIDER_ID = 'openstreetmap'

/** The production OpenStreetMap OIDC issuer. */
export const DEFAULT_OSM_ISSUER = 'https://www.openstreetmap.org'

/** Domain of the placeholder addresses; `.invalid` can never resolve. */
export const OSM_PLACEHOLDER_EMAIL_DOMAIN = 'users.openstreetmap.invalid'

/**
 * The configured issuer's origin, from `OSM_ISSUER` (for example
 * `https://master.apis.dev.openstreetmap.org` for the OSM dev server).
 * Only an https URL is accepted; anything else falls back to production.
 */
export function osmIssuer(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.OSM_ISSUER?.trim()
  if (!raw) return DEFAULT_OSM_ISSUER
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' ? url.origin : DEFAULT_OSM_ISSUER
  } catch {
    return DEFAULT_OSM_ISSUER
  }
}

/** `sub` as a plain OSM user id (digits), or undefined. */
function osmUserId(sub: unknown): string | undefined {
  const id = typeof sub === 'number' ? String(sub) : sub
  return typeof id === 'string' && /^\d{1,20}$/.test(id) ? id : undefined
}

/**
 * The account key for an OpenStreetMap `sub` from `issuer`:
 * `<issuer host>:<user id>`, or '' when the `sub` is not a plain OSM user
 * id, which better-auth rejects (OAUTH_ACCOUNT_SUBJECT_INVALID) before
 * any lookup or link.
 */
export function osmAccountSubject(issuer: string, sub: unknown): string {
  const id = osmUserId(sub)
  return id ? `${new URL(issuer).host}:${id}` : ''
}

/**
 * The OSM user id and instance host of an account key, for display. A key
 * without a host (none are written that way) is shown as it is.
 */
export function parseOsmAccountId(accountId: string): {
  userId: string
  host: string | null
} {
  const at = accountId.lastIndexOf(':')
  return at < 0
    ? { userId: accountId, host: null }
    : { userId: accountId.slice(at + 1), host: accountId.slice(0, at) }
}

/**
 * A fresh, unpredictable placeholder address for an OpenStreetMap sign-in,
 * or undefined when the `sub` is not a plain OSM user id. Without an
 * address better-auth ends the sign-in with `email_not_found`.
 */
export function osmPlaceholderEmail(sub: unknown): string | undefined {
  if (!osmUserId(sub)) return undefined
  return `${randomUUID()}@${OSM_PLACEHOLDER_EMAIL_DOMAIN}`
}

/**
 * better-auth `mapProfileToUser` for OpenStreetMap: never a real or
 * verified email (see the module comment), and the OSM username as the
 * display name.
 */
export function mapOsmProfileToUser(profile: {
  sub?: unknown
  preferred_username?: unknown
}): { email: string | undefined; emailVerified: false; name: string } {
  return {
    email: osmPlaceholderEmail(profile.sub),
    emailVerified: false,
    name:
      typeof profile.preferred_username === 'string'
        ? profile.preferred_username
        : '',
  }
}

/**
 * The generic OAuth config for OpenStreetMap, or null unless both
 * `OSM_CLIENT_ID` and `OSM_CLIENT_SECRET` are set.
 */
export function buildOpenStreetMapConfig(
  env: NodeJS.ProcessEnv = process.env,
): GenericOAuthConfig | null {
  const clientId = env.OSM_CLIENT_ID
  const clientSecret = env.OSM_CLIENT_SECRET
  if (!clientId || !clientSecret) return null
  const issuer = osmIssuer(env)
  return {
    providerId: OSM_PROVIDER_ID,
    name: 'OpenStreetMap',
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    // Identity comes from the ID token's `sub`, so refuse to register the
    // provider if discovery cannot supply the JWKS to verify it.
    requireIdTokenVerification: true,
    clientId,
    clientSecret,
    // `openid` alone: ePDS needs only the stable `sub`. No email, no
    // permission to edit the map; apps ask OSM for that themselves.
    scopes: ['openid'],
    pkce: true,
    disableSignUp: true,
    mapProfileToUser: mapOsmProfileToUser,
    // better-auth passes the userinfo profile only after checking its
    // `sub` against the verified ID token's.
    accountSubject: ({ profile }) =>
      osmAccountSubject(issuer, (profile as { sub?: unknown }).sub),
  }
}
