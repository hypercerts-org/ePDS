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
 * - The provider is keyed by the ID token's verified `sub`, which
 *   better-auth stores as the account's `accountId`. A returning sign-in
 *   finds its user by `(providerId, accountId)`, never by email.
 * - {@link mapOsmProfileToUser} replaces the email with a placeholder in
 *   the reserved `.invalid` TLD (RFC 2606), unique per `sub` and marked
 *   unverified. No real user can hold such an address (no email code can
 *   reach it), so better-auth's implicit linking by email never matches,
 *   and the user-creation guard in better-auth.ts refuses it anyway.
 * - `disableSignUp` makes an unconnected sign-in fail with
 *   `signup_disabled` before any user is created.
 * - The only way to connect an OpenStreetMap identity is the explicit
 *   link from account settings, which needs a live session for the
 *   account (see `openStreetMapAccountLinking` in better-auth.ts).
 */
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

/**
 * The placeholder address for an OpenStreetMap `sub`, or undefined when
 * the `sub` is not a plain OSM user id. Without an address better-auth
 * ends the sign-in with `email_not_found`.
 */
export function osmPlaceholderEmail(sub: unknown): string | undefined {
  const id = typeof sub === 'number' ? String(sub) : sub
  if (typeof id !== 'string' || !/^\d{1,20}$/.test(id)) return undefined
  return `${id}@${OSM_PLACEHOLDER_EMAIL_DOMAIN}`
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
  return {
    providerId: OSM_PROVIDER_ID,
    name: 'OpenStreetMap',
    discoveryUrl: `${osmIssuer(env)}/.well-known/openid-configuration`,
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
  }
}
