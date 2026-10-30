/**
 * The one check for "this better-auth user's email is verified".
 *
 * ePDS keys a sign-in to a PDS account by email alone, so every route that
 * decides whether a session may act for that address (/auth/complete,
 * /auth/choose-handle, account settings, GET /account/login) and the
 * user-creation guard in better-auth.ts must agree on it. A looser check in
 * one route and a strict one in another made /account and /account/login
 * redirect to each other forever for some rows.
 */
export function hasVerifiedEmail(
  user: { emailVerified?: unknown } | null | undefined,
): boolean {
  return user?.emailVerified === true
}
