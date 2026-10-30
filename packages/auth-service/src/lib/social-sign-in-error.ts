/**
 * Errors from a social (e.g. Google) sign-in, carried back to the
 * login page.
 *
 * The login page's social buttons pass `errorCallbackURL: '/auth/complete'`
 * to better-auth, so a sign-in that is cancelled at the provider or refused
 * by better-auth lands on /auth/complete with `?error=<code>` instead of on
 * better-auth's bare /api/auth/error page. /auth/complete reduces the code
 * to one of a few {@link SocialSignInErrorCode}s and sends the user back to
 * the login page for the same flow with `epds_social_error=<code>`, where
 * it is shown as a fixed message. The button also puts its provider in
 * the errorCallbackURL (`epds_social_provider`), so the message can name
 * it; only names from {@link PROVIDER_NAMES} are ever shown. Nothing else
 * from the query string is reflected into the page.
 */

/** Query parameter that carries the error back to GET /oauth/authorize. */
export const SOCIAL_ERROR_PARAM = 'epds_social_error'

/**
 * Query parameter that carries the provider through the same round trip.
 * On a request without {@link SOCIAL_ERROR_PARAM} it is a client's request
 * to start that provider's sign-in straight away (see login-page.ts).
 */
export const SOCIAL_PROVIDER_PARAM = 'epds_social_provider'

/** Display names for the social providers the login page can offer. */
const PROVIDER_NAMES: Record<string, string> = {
  google: 'Google',
  github: 'GitHub',
}

function providerName(provider: unknown): string | null {
  return typeof provider === 'string' && Object.hasOwn(PROVIDER_NAMES, provider)
    ? PROVIDER_NAMES[provider]
    : null
}

export type SocialSignInErrorCode =
  | 'cancelled'
  | 'email_unverified'
  | 'no_email'
  | 'failed'

// `name` is the provider's display name, or null when it is not known.
const MESSAGES: Record<SocialSignInErrorCode, (name: string | null) => string> =
  {
    cancelled: () =>
      'Sign-in was cancelled. You can try again, or sign in with your email instead.',
    email_unverified: (name) =>
      `${name ?? 'That account'} could not confirm that this email address is yours. Please sign in with a code sent to your email instead.`,
    no_email: (name) =>
      `${name ?? 'That account'} did not share an email address. Please sign in with your email instead.`,
    failed: (name) =>
      `Could not sign in with ${name ?? 'that account'}. Please try again, or sign in with your email instead.`,
  }

/**
 * Reduce an error code from better-auth's OAuth callback (or the provider,
 * which better-auth passes through) to a {@link SocialSignInErrorCode}.
 *
 * - `access_denied`: the user cancelled at the provider.
 * - `account_not_linked`: the email belongs to an existing user and the
 *   provider did not prove control of it (see lib/google-email-verified.ts).
 * - `email_not_verified`: the user-creation guard in better-auth.ts
 *   (refuseUnverifiedUser) refused an email the provider did not prove.
 * - `email_not_found`: the provider returned no email address.
 */
export function socialSignInErrorCode(
  betterAuthError: unknown,
): SocialSignInErrorCode {
  switch (betterAuthError) {
    case 'access_denied':
      return 'cancelled'
    case 'account_not_linked':
    case 'email_not_verified':
      return 'email_unverified'
    case 'email_not_found':
      return 'no_email'
    default:
      return 'failed'
  }
}

/**
 * The message for an `epds_social_error` value, naming the provider when
 * it is a known one, or null if the code is unknown.
 */
export function socialSignInErrorMessage(
  code: unknown,
  provider?: unknown,
): string | null {
  return typeof code === 'string' && Object.hasOwn(MESSAGES, code)
    ? MESSAGES[code as SocialSignInErrorCode](providerName(provider))
    : null
}

/**
 * The login page URL for an existing flow, carrying `code`. Mirrors the
 * redirect /auth/complete already uses when it finds no session.
 */
export function loginPageUrlWithError(
  flow: { requestUri: string; clientId: string | null },
  code: SocialSignInErrorCode,
  provider?: unknown,
): string {
  const params = new URLSearchParams({ request_uri: flow.requestUri })
  if (flow.clientId) params.set('client_id', flow.clientId)
  params.set(SOCIAL_ERROR_PARAM, code)
  if (providerName(provider)) {
    params.set(SOCIAL_PROVIDER_PARAM, provider as string)
  }
  return `/oauth/authorize?${params.toString()}`
}
