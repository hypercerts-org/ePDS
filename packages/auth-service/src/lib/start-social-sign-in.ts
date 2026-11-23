/**
 * Start a social sign-in on the server, for GET /oauth/authorize with
 * ?epds_social_provider= (see routes/login-page.ts): the browser is sent
 * straight to the provider instead of loading the login page first.
 *
 * better-auth is asked for exactly what the login page's button asks for
 * with POST /api/auth/sign-in/social. Its answer carries the provider URL
 * and a Set-Cookie for the signed OAuth state, which the provider callback
 * checks, so the caller must send both to the browser.
 */
import { createLogger } from '@certified-app/shared'
import type { BetterAuthInstance } from '../better-auth.js'
import { osmIssuer, OSM_PROVIDER_ID } from './openstreetmap.js'
import { SOCIAL_PROVIDER_PARAM } from './social-sign-in-error.js'

const logger = createLogger('auth:start-social-sign-in')

/** The social providers a sign-in can be started for. */
export type StartableSocialProvider = 'google' | typeof OSM_PROVIDER_ID

/**
 * The origin of each provider's authorization server. OpenStreetMap's is
 * its configured issuer (`OSM_ISSUER`), whose discovery document serves
 * the authorization endpoint on the same origin.
 */
export function providerOrigins(
  env: NodeJS.ProcessEnv = process.env,
): Record<StartableSocialProvider, string> {
  return {
    google: 'https://accounts.google.com',
    [OSM_PROVIDER_ID]: osmIssuer(env),
  }
}

/**
 * `url` if it is an https URL on `provider`'s authorization server, else
 * null. The same check the login page's button makes before following the
 * URL better-auth returns.
 */
export function providerAuthorizationUrl(
  provider: string,
  url: unknown,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const origins: Record<string, string> = providerOrigins(env)
  if (typeof url !== 'string' || !Object.hasOwn(origins, provider)) {
    return null
  }
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' && parsed.origin === origins[provider]
      ? parsed.href
      : null
  } catch {
    return null
  }
}

export interface SocialSignInStart {
  /** The provider's authorization URL to redirect the browser to. */
  url: string
  /** Set-Cookie values better-auth issued for this sign-in. */
  cookies: string[]
}

/**
 * Start `provider`'s sign-in, passing `loginHint` to Google when set
 * (OpenStreetMap signs in by username, so an email hint means nothing to
 * it). Resolves to null when the sign-in could not be started.
 */
export async function startSocialSignIn(
  auth: Pick<BetterAuthInstance, 'api'>,
  provider: StartableSocialProvider,
  loginHint: string,
): Promise<SocialSignInStart | null> {
  try {
    const { headers, response } = await auth.api.signInSocial({
      body: {
        provider,
        callbackURL: '/auth/complete',
        // Cancels and refusals return to the login page with a message
        // naming the provider (see lib/social-sign-in-error.ts).
        errorCallbackURL: `/auth/complete?${SOCIAL_PROVIDER_PARAM}=${provider}`,
        disableRedirect: true,
        ...(loginHint && provider === 'google' ? { loginHint } : {}),
      },
      returnHeaders: true,
    })
    const url = providerAuthorizationUrl(provider, response.url)
    if (!url) {
      logger.error({ provider }, 'Social sign-in returned no provider URL')
      return null
    }
    return { url, cookies: headers.getSetCookie() }
  } catch (err) {
    logger.error({ err, provider }, 'Failed to start social sign-in')
    return null
  }
}
