/**
 * sec-fetch-site rewrite logic for GET /oauth/authorize.
 *
 * PR #21 changed epds-callback to redirect through the stock
 * @atproto/oauth-provider /oauth/authorize endpoint. The browser tags that
 * redirect as `same-site` (auth subdomain → PDS origin), but the upstream
 * oauth-provider rejects `same-site` — it only accepts `same-origin`,
 * `cross-site`, or `none`.
 *
 * Extracted into a pure function so it can be unit-tested without Express.
 */

export interface RewriteParams {
  method: string
  path: string
  secFetchSite: string | undefined
  referer: string | undefined
  authOrigin: string
  pdsOrigin: string
}

/**
 * Returns true if the sec-fetch-site header should be rewritten from
 * `same-site` to `same-origin` for this request.
 *
 * Only rewrites when:
 * - The request is GET /oauth/authorize
 * - sec-fetch-site is exactly `same-site`
 * - The referer is the auth subdomain, the PDS itself, or absent
 *
 * Unknown same-site origins are left untouched to preserve the security boundary.
 */
export function shouldRewriteSecFetchSite(params: RewriteParams): boolean {
  const { method, path, secFetchSite, referer, authOrigin, pdsOrigin } = params

  if (method !== 'GET' || path !== '/oauth/authorize') return false
  if (secFetchSite !== 'same-site') return false

  if (!referer) return true

  const allowedOrigins = [authOrigin, pdsOrigin]
  return allowedOrigins.some((origin) => referer.startsWith(origin))
}
