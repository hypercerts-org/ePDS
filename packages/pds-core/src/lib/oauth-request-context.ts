/**
 * OAuth request-context helpers for pds-core response enrichment.
 *
 * OAuth authorize pages may receive either a direct `client_id` query
 * parameter or only a PAR `request_uri`. This module owns the narrow
 * resolution step from the current request query to the OAuth client id,
 * while callers keep their feature-specific policy decisions local.
 */

export type OAuthRequestQuery = Record<string, unknown>

export type ResolveClientIdFromRequestUri = (
  requestUri: string,
) => Promise<string | undefined>

/**
 * Resolve the OAuth client id visible from the current request query.
 *
 * Prefer an explicit `client_id` query parameter. When it is absent,
 * optionally resolve the PAR `request_uri` through the provider request
 * manager supplied by the caller. Resolver errors are intentionally left
 * to the caller so each middleware can choose its own logging and fallback
 * behaviour.
 */
export async function resolveOAuthClientIdFromQuery(
  query: OAuthRequestQuery,
  resolveClientIdFromRequestUri?: ResolveClientIdFromRequestUri,
): Promise<string | undefined> {
  if (typeof query.client_id === 'string') return query.client_id
  if (!resolveClientIdFromRequestUri) return undefined

  const requestUri =
    typeof query.request_uri === 'string' ? query.request_uri : undefined
  if (!requestUri) return undefined

  return resolveClientIdFromRequestUri(requestUri)
}
