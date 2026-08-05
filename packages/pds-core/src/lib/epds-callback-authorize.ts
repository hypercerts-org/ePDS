import { VALID_HANDLE_MODES, type HandleMode } from '@certified-app/shared'

export function resolveCallbackHandleMode(
  value: unknown,
): HandleMode | undefined {
  return typeof value === 'string' &&
    (VALID_HANDLE_MODES as readonly string[]).includes(value)
    ? (value as HandleMode)
    : undefined
}

/**
 * Builds the post-/oauth/epds-callback redirect back to stock /oauth/authorize.
 * This differs from auth-service callback builders, which create signed
 * auth-service -> pds-core /oauth/epds-callback URLs. It is extracted from the
 * old inline construction so epds_handle_mode forwarding and sanitization can be
 * unit-tested.
 */
export function buildPostCallbackAuthorizeUrl(opts: {
  pdsUrl: string
  requestUri: string
  clientId: string
  handleMode: unknown
}): URL {
  const authorizeUrl = new URL('/oauth/authorize', opts.pdsUrl)
  authorizeUrl.searchParams.set('request_uri', opts.requestUri)
  authorizeUrl.searchParams.set('client_id', opts.clientId)

  const handleMode = resolveCallbackHandleMode(opts.handleMode)
  if (handleMode) authorizeUrl.searchParams.set('epds_handle_mode', handleMode)

  return authorizeUrl
}
