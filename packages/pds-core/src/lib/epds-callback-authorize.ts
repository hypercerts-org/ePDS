import { VALID_HANDLE_MODES, type HandleMode } from '@certified-app/shared'

export function resolveCallbackHandleMode(
  value: unknown,
): HandleMode | undefined {
  return typeof value === 'string' &&
    (VALID_HANDLE_MODES as readonly string[]).includes(value)
    ? (value as HandleMode)
    : undefined
}

export function buildEpdsCallbackAuthorizeUrl(opts: {
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
