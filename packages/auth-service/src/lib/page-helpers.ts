export function renderOptionalStyleTag(css?: string | null): string {
  if (!css) return ''
  return `\n  <style>${css}</style>`
}

export function buildPdsAuthorizeUrl(
  pdsPublicUrl: string,
  requestUri: string,
  clientId?: string,
): string {
  const url = new URL('/oauth/authorize', pdsPublicUrl)
  url.searchParams.set('request_uri', requestUri)
  if (clientId) {
    url.searchParams.set('client_id', clientId)
  }
  return url.toString()
}
