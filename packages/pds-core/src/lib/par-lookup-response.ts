/**
 * Response body of /_internal/par-login-hint.
 *
 * `issuer` is the exact OAuth issuer the PDS advertises. auth-service sends
 * it as `iss` on the Atmosphere hand-off, and clients compare it verbatim,
 * so it must come from the OAuth provider, not from PDS_PUBLIC_URL (the two
 * differ, e.g. http vs https on `*.localhost`).
 */
export interface ParLookupResponse {
  login_hint: string | null
  state: string | null
  client_id: string | null
  issuer: string | null
}

/** The PAR parameters this endpoint exposes. */
export interface ParLookupParameters {
  login_hint?: string
  state?: string
  client_id: string
}

/**
 * Build the response for a stored PAR request, or the all-null response when
 * the request is unknown or expired (not an error: there is just no hint).
 */
export function buildParLookupResponse(
  parameters: ParLookupParameters | null,
  issuer: string,
): ParLookupResponse {
  if (!parameters) {
    return { login_hint: null, state: null, client_id: null, issuer: null }
  }
  return {
    login_hint: parameters.login_hint ?? null,
    state: parameters.state ?? null,
    client_id: parameters.client_id,
    issuer,
  }
}
