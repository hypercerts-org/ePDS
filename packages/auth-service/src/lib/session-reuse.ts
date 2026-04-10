/**
 * Session-reuse detection for HYPER-268.
 *
 * When a user has already signed in via any OAuth client in this browser,
 * the upstream @atproto/oauth-provider's DeviceManager stores a dev-id
 * cookie on the shared parent domain (see packages/pds-core cookie-domain
 * middleware). The auth-service uses these helpers to decide, on incoming
 * /oauth/authorize requests, whether to bypass its own email/OTP login
 * form and redirect the browser to pds-core's upstream middleware, which
 * then either auto-selects a matching session (flow 1 with login_hint)
 * or renders the account chooser (flow 2).
 */

/** Shape of the request data the helpers consume. Intentionally narrow
 *  so we can unit-test without an Express instance. Mirrors the fields
 *  of `http.IncomingMessage`/`express.Request` that we actually read. */
export type SessionReuseRequest = {
  /** The parsed Express `req.cookies` bag (populated when the
   *  cookie-parser middleware is installed). May be undefined. */
  cookies?: Record<string, string>
  /** Raw HTTP headers. We fall back to parsing `cookie` here when the
   *  parsed bag is missing. */
  headers: {
    cookie?: string
  }
  /** Parsed query string. We honour `prompt=login` as an override. */
  query: Record<string, unknown>
}

/** True if the request carries a `dev-id` cookie, meaning the browser
 *  already has an upstream device session on the pds-core side that the
 *  auth-service should defer to rather than re-prompting for credentials.
 *
 *  Uses the parsed cookie bag first (which is produced by cookie-parser
 *  and normalised), then falls back to regex-scanning the raw Cookie
 *  header so we never miss an existing session even in configurations
 *  where cookie-parser is not mounted. */
export function hasDeviceSessionCookie(req: SessionReuseRequest): boolean {
  if (req.cookies && typeof req.cookies['dev-id'] === 'string') return true
  const raw = req.headers.cookie ?? ''
  return /(?:^|;\s*)dev-id=/.test(raw)
}

/** True if the client is asking the authorization server to force a
 *  fresh credential prompt. Maps to OIDC's standard `prompt=login`
 *  parameter (https://openid.net/specs/openid-connect-core-1_0.html
 *  #AuthRequest): "The Authorization Server SHOULD prompt the End-User
 *  for reauthentication". The "Use a different account" link injected
 *  into the chooser in pds-core uses this to opt out of session reuse. */
export function isForceLoginPrompt(req: SessionReuseRequest): boolean {
  const p = req.query.prompt
  return typeof p === 'string' && p === 'login'
}

/** True if the current /oauth/authorize request should be redirected to
 *  pds-core's upstream /oauth/authorize for session-reuse handling,
 *  bypassing the ePDS email/OTP form. */
export function shouldReuseSession(req: SessionReuseRequest): boolean {
  if (isForceLoginPrompt(req)) return false
  return hasDeviceSessionCookie(req)
}

/** Build the pds-core /oauth/authorize URL to redirect to, preserving
 *  the full original query string unmodified. pds-core's upstream
 *  middleware uses request_uri to look up the PAR request and
 *  login_hint to auto-select a matching session. */
export function buildPdsAuthorizeRedirect(
  pdsPublicUrl: string,
  query: Record<string, unknown>,
): string {
  const target = new URL('/oauth/authorize', pdsPublicUrl)
  for (const [k, v] of Object.entries(query)) {
    if (typeof v === 'string') {
      target.searchParams.set(k, v)
    } else if (Array.isArray(v)) {
      for (const one of v) {
        if (typeof one === 'string') target.searchParams.append(k, one)
      }
    }
  }
  return target.toString()
}
