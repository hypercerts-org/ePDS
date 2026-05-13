/**
 * Security headers builder for the auth-service Express app.
 *
 * Sets the standard X-Frame-Options / X-Content-Type-Options /
 * Referrer-Policy / Strict-Transport-Security headers, plus a
 * Content-Security-Policy whose `img-src` directive is dynamically
 * widened to allow images from the OAuth client's origin (for
 * client-branded login pages).
 *
 * The middleware factory + helpers are pure: no module-level state,
 * no Express types, no res/req mutation outside the well-defined
 * setHeader contract. That keeps them straightforward to unit-test
 * with the same mock-response shape used by the cookie-domain and
 * chooser-enrichment middleware factories in pds-core.
 */

/**
 * Build the `img-src` directive for the auth-service's CSP. Always
 * includes `'self'` and `data:`. If a `client_id` is supplied AND it
 * parses as a URL with a non-`null` origin, that origin is appended so
 * the client's branded logo can render.
 *
 * Returns just the directive value (without the `img-src` keyword) so
 * the caller can splice it into a full CSP string.
 */
export function buildImgSrcDirective(clientId?: string | null): string {
  const baseline = "'self' data:"
  if (!clientId || typeof clientId !== 'string') return baseline
  try {
    const origin = new URL(clientId).origin
    if (origin && origin !== 'null') {
      return `${baseline} ${origin}`
    }
  } catch {
    // not a valid URL, keep default
  }
  return baseline
}

/**
 * Build the full Content-Security-Policy header value used by the
 * auth-service. Composed of fixed directives plus a dynamically
 * computed `img-src`.
 */
export function buildAuthServiceCsp(clientId?: string | null): string {
  const imgSrc = buildImgSrcDirective(clientId)
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    `img-src ${imgSrc}`,
    "connect-src 'self'",
  ].join('; ')
}

/**
 * Minimal shape of `http.ServerResponse` we need to set headers on.
 * Narrow on purpose so unit tests can use a fake without depending on
 * Express types.
 */
export interface SecurityHeadersResponse {
  setHeader: (name: string, value: string) => unknown
}

/**
 * Minimal request shape: we read `query.client_id`, `query.request_uri`
 * and `body?.client_id`, any of which may be missing.
 */
export interface SecurityHeadersRequest {
  query: Record<string, unknown>
  body?: Record<string, unknown> | null
}

/**
 * Optional lookup used when `client_id` is absent from the request but
 * `request_uri` is present — e.g. back-navigation from the recovery
 * page leaves a bare request_uri link. Return the stored clientId for
 * the flow, or null when unknown. Kept as a plain callback so the
 * middleware stays decoupled from any specific DB type.
 */
export type AuthFlowClientIdLookup = (requestUri: string) => string | null

export interface CreateSecurityHeadersMiddlewareOptions {
  authFlowLookup?: AuthFlowClientIdLookup
}

/** Minimal Express middleware `next()` callback. */
export type SecurityHeadersNext = () => void

/**
 * Pull the OAuth `client_id` out of either the query string or the
 * request body. We accept both because some routes are GET (login
 * page) and others are POST (form submissions). Returns null when
 * the client_id is absent or not a string.
 */
export function extractClientIdFromRequest(
  req: SecurityHeadersRequest,
): string | null {
  const fromQuery = req.query.client_id
  if (typeof fromQuery === 'string') return fromQuery
  const fromBody = req.body?.client_id
  if (typeof fromBody === 'string') return fromBody
  return null
}

/**
 * Resolve the effective clientId for CSP widening: prefer a client_id
 * carried directly on the request (query or body), else fall back to
 * the clientId stored against the request_uri in the auth_flow table.
 * The fallback covers back-navigation from recovery, where the URL
 * carries only request_uri. Returns null when no source yields one.
 */
export function resolveClientIdForCsp(
  req: SecurityHeadersRequest,
  authFlowLookup?: AuthFlowClientIdLookup,
): string | null {
  const direct = extractClientIdFromRequest(req)
  if (direct) return direct
  if (!authFlowLookup) return null
  const requestUri = req.query.request_uri
  if (typeof requestUri !== 'string' || !requestUri) return null
  return authFlowLookup(requestUri)
}

/**
 * Build the auth-service security headers middleware. Sets the
 * standard hardening headers plus a dynamically-built CSP whose
 * `img-src` accommodates the requesting OAuth client's origin.
 *
 * Pure factory: zero side-effects at module load, safe to call from
 * `main()` or unit tests alike.
 */
export function createSecurityHeadersMiddleware(
  options: CreateSecurityHeadersMiddlewareOptions = {},
) {
  const { authFlowLookup } = options
  return function securityHeadersMiddleware(
    req: SecurityHeadersRequest,
    res: SecurityHeadersResponse,
    next: SecurityHeadersNext,
  ): void {
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')

    const clientId = resolveClientIdForCsp(req, authFlowLookup)
    res.setHeader('Content-Security-Policy', buildAuthServiceCsp(clientId))
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=63072000; includeSubDomains; preload',
    )
    next()
  }
}
