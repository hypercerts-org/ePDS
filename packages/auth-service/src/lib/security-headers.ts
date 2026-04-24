/**
 * Security headers builder for the auth-service Express app.
 *
 * Sets the standard X-Frame-Options / X-Content-Type-Options /
 * Referrer-Policy / Strict-Transport-Security headers, plus a
 * Content-Security-Policy whose `img-src` directive is dynamically
 * widened to allow images from the OAuth client's origin (for
 * client-branded login pages).
 */

/**
 * Build the `img-src` directive for the auth-service's CSP. Always
 * includes `'self'` and `data:`. If a `client_id` is supplied AND it
 * parses as a URL with a non-`null` origin, that origin is appended so
 * the client's branded logo can render.
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

export interface SecurityHeadersResponse {
  setHeader: (name: string, value: string) => unknown
}

export interface SecurityHeadersRequest {
  query: Record<string, unknown>
  body?: Record<string, unknown> | null
}

export type AuthFlowClientIdLookup = (requestUri: string) => string | null

export interface CreateSecurityHeadersMiddlewareOptions {
  authFlowLookup?: AuthFlowClientIdLookup
}

export type SecurityHeadersNext = () => void

export function extractClientIdFromRequest(
  req: SecurityHeadersRequest,
): string | null {
  const fromQuery = req.query.client_id
  if (typeof fromQuery === 'string') return fromQuery
  const fromBody = req.body?.client_id
  if (typeof fromBody === 'string') return fromBody
  return null
}

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
