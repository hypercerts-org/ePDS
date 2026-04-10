/**
 * Cookie-domain rewriting helpers for HYPER-268 cross-client session reuse.
 *
 * Upstream @atproto/oauth-provider sets its dev-id/ses-id device-session
 * cookies without a Domain attribute, scoping them host-only to the
 * pds-core host. The ePDS auth-service runs on a sibling subdomain
 * (e.g. auth.pds.foo.com) and therefore can't read those cookies — so
 * it has no way to detect an existing device session when a second OAuth
 * client starts a new /oauth/authorize flow.
 *
 * These helpers rewrite outbound Set-Cookie headers in a middleware to
 * inject Domain=<parent>, making the cookie visible to all sibling
 * subdomains of that parent. They are pure and safe to unit-test.
 */

/**
 * Derive the cookie domain for cross-subdomain session reuse from the
 * PDS and auth-service hostnames. Returns the shared parent domain if
 * one exists, or null if the hosts are unrelated (e.g. Railway preview
 * envs where services get random subdomains under a public suffix).
 *
 * The relationship we recognise is "auth-service is a direct or nested
 * subdomain of PDS". Concretely, if `authHostname` ends with
 * `.<pdsHostname>`, then `pdsHostname` is the shared parent and we use
 * it as the `Domain=` cookie attribute. Examples:
 *
 *   auth.pds.example + pds.example     → "pds.example"      (subdomain)
 *   api.auth.pds.example + pds.example → "pds.example"      (nested)
 *   auth.other.example + pds.example   → null               (unrelated)
 *   pds.example + pds.example          → null               (same host)
 *
 * Intentionally returns null for the "same host" case: if both services
 * share the exact same hostname, cookies are already readable by both
 * without any Domain attribute, so the middleware has nothing to do.
 */
export function deriveCookieDomain(
  authHostname: string,
  pdsHostname: string,
): string | null {
  if (!authHostname || !pdsHostname) return null
  if (authHostname === pdsHostname) return null
  if (authHostname.endsWith(`.${pdsHostname}`)) return pdsHostname
  return null
}

/** The upstream cookie names we rewrite. Four total: the two device
 *  cookies and their :hash sidecars. Anything else (CSRF tokens, ePDS
 *  auth flow cookies, etc.) passes through untouched. */
export const DEVICE_COOKIE_NAMES = new Set<string>([
  'dev-id',
  'ses-id',
  'dev-id:hash',
  'ses-id:hash',
])

/**
 * Inject `Domain=<domain>` into a Set-Cookie value that targets one of
 * our device cookies. Leaves unrelated cookies untouched.
 *
 * Behaviour:
 * - Returns the input unchanged if it doesn't target a device cookie.
 * - Returns the input unchanged if it already has a `Domain=` attribute
 *   (case-insensitive) — never double-scopes.
 * - Otherwise appends `; Domain=<domain>` to the end of the value.
 *
 * Set-Cookie values look like "name=value; Path=/; HttpOnly; Secure".
 * We rely on the name being the first token before `=`, which is the
 * standard RFC 6265 serialization and what upstream's cookie helper
 * always produces.
 */
export function rewriteSetCookie(value: string, domain: string): string {
  const eqIdx = value.indexOf('=')
  if (eqIdx < 0) return value
  const name = value.slice(0, eqIdx)
  if (!DEVICE_COOKIE_NAMES.has(name)) return value
  // Already has Domain attribute? Don't double-inject.
  if (/;\s*Domain=/i.test(value)) return value
  return `${value}; Domain=${domain}`
}

/**
 * Apply {@link rewriteSetCookie} to a Set-Cookie header value, which
 * Node's http module allows to be either a single string or an array
 * of strings (when multiple cookies are set in one response). Handles
 * both shapes. Non-string array entries (numbers, undefined) pass
 * through untouched — they shouldn't occur in practice, but being
 * defensive here avoids a runtime crash if some middleware misuses
 * the API.
 */
export function rewriteSetCookieHeader(
  value: string | string[] | number,
  domain: string,
): string | string[] | number {
  if (Array.isArray(value)) {
    return value.map((v) =>
      typeof v === 'string' ? rewriteSetCookie(v, domain) : v,
    )
  }
  if (typeof value === 'string') {
    return rewriteSetCookie(value, domain)
  }
  return value
}

/**
 * Minimal shape of `http.ServerResponse` we need to wrap. Keeping this
 * narrow lets unit tests construct a mock without depending on the
 * full Node http types or Express typings.
 */
export interface CookieRewriteResponse {
  setHeader: (name: string, value: string | string[] | number) => unknown
  appendHeader?: (name: string, value: string | string[]) => unknown
}

/** Minimal shape of an Express middleware `next()` callback. */
export type NextFn = () => void

/**
 * Build an Express middleware that rewrites outbound `Set-Cookie`
 * headers to inject `Domain=<domain>` on the upstream device-session
 * cookies. Wraps both `res.setHeader` and `res.appendHeader` because
 * upstream's cookie helper uses `appendHeader` directly via Node's
 * built-in API rather than going through `setHeader`.
 *
 * Pure factory: takes a domain, returns a middleware function that
 * mutates only the response object passed to it. Side-effect-free at
 * module load time, so it's safe to call from `main()` or unit tests
 * alike.
 */
export function createCookieDomainMiddleware(domain: string) {
  return function cookieDomainMiddleware(
    _req: unknown,
    res: CookieRewriteResponse,
    next: NextFn,
  ): void {
    const origSetHeader = res.setHeader.bind(res)
    res.setHeader = (name: string, value: string | string[] | number) => {
      if (typeof name === 'string' && name.toLowerCase() === 'set-cookie') {
        value = rewriteSetCookieHeader(value, domain)
      }
      return origSetHeader(name, value)
    }

    // Upstream uses res.appendHeader('Set-Cookie', …) via the
    // @atproto/oauth-provider setCookie() helper, which goes around
    // setHeader entirely — wrap it too or device cookies bypass our
    // rewrite. Some response shells (older Express, test mocks) don't
    // expose appendHeader, so guard the wrap.
    const maybeAppend = res.appendHeader
    if (typeof maybeAppend === 'function') {
      const origAppend = maybeAppend.bind(res) as (
        n: string,
        v: string | string[],
      ) => unknown
      res.appendHeader = (name: string, value: string | string[]) => {
        if (typeof name === 'string' && name.toLowerCase() === 'set-cookie') {
          const rewritten = rewriteSetCookieHeader(value, domain)
          // appendHeader's signature only allows string | string[];
          // rewriteSetCookieHeader doesn't widen non-number inputs to
          // number, so this narrowing cast is safe.
          return origAppend(name, rewritten as string | string[])
        }
        return origAppend(name, value)
      }
    }
    next()
  }
}
