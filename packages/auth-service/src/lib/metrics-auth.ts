/**
 * HTTP Basic authentication check for the /metrics endpoint.
 *
 * Deny-by-default: if `PDS_ADMIN_PASSWORD` is unset the endpoint is
 * unavailable rather than open — historically an unset password meant
 * "no auth required", which leaked process uptime, RSS, and DB
 * counters. Operators who want to scrape /metrics must set
 * `PDS_ADMIN_PASSWORD` and send HTTP Basic auth as `admin:<password>`.
 *
 * Kept as a pure helper so the wiring in the /metrics handler is a
 * thin wrapper and the branching logic is unit-testable without
 * spinning up Express.
 */
import { timingSafeEqual } from '@certified-app/shared'

/**
 * Result of the /metrics Basic-auth check. When `ok` is false the
 * caller should return a 401 with both `headers` set (for RFC 7235
 * `WWW-Authenticate`) and `body` as the JSON payload.
 */
export type MetricsAuthResult =
  | { ok: true }
  | {
      ok: false
      status: 401
      headers: { 'WWW-Authenticate': string }
      body: { error: string }
    }

const UNAUTHORIZED: Extract<MetricsAuthResult, { ok: false }> = {
  ok: false,
  status: 401,
  headers: { 'WWW-Authenticate': 'Basic realm="metrics"' },
  body: { error: 'Unauthorized' },
}

/**
 * Validate the `Authorization` header for a /metrics request against
 * the configured admin password.
 *
 *   - `adminPassword` unset/empty → always 401 (deny-by-default)
 *   - Header missing → 401
 *   - Header present but does not match `Basic <base64(admin:<pw>)>` →
 *     401 (comparison uses `timingSafeEqual` to avoid leaking the
 *     password byte-by-byte)
 *   - Header matches → `{ ok: true }`
 */
export function checkMetricsAuth(
  authHeader: string | undefined,
  adminPassword: string | undefined,
): MetricsAuthResult {
  if (!adminPassword) return UNAUTHORIZED
  if (!authHeader) return UNAUTHORIZED
  const expected =
    'Basic ' + Buffer.from('admin:' + adminPassword).toString('base64')
  if (!timingSafeEqual(authHeader, expected)) return UNAUTHORIZED
  return { ok: true }
}
