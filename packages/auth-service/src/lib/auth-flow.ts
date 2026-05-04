/**
 * Constants shared between auth_flow producers (login-page, recovery)
 * and consumers (complete, choose-handle).
 */

/** Cookie that carries the auth_flow ID across redirects. */
export const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/**
 * How long an auth_flow row + browser cookie carry the OAuth `request_uri`
 * across page navigations and better-auth redirects until /auth/complete
 * can use them.
 *
 * NOT the OTP code's lifetime — better-auth enforces that separately
 * in the `verification` table (`expiresIn: 600` in better-auth.ts).
 *
 * 60 minutes lets a slow user who hits OTP expiry (10 min) and clicks
 * Resend still have a live auth_flow + cookie to land on /auth/complete
 * after the second OTP submit. Loosely bounded by the upstream PAR
 * `request_uri` lifetime; the ping-par-request heartbeat keeps the PAR
 * alive while the user sits on the form, and any later expiry on the
 * PDS side is reported by /auth/complete via the existing flow lookup.
 */
export const AUTH_FLOW_TTL_MS = 60 * 60 * 1000
