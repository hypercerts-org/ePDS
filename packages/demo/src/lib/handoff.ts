/**
 * Checks for the "Sign in with Atmosphere" hand-off from the ePDS login page.
 *
 * ePDS sends the browser to our `epds_handle_login_url` with `handle`, `iss`
 * (the PDS issuer) and `state` (the `state` from our own PAR request). A link
 * like that can be forged and sent to someone else, so we only continue if it
 * belongs to a sign-in *this browser* started. See docs/tutorial.md, "Optional:
 * offer Atmosphere handle sign-in", and the epds-login skill, "Atmosphere
 * Hand-Off".
 *
 * The demo does not use an OAuth SDK, so there is no server-side state store
 * to look the state up in. The PAR `state` lives in the signed, httpOnly
 * `oauth_state` cookie we set when the sign-in started, and that cookie is the
 * browser binding: an attacker cannot obtain a victim's cookie, so a `state`
 * from a sign-in started elsewhere never matches it. Sequential replay is blocked by the
 * route deleting that cookie in the response that accepts the hand-off.
 *
 * Does not look at the Referer header: the login page sends
 * `Referrer-Policy: no-referrer`.
 */

import * as crypto from 'node:crypto'
import type { OAuthSession } from './session'
import { validateHandle } from './validation'

/** Why a hand-off was refused. Logged server-side; never sent to the user. */
export type HandoffRefusal =
  | 'missing_params'
  | 'no_sign_in_in_this_browser'
  | 'state_mismatch'
  | 'wrong_issuer'
  | 'sign_in_started_elsewhere'
  | 'invalid_handle'

export type HandoffResult =
  | { ok: true; handle: string }
  | { ok: false; reason: HandoffRefusal }

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb)
}

/**
 * Decide whether to continue a sign-in from a hand-off.
 *
 * @param params - Query params of the hand-off request (`handle`, `iss`, `state`).
 * @param session - The sign-in this browser started (the `oauth_state` cookie),
 *   or null when it is absent, expired or fails its signature.
 * @param expectedIssuer - This PDS's issuer, exactly as in its
 *   `/.well-known/oauth-authorization-server` (no trailing slash).
 *
 * The handle's shape is checked last, so a bad request cannot tell a caller
 * anything about the sign-in before the browser binding has passed.
 */
export function verifyHandoff(opts: {
  params: URLSearchParams
  session: OAuthSession | null
  expectedIssuer: string
}): HandoffResult {
  const { params, session, expectedIssuer } = opts
  const state = params.get('state')
  const iss = params.get('iss')
  const rawHandle = params.get('handle')

  // The login page leaves `state` out when it cannot give it to us (PAR
  // expired, or pushed by another client). Without it we cannot tell whose
  // sign-in this is, so refuse.
  if (!state || !iss || !rawHandle) {
    return { ok: false, reason: 'missing_params' }
  }
  if (!session) {
    return { ok: false, reason: 'no_sign_in_in_this_browser' }
  }
  if (!safeEqual(session.state, state)) {
    return { ok: false, reason: 'state_mismatch' }
  }
  if (!safeEqual(iss, expectedIssuer)) {
    return { ok: false, reason: 'wrong_issuer' }
  }
  // The cookie also holds sign-ins started against other servers (the
  // demo's own handle form); only one started against this PDS can have
  // produced this hand-off.
  if (!safeEqual(session.issuer, expectedIssuer)) {
    return { ok: false, reason: 'sign_in_started_elsewhere' }
  }

  const handle = rawHandle.trim().replace(/^@/, '')
  if (!validateHandle(handle)) {
    return { ok: false, reason: 'invalid_handle' }
  }
  return { ok: true, handle }
}
