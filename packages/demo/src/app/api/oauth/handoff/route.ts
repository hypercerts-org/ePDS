/**
 * Atmosphere hand-off — the demo's `epds_handle_login_url`.
 *
 * The ePDS login page sends the browser here with ?handle=, ?iss= and
 * ?state= when the user picks "Sign in with Atmosphere". We continue only if
 * the hand-off belongs to a sign-in this browser started (see
 * lib/handoff.ts for the checks).
 *
 * Flow:
 * 1. Verify state against the signed oauth_state cookie, and iss against
 *    this PDS's issuer
 * 2. Refused: redirect to /?error=handoff_refused. The cookie is left alone,
 *    so a forged link cannot cancel the user's real pending sign-in.
 * 3. Accepted: clear the oauth_state cookie and hand over to
 *    /api/oauth/login?handle=..., which resolves the handle and starts a
 *    fresh OAuth flow against that handle's PDS, setting a new cookie.
 *
 * Clearing the cookie stops sequential replay only. The demo has no
 * server-side store, so concurrent requests with the same valid cookie can
 * both pass before the browser applies the deletion; each just starts a new
 * OAuth flow.
 *
 * Always answers with a redirect and never logs the query, so `state` stays
 * out of rendered pages and logs. A malformed handle is not a security
 * refusal: it gets the usual invalid_handle error and the sign-in is kept.
 */

import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { getBaseUrl, PDS_URL } from '@/lib/auth'
import { verifyHandoff } from '@/lib/handoff'
import { getOAuthSessionFromCookie, OAUTH_COOKIE } from '@/lib/session'

export const runtime = 'nodejs'

export function GET(request: NextRequest) {
  const baseUrl = getBaseUrl()

  const result = verifyHandoff({
    params: request.nextUrl.searchParams,
    session: getOAuthSessionFromCookie(request.cookies),
    expectedIssuer: PDS_URL,
  })

  if (!result.ok) {
    console.warn('[oauth/handoff] Refused hand-off:', result.reason)
    const error =
      result.reason === 'invalid_handle' ? 'invalid_handle' : 'handoff_refused'
    return NextResponse.redirect(new URL(`/?error=${error}`, baseUrl))
  }

  const next = new URL('/api/oauth/login', baseUrl)
  next.searchParams.set('handle', result.handle)
  const response = NextResponse.redirect(next)
  response.cookies.delete(OAUTH_COOKIE)
  return response
}
