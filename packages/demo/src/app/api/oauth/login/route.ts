/**
 * OAuth login initiator — starts the AT Protocol OAuth flow.
 *
 * Accepts ?email=... or ?handle=... query params. If neither is provided,
 * the auth server collects credentials itself (Flow 2).
 *
 * Optional ?handle_mode=... (e.g. picker-with-random) is forwarded to the
 * auth server as epds_handle_mode, overriding the default handle assignment
 * mode for the session.
 *
 * Flow:
 * 1. Generate PKCE code verifier/challenge + DPoP key pair + state
 * 2. Send Pushed Authorization Request (PAR) to PDS
 * 3. Store OAuth session in signed cookie
 * 4. Redirect browser to auth endpoint
 */

import { NextResponse } from 'next/server'
import {
  getBaseUrl,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  generateDpopKeyPair,
  createDpopProof,
  PDS_URL,
  AUTH_ENDPOINT,
  resolveHandleToDid,
  resolveDidToPds,
  discoverOAuthEndpoints,
} from '@/lib/auth'
import { createOAuthSessionCookie } from '@/lib/session'
import { signClientAssertion } from '@/lib/client-jwk'
import { validateEmail, validateHandle, sanitizeForLog } from '@/lib/validation'
import { checkRateLimit } from '@/lib/ratelimit'

export const runtime = 'nodejs'

const RATE_LIMIT_LOGIN = Number(process.env.RATE_LIMIT_LOGIN) || 10
const RATE_LIMIT_WINDOW_MS = 60 * 1000

export async function GET(request: Request) {
  const baseUrl = getBaseUrl()

  try {
    // Rate limit by IP
    const ip =
      request.headers.get('x-real-ip') ||
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      'unknown'
    const rl = checkRateLimit(
      `login:${ip}`,
      RATE_LIMIT_LOGIN,
      RATE_LIMIT_WINDOW_MS,
    )
    if (!rl.allowed) {
      return new NextResponse('Too many requests', {
        status: 429,
        headers: { 'Retry-After': String(rl.retryAfter) },
      })
    }

    const url = new URL(request.url)
    const email = url.searchParams.get('email') || ''
    const handle = (url.searchParams.get('handle') || '')
      .replace(/^@/, '')
      .trim()
    const handleMode = url.searchParams.get('handle_mode') || ''
    const handleModeParam = handleMode
      ? `&epds_handle_mode=${encodeURIComponent(handleMode)}`
      : ''

    // Input validation
    // Note: email and handle are both optional — omitting both triggers Flow 2
    // (auth server collects the email itself via its own form).
    if (email && !validateEmail(email)) {
      return NextResponse.redirect(new URL('/?error=invalid_email', baseUrl))
    }
    if (handle && !validateHandle(handle)) {
      return NextResponse.redirect(new URL('/?error=invalid_handle', baseUrl))
    }

    // Determine endpoints: dynamic for handle, defaults for email.
    // The `issuer` is the authorization server identifier used as the
    // `aud` claim in client_assertion JWTs for confidential clients.
    // For atproto PDSs the PDS is its own authorization server, so the
    // issuer matches PDS_URL for the email path; for the handle path
    // we take whatever the PDS's AS metadata declares.
    let issuer = PDS_URL
    let parEndpoint = `${PDS_URL}/oauth/par`
    let authEndpoint = AUTH_ENDPOINT
    let tokenEndpoint = `${PDS_URL}/oauth/token`
    let expectedDid: string | undefined
    let expectedPdsUrl: string | undefined

    if (handle) {
      console.log('[oauth/login] Resolving handle:', sanitizeForLog(handle))
      const did = await resolveHandleToDid(handle)
      console.log('[oauth/login] Resolved DID:', sanitizeForLog(did))
      const pdsUrl = await resolveDidToPds(did)
      console.log('[oauth/login] Resolved PDS:', sanitizeForLog(pdsUrl))
      const endpoints = await discoverOAuthEndpoints(pdsUrl)
      console.log('[oauth/login] Discovered OAuth endpoints')
      issuer = endpoints.issuer
      parEndpoint = endpoints.parEndpoint
      authEndpoint = endpoints.authEndpoint
      tokenEndpoint = endpoints.tokenEndpoint
      expectedDid = did
      expectedPdsUrl = pdsUrl
    }

    const clientId = `${baseUrl}/client-metadata.json`
    const redirectUri = `${baseUrl}/api/oauth/callback`

    // Generate PKCE
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = generateCodeChallenge(codeVerifier)
    const state = generateState()

    // Generate DPoP proof for PAR
    const { privateKey, publicJwk, privateJwk } = generateDpopKeyPair()
    const dpopProof = createDpopProof({
      privateKey,
      jwk: publicJwk,
      method: 'POST',
      url: parEndpoint,
    })

    // Push Authorization Request (PAR)
    const parBody = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'atproto transition:generic',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })

    // If this demo is configured as a confidential OAuth client
    // (EPDS_CLIENT_PRIVATE_JWK set), sign a client_assertion and add
    // it to the PAR body. The PDS's PAR endpoint enforces the same
    // client authentication method as the token endpoint, so missing
    // the assertion here produces "client authentication method
    // private_key_jwt required a client_assertion". See HYPER-270.
    //
    // The `aud` claim MUST be the authorization server's issuer
    // identifier (not the specific endpoint URL) — upstream atproto
    // explicitly checks `audience: this.issuer` when verifying the
    // client_assertion (see @atproto/oauth-provider's client.ts).
    const parClientAssertion = await signClientAssertion({
      clientId,
      audience: issuer,
    })
    if (parClientAssertion) {
      parBody.set(
        'client_assertion_type',
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      )
      parBody.set('client_assertion', parClientAssertion)
    }

    console.log('[oauth/login] Sending PAR request')

    const parRes = await fetch(parEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        DPoP: dpopProof,
      },
      body: parBody.toString(),
    })

    // Session data to store in signed cookie
    const sessionData = {
      state,
      codeVerifier,
      dpopPrivateJwk: privateJwk,
      tokenEndpoint,
      issuer,
      email: email || undefined,
      expectedDid,
      expectedPdsUrl,
    }
    const oauthCookie = createOAuthSessionCookie(sessionData)

    if (!parRes.ok) {
      const parErrBody = await parRes.text()
      console.error('[oauth/login] PAR failed:', parRes.status, parErrBody)

      // Check for DPoP nonce requirement
      const dpopNonce = parRes.headers.get('dpop-nonce')
      if (dpopNonce) {
        console.log('[oauth/login] Retrying with DPoP nonce')
        const dpopProof2 = createDpopProof({
          privateKey,
          jwk: publicJwk,
          method: 'POST',
          url: parEndpoint,
          nonce: dpopNonce,
        })

        // Regenerate the client_assertion for the retry so its jti is
        // fresh and the PDS's replay store doesn't reject it as a
        // duplicate of the first attempt's assertion.
        const parClientAssertionRetry = await signClientAssertion({
          clientId,
          audience: issuer,
        })
        if (parClientAssertionRetry) {
          parBody.set('client_assertion', parClientAssertionRetry)
        }

        const parRes2 = await fetch(parEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            DPoP: dpopProof2,
          },
          body: parBody.toString(),
        })

        if (!parRes2.ok) {
          const retryErrBody = await parRes2.text()
          console.error(
            '[oauth/login] PAR retry failed:',
            parRes2.status,
            retryErrBody,
          )
          return NextResponse.redirect(new URL('/?error=par_failed', baseUrl))
        }

        const parData2 = (await parRes2.json()) as { request_uri: string }
        const loginHint = email
          ? `&login_hint=${encodeURIComponent(email)}`
          : ''
        const authUrl = `${authEndpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(parData2.request_uri)}${loginHint}${handleModeParam}`
        console.log('[oauth/login] Redirecting to auth (after nonce retry)')
        const resp2 = NextResponse.redirect(authUrl)
        resp2.cookies.set(oauthCookie.name, oauthCookie.value, {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          maxAge: 600,
          path: '/',
        })
        return resp2
      }

      return NextResponse.redirect(new URL('/?error=par_failed', baseUrl))
    }

    const parData = (await parRes.json()) as { request_uri: string }
    const loginHintParam = email
      ? `&login_hint=${encodeURIComponent(email)}`
      : ''
    const authUrl = `${authEndpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(parData.request_uri)}${loginHintParam}${handleModeParam}`

    console.log('[oauth/login] Redirecting to auth')
    const response = NextResponse.redirect(authUrl)
    response.cookies.set(oauthCookie.name, oauthCookie.value, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 600,
      path: '/',
    })
    return response
  } catch (err) {
    console.error(
      '[oauth/login] Error:',
      err instanceof Error ? err.message : 'Unknown error',
    )
    return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
  }
}
