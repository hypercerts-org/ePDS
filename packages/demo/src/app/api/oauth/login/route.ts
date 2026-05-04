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

export const runtime = 'nodejs'

export async function GET(request: Request) {
  const baseUrl = getBaseUrl()

  try {
    const url = new URL(request.url)
    const email = url.searchParams.get('email') || ''
    const handle = (url.searchParams.get('handle') || '')
      .replace(/^@/, '')
      .trim()
    const handleMode = url.searchParams.get('handle_mode') || ''
    const handleModeParam = handleMode
      ? `&epds_handle_mode=${encodeURIComponent(handleMode)}`
      : ''
    // Raw login_hint override: accept any identifier (email, handle, DID) and
    // forward it verbatim. When set, takes precedence over the derived
    // login_hint from `email`. Used by login-hint-resolution e2e scenarios
    // that need to exercise handle/DID hints and PAR-body placement, which
    // the primary ?email= path doesn't produce.
    const rawLoginHint = url.searchParams.get('login_hint') || ''
    const loginHintLocationRaw =
      url.searchParams.get('login_hint_location') || 'query'
    const loginHintLocation: 'query' | 'body' =
      loginHintLocationRaw === 'body' ? 'body' : 'query'
    // OIDC prompt=login: when set, asks the authorization server to force a
    // fresh credential prompt regardless of existing session cookies. Sent
    // in the PAR body so the demo exercises the same path most production
    // atproto OAuth clients use (per the cross-client-session-reuse changeset).
    const forceLogin = url.searchParams.get('prompt') === 'login'

    // Input validation
    // Note: email and handle are both optional — omitting both triggers Flow 2
    // (auth server collects the email itself via its own form).
    if (email && !validateEmail(email)) {
      return NextResponse.redirect(new URL('/?error=invalid_email', baseUrl))
    }
    if (handle && !validateHandle(handle)) {
      return NextResponse.redirect(new URL('/?error=invalid_handle', baseUrl))
    }
    // Lax validation for the raw login_hint override — accepts email,
    // handle, or DID shapes. Reject only obvious garbage so attackers can't
    // push arbitrary strings through our PAR body / authorize URL.
    if (rawLoginHint && !/^[\w.@:+-]{1,256}$/.test(rawLoginHint)) {
      return NextResponse.redirect(
        new URL('/?error=invalid_login_hint', baseUrl),
      )
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

    // Effective login_hint: explicit ?login_hint= wins over the derived
    // email-based hint so callers can inject handle/DID identifiers.
    const effectiveLoginHint = rawLoginHint || email
    // When login_hint_location=body, the hint goes in the PAR body only and
    // is omitted from the authorize redirect URL — this mirrors the
    // third-party app pattern that the auth service's fetchParLoginHint
    // path exists to handle.
    const loginHintQueryParam =
      effectiveLoginHint && loginHintLocation === 'query'
        ? `&login_hint=${encodeURIComponent(effectiveLoginHint)}`
        : ''
    // prompt=login also goes on the authorize redirect URL so auth-service's
    // shouldReuseSession (which reads only the query string at the AS metadata
    // redirect, never the PAR body) sees it and short-circuits cookie-driven
    // session reuse. PAR body alone isn't enough for the ePDS short-circuit.
    const promptQueryParam = forceLogin ? '&prompt=login' : ''

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
    if (effectiveLoginHint && loginHintLocation === 'body') {
      parBody.set('login_hint', effectiveLoginHint)
    }
    if (forceLogin) {
      parBody.set('prompt', 'login')
    }

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
        const authUrl = `${authEndpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(parData2.request_uri)}${loginHintQueryParam}${handleModeParam}${promptQueryParam}`
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
    const authUrl = `${authEndpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(parData.request_uri)}${loginHintQueryParam}${handleModeParam}${promptQueryParam}`

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
