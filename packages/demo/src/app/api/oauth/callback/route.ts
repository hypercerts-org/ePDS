/**
 * OAuth callback handler — exchanges authorization code for tokens.
 *
 * Flow:
 * 1. Verify state matches signed cookie
 * 2. Exchange code for tokens using DPoP
 * 3. Validate DID from token response
 * 4. Resolve handle from PLC directory
 * 5. Create signed user session cookie
 * 6. Redirect to /welcome
 */

import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import {
  getBaseUrl,
  restoreDpopKeyPair,
  createDpopProof,
  resolveDidToPds,
  PDS_URL,
  PLC_DIRECTORY_URL,
} from '@/lib/auth'
import { signClientAssertion } from '@/lib/client-jwk'
import { cookies } from 'next/headers'
import {
  getOAuthSessionFromCookie,
  createUserSessionCookie,
  OAUTH_COOKIE,
} from '@/lib/session'
import { sanitizeForLog } from '@/lib/validation'

export const runtime = 'nodejs'

export async function GET(request: NextRequest) {
  const baseUrl = getBaseUrl()

  try {
    const code = request.nextUrl.searchParams.get('code')
    const state = request.nextUrl.searchParams.get('state')
    const error = request.nextUrl.searchParams.get('error')

    if (error) {
      console.error('[oauth/callback] Auth error from PDS')
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    if (!code || !state) {
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    // Retrieve OAuth session from signed cookie
    const cookieStore = await cookies()
    const stateData = getOAuthSessionFromCookie(cookieStore)
    if (!stateData) {
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    if (stateData.state !== state) {
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    const codeVerifier = stateData.codeVerifier
    const tokenUrl = stateData.tokenEndpoint || `${PDS_URL}/oauth/token`
    // Authorization server issuer identifier from the login-time
    // discovery, used as the `aud` claim on client_assertion JWTs.
    const issuer = stateData.issuer

    const clientId = `${baseUrl}/client-metadata.json`
    const redirectUri = `${baseUrl}/api/oauth/callback`

    // Exchange code for tokens with DPoP
    const { privateKey, publicJwk } = restoreDpopKeyPair(
      stateData.dpopPrivateJwk,
    )

    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    })

    // If this demo is configured as a confidential OAuth client
    // (EPDS_CLIENT_PRIVATE_JWK set), sign a client_assertion and add
    // it to the token exchange request. This is required to convince
    // @atproto/oauth-provider to honour previously-recorded consent
    // grants on return logins — otherwise the upstream force-consent
    // rule for public clients kicks in. See HYPER-270 for the full
    // diagnosis.
    //
    // The `aud` claim MUST be the authorization server's issuer
    // identifier (not the token endpoint URL) — upstream atproto
    // explicitly checks `audience: this.issuer` when verifying the
    // client_assertion (see @atproto/oauth-provider's client.ts).
    const clientAssertion = await signClientAssertion({
      clientId,
      audience: issuer,
    })
    if (clientAssertion) {
      tokenBody.set(
        'client_assertion_type',
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      )
      tokenBody.set('client_assertion', clientAssertion)
    }

    // First attempt
    let dpopProof = createDpopProof({
      privateKey,
      jwk: publicJwk,
      method: 'POST',
      url: tokenUrl,
    })

    let tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        DPoP: dpopProof,
      },
      body: tokenBody.toString(),
    })

    // Handle DPoP nonce requirement
    if (!tokenRes.ok) {
      const dpopNonce = tokenRes.headers.get('dpop-nonce')
      if (dpopNonce) {
        dpopProof = createDpopProof({
          privateKey,
          jwk: publicJwk,
          method: 'POST',
          url: tokenUrl,
          nonce: dpopNonce,
        })

        // Regenerate the client_assertion for the retry so its jti is
        // fresh (see the matching comment in the PAR retry path in
        // api/oauth/login/route.ts).
        const clientAssertionRetry = await signClientAssertion({
          clientId,
          audience: issuer,
        })
        if (clientAssertionRetry) {
          tokenBody.set('client_assertion', clientAssertionRetry)
        }

        tokenRes = await fetch(tokenUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            DPoP: dpopProof,
          },
          body: tokenBody.toString(),
        })
      }
    }

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text().catch(() => '')
      console.error(
        `[oauth/callback] FAILED status=${tokenRes.status} url=${tokenUrl} body=${errBody}`,
      )
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    const tokenData = (await tokenRes.json()) as {
      access_token: string
      token_type: string
      sub: string
      scope?: string
    }

    // Validate sub matches expected DID (blocks malicious PDS impersonation)
    if (stateData.expectedDid && tokenData.sub !== stateData.expectedDid) {
      console.error(
        `[oauth/callback] FAIL=did_mismatch sub=${tokenData.sub} expected=${stateData.expectedDid}`,
      )
      return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
    }

    // For email login: verify the returned DID's PDS matches our token endpoint
    if (!stateData.expectedDid && tokenData.sub) {
      try {
        const didPdsUrl = await resolveDidToPds(tokenData.sub)
        const didPdsOrigin = new URL(didPdsUrl).origin
        const tokenOrigin = new URL(tokenUrl).origin
        if (didPdsOrigin !== tokenOrigin) {
          console.error(
            `[oauth/callback] FAIL=email_pds_mismatch did_pds=${didPdsOrigin} token=${tokenOrigin}`,
          )
          return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
        }
      } catch (err) {
        console.error(
          `[oauth/callback] FAIL=email_pds_resolve error=${err instanceof Error ? err.message : err}`,
        )
        return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
      }
    }

    console.log(`[oauth/callback] OK sub=${sanitizeForLog(tokenData.sub)}`)

    // Resolve handle from DID via PLC directory (no auth needed)
    let handle = tokenData.sub
    try {
      const plcRes = await fetch(`${PLC_DIRECTORY_URL}/${tokenData.sub}`)
      if (plcRes.ok) {
        const plcData = (await plcRes.json()) as { alsoKnownAs?: string[] }
        const atUri = plcData.alsoKnownAs?.find((u: string) =>
          u.startsWith('at://'),
        )
        if (atUri) {
          handle = atUri.replace('at://', '')
        }
      }
    } catch {
      console.warn('[oauth/callback] Could not resolve handle from PLC')
    }

    // Create signed user session cookie
    const userCookie = createUserSessionCookie({
      userDid: tokenData.sub,
      userHandle: handle,
      createdAt: Date.now(),
    })

    // Delete OAuth cookie, set user session cookie
    cookieStore.delete(OAUTH_COOKIE)
    cookieStore.set(userCookie.name, userCookie.value, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 60 * 60 * 24,
      path: '/',
    })

    return NextResponse.redirect(new URL('/welcome', baseUrl))
  } catch (err) {
    console.error(
      '[oauth/callback] Error:',
      err instanceof Error ? err.message : 'Unknown error',
    )
    return NextResponse.redirect(new URL('/?error=auth_failed', baseUrl))
  }
}
