/**
 * Dynamic OAuth client metadata endpoint.
 *
 * Served at /client-metadata.json so the client_id URL is self-referencing.
 * Adapts to PUBLIC_URL so it works in any deployment environment.
 *
 * When EPDS_CLIENT_PRIVATE_JWK is set in the environment, this client
 * advertises itself as a confidential client using private_key_jwt
 * authentication, with a jwks_uri pointing at /jwks.json on the same
 * origin. That unblocks the upstream @atproto/oauth-provider's
 * "remember consent for previously-authorized clients" behaviour,
 * which is disabled for public (token_endpoint_auth_method=none)
 * clients as a hard-coded policy (see request-manager.ts in the
 * upstream package, which forces prompt=consent on every authorize
 * request from untrusted public clients).
 *
 * When EPDS_CLIENT_PRIVATE_JWK is NOT set, this client falls back to
 * the public client mode — convenient for local dev without having
 * to generate a keypair, and for any deployment that doesn't care
 * about the consent-persistence behaviour.
 */

import { NextResponse } from 'next/server'
import { getBaseUrl } from '@/lib/auth'
import { getClientPublicJwk } from '@/lib/client-jwk'

export const runtime = 'nodejs'

export async function GET() {
  const baseUrl = getBaseUrl()

  const publicJwk = await getClientPublicJwk()
  const isConfidential = publicJwk !== null

  const metadata = {
    client_id: `${baseUrl}/client-metadata.json`,
    client_name: process.env.EPDS_CLIENT_NAME ?? 'ePDS Demo',
    client_uri: baseUrl,
    logo_uri: `${baseUrl}/certified-logo.png`,
    redirect_uris: [`${baseUrl}/api/oauth/callback`],
    scope: 'atproto transition:generic',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    ...(isConfidential
      ? {
          token_endpoint_auth_method: 'private_key_jwt',
          token_endpoint_auth_signing_alg: 'ES256',
          jwks_uri: `${baseUrl}/jwks.json`,
        }
      : {
          token_endpoint_auth_method: 'none',
        }),
    dpop_bound_access_tokens: true,
    brand_color: '#2563eb',
    background_color: '#f8f9fa',
    ...(process.env.EPDS_SKIP_CONSENT_ON_SIGNUP === 'true' && {
      epds_skip_consent_on_signup: true,
    }),
    branding: {
      css: [
        ':root { --demo-accent: #2563eb; --demo-accent-hover: #1d4ed8; }',
        '.btn-primary { background: linear-gradient(135deg, #2563eb, #7c3aed); }',
        '.btn-primary:hover { opacity: 0.95; }',
      ].join(' '),
    },
  }

  return NextResponse.json(metadata, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=300',
    },
  })
}
