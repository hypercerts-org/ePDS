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
import { getTheme } from '@/lib/theme'

export const runtime = 'nodejs'

export async function GET() {
  const baseUrl = getBaseUrl()
  const theme = getTheme()

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
    brand_color: theme?.page.primary ?? '#2563eb',
    background_color: theme?.page.bg ?? '#f8f9fa',
    // Custom OTP email template, served from this same origin. Only
    // honoured by auth-service when this client_id is on
    // PDS_OAUTH_TRUSTED_CLIENTS (see `buildClientBrandedEmail` in
    // packages/auth-service/src/email/client-template.ts); untrusted
    // clients get the default PDS template regardless.
    email_template_uri: `${baseUrl}/email-template.html`,
    email_subject_template: '{{code}} — your {{app_name}} code',
    // Opt in to the auth-service login page's "Or sign in with
    // ATProto/Bluesky" button. Submitting a handle redirects here with
    // ?handle=<value>, which our /api/oauth/login route already handles
    // (resolves handle → PDS → fresh PAR against that PDS).
    epds_handle_login_url: `${baseUrl}/api/oauth/login`,
    ...(process.env.EPDS_SKIP_CONSENT_ON_SIGNUP === 'true' && {
      epds_skip_consent_on_signup: true,
    }),
    ...(theme && {
      branding: {
        css: theme.injectedCss,
        // Same-origin favicons: served from this demo's PUBLIC_URL so they
        // share an origin with `client_id` (auth-service rejects
        // cross-origin favicons because the CSP img-src only widens to
        // the client_id origin). Light + dark variants let auth-service
        // emit two `<link rel="icon" media="(prefers-color-scheme: ...)">`
        // tags so browsers pick the one that matches the user's OS theme.
        favicon_url: `${baseUrl}/favicon-demo.svg`,
        favicon_url_dark: `${baseUrl}/favicon-demo-dark.svg`,
      },
    }),
  }

  return NextResponse.json(metadata, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=300',
    },
  })
}
