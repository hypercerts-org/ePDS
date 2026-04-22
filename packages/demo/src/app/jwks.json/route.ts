/**
 * Public JWKS endpoint for OAuth confidential-client authentication.
 *
 * Served at /jwks.json so the client-metadata.json's jwks_uri can be
 * a self-referencing URL relative to the same PUBLIC_URL. Reads the
 * private JWK from EPDS_CLIENT_PRIVATE_JWK (via lib/client-jwk), strips
 * the private component, and returns the public half wrapped in a
 * standard JWKS envelope.
 *
 * Returns 404 if EPDS_CLIENT_PRIVATE_JWK is not set, so that a public
 * client (fallback mode) doesn't accidentally advertise an empty JWKS
 * that the PDS would then cache and use to reject valid assertions.
 */

import { NextResponse } from 'next/server'
import { getClientPublicJwk } from '@/lib/client-jwk'

export const runtime = 'nodejs'

export async function GET() {
  const publicJwk = await getClientPublicJwk()
  if (!publicJwk) {
    return NextResponse.json({ error: 'not_found' }, { status: 404 })
  }

  return NextResponse.json(
    { keys: [publicJwk] },
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
        // Shorter cache than client-metadata.json because if we ever
        // need to rotate keys in anger, we want the window of stale
        // cached JWKS to be as small as the upstream pds-core's
        // clientJwksCache TTL (~10 min) rather than longer.
        'Cache-Control': 'public, max-age=60',
      },
    },
  )
}
