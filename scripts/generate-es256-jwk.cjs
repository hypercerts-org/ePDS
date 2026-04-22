#!/usr/bin/env node

// Generate an ES256 (P-256) private JWK with a deterministic kid.
// Output: compact JSON on stdout, suitable for EPDS_CLIENT_PRIVATE_JWK.
//
// The kid is an RFC 7638 JWK thumbprint (SHA-256, base64url) of the
// public key. The runtime client-jwk.ts uses the same thumbprint as a
// fallback when no explicit kid is present, so keys generated here will
// produce the same kid whether or not it's stripped and re-derived.

const crypto = require('node:crypto')
const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
const jwk = privateKey.export({ format: 'jwk' })

// RFC 7638: canonical JSON with required public members in lexicographic order
const thumbprintInput = JSON.stringify({
  crv: jwk.crv,
  kty: jwk.kty,
  x: jwk.x,
  y: jwk.y,
})
jwk.kid = crypto
  .createHash('sha256')
  .update(thumbprintInput)
  .digest('base64url')

process.stdout.write(JSON.stringify(jwk) + '\n')
