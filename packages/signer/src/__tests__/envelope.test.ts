import { describe, expect, it } from 'vitest'
import { p256 } from '@noble/curves/nist.js'
import { verifyEnvelope, type WalletOp } from '../envelope.js'

const userPriv = p256.utils.randomSecretKey()
const userPubHex = Buffer.from(p256.getPublicKey(userPriv, true)).toString(
  'hex',
)
const otherPriv = p256.utils.randomSecretKey()

// Shape-valid compact JWE (ECDH-ES: empty encrypted-key segment).
const fakeJwe = `${'A'.repeat(24)}..${'B'.repeat(16)}.${'C'.repeat(32)}.${'D'.repeat(22)}`

function makeEnvelope(
  payload: Record<string, unknown>,
  signWith: Uint8Array = userPriv,
): { payloadB64: string; sigB64: string } {
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = p256
    .sign(payloadBytes, signWith, { prehash: true, lowS: false })
    .toBytes('compact')
  return {
    payloadB64: payloadBytes.toString('base64url'),
    sigB64: Buffer.from(sig).toString('base64url'),
  }
}

function verify(
  env: { payloadB64: string; sigB64: string },
  extra: Partial<{
    requestPubkeyHex: string
    expectedOp: WalletOp
    freshnessSec: number
  }> = {},
) {
  return verifyEnvelope({
    payloadB64: env.payloadB64,
    sigB64: env.sigB64,
    requestPubkeyHex: userPubHex,
    expectedOp: 'sign',
    ...extra,
  })
}

const now = Math.floor(Date.now() / 1000)
const basePayload = {
  did: 'did:plc:walletuser',
  purpose: 'wallet/evm' as const,
  digestHex: 'ab'.repeat(32),
  deviceShareJwe: fakeJwe,
  nonce: 1,
  iat: now,
}

describe('verifyEnvelope', () => {
  it('accepts a well-formed user-signed sign envelope', () => {
    const result = verify(makeEnvelope(basePayload))
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.payload.did).toBe('did:plc:walletuser')
      expect(result.payload.op).toBe('sign')
      expect(result.payload.purpose).toBe('wallet/evm')
      expect(result.payload.deviceShareJwe).toBe(fakeJwe)
    }
  })

  it('accepts an explicit op: sign', () => {
    const result = verify(makeEnvelope({ ...basePayload, op: 'sign' }))
    expect(result.ok).toBe(true)
  })

  it('accepts a solana envelope with messageBase64', () => {
    const result = verify(
      makeEnvelope({
        ...basePayload,
        purpose: 'wallet/sol',
        digestHex: undefined,
        messageBase64: Buffer.from('sol msg').toString('base64url'),
      }),
    )
    expect(result.ok).toBe(true)
  })

  it('accepts an export envelope without purpose or digest', () => {
    const result = verify(
      makeEnvelope({
        did: basePayload.did,
        op: 'export',
        deviceShareJwe: fakeJwe,
        nonce: 2,
        iat: now,
      }),
      { expectedOp: 'export' },
    )
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.payload.op).toBe('export')
  })

  it('rejects an op mismatch in both directions', () => {
    const exportEnv = makeEnvelope({
      did: basePayload.did,
      op: 'export',
      deviceShareJwe: fakeJwe,
      nonce: 2,
      iat: now,
    })
    expect(verify(exportEnv, { expectedOp: 'sign' })).toEqual({
      ok: false,
      error: "envelope op is not 'sign'",
    })
    expect(verify(makeEnvelope(basePayload), { expectedOp: 'export' })).toEqual(
      {
        ok: false,
        error: "envelope op is not 'export'",
      },
    )
  })

  it('rejects a signature from a different key', () => {
    const result = verify(makeEnvelope(basePayload, otherPriv))
    expect(result).toEqual({ ok: false, error: 'invalid signature' })
  })

  it('rejects a tampered payload', () => {
    const env = makeEnvelope(basePayload)
    const tampered = Buffer.from(
      JSON.stringify({ ...basePayload, digestHex: 'cd'.repeat(32) }),
    ).toString('base64url')
    const result = verify({ payloadB64: tampered, sigB64: env.sigB64 })
    expect(result).toEqual({ ok: false, error: 'invalid signature' })
  })

  it('rejects stale envelopes (iat outside the window)', () => {
    const result = verify(makeEnvelope({ ...basePayload, iat: now - 3600 }))
    expect(result).toEqual({ ok: false, error: 'stale envelope' })
  })

  it('respects a custom freshness window', () => {
    const result = verify(makeEnvelope({ ...basePayload, iat: now - 3600 }), {
      freshnessSec: 7200,
    })
    expect(result.ok).toBe(true)
  })

  it.each([
    ['bad purpose', { ...basePayload, purpose: 'atproto/signing' }],
    ['repo purpose smuggled', { ...basePayload, purpose: 'wallet/evil' }],
    ['bad op', { ...basePayload, op: 'exfiltrate' }],
    ['bad did', { ...basePayload, did: 'not-a-did' }],
    ['zero nonce', { ...basePayload, nonce: 0 }],
    ['float nonce', { ...basePayload, nonce: 1.5 }],
    ['missing digest', { ...basePayload, digestHex: undefined }],
    ['short digest', { ...basePayload, digestHex: 'ab'.repeat(16) }],
    ['missing device share', { ...basePayload, deviceShareJwe: undefined }],
    ['non-JWE device share', { ...basePayload, deviceShareJwe: 'AAAA' }],
    [
      'oversized device share',
      { ...basePayload, deviceShareJwe: `${'A'.repeat(9000)}..B.C.D` },
    ],
  ])('rejects malformed payload: %s', (_name, payload) => {
    const result = verify(makeEnvelope(payload))
    expect(result).toEqual({ ok: false, error: 'malformed payload' })
  })

  it('rejects malformed encodings', () => {
    expect(verify({ payloadB64: '!!!not-base64url!!!', sigB64: 'AA' })).toEqual(
      { ok: false, error: 'malformed payload encoding' },
    )
    const env = makeEnvelope(basePayload)
    expect(verify({ payloadB64: env.payloadB64, sigB64: 'AAAA' })).toEqual({
      ok: false,
      error: 'malformed signature encoding',
    })
  })

  it('rejects non-JSON payload bytes', () => {
    const payloadBytes = Buffer.from('this is not json', 'utf8')
    const sig = p256
      .sign(payloadBytes, userPriv, { prehash: true, lowS: false })
      .toBytes('compact')
    const result = verify({
      payloadB64: payloadBytes.toString('base64url'),
      sigB64: Buffer.from(sig).toString('base64url'),
    })
    expect(result).toEqual({ ok: false, error: 'malformed payload' })
  })
})
