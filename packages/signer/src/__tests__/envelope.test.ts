import { describe, expect, it } from 'vitest'
import { p256 } from '@noble/curves/nist.js'
import { verifyEnvelope } from '../envelope.js'

const userPriv = p256.utils.randomSecretKey()
const userPubHex = Buffer.from(p256.getPublicKey(userPriv, true)).toString(
  'hex',
)
const otherPriv = p256.utils.randomSecretKey()

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

const now = Math.floor(Date.now() / 1000)
const basePayload = {
  did: 'did:plc:walletuser',
  purpose: 'wallet/evm' as const,
  digestHex: 'ab'.repeat(32),
  nonce: 1,
  iat: now,
}

describe('verifyEnvelope', () => {
  it('accepts a well-formed user-signed envelope', () => {
    const env = makeEnvelope(basePayload)
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.payload.did).toBe('did:plc:walletuser')
      expect(result.payload.purpose).toBe('wallet/evm')
    }
  })

  it('accepts a solana envelope with messageBase64', () => {
    const env = makeEnvelope({
      ...basePayload,
      purpose: 'wallet/sol',
      digestHex: undefined,
      messageBase64: Buffer.from('sol msg').toString('base64url'),
    })
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result.ok).toBe(true)
  })

  it('rejects a signature from a different key', () => {
    const env = makeEnvelope(basePayload, otherPriv)
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result).toEqual({ ok: false, error: 'invalid signature' })
  })

  it('rejects a tampered payload', () => {
    const env = makeEnvelope(basePayload)
    const tampered = Buffer.from(
      JSON.stringify({ ...basePayload, digestHex: 'cd'.repeat(32) }),
    ).toString('base64url')
    const result = verifyEnvelope({
      payloadB64: tampered,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result).toEqual({ ok: false, error: 'invalid signature' })
  })

  it('rejects stale envelopes (iat outside the window)', () => {
    const env = makeEnvelope({ ...basePayload, iat: now - 3600 })
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result).toEqual({ ok: false, error: 'stale envelope' })
  })

  it('respects a custom freshness window', () => {
    const env = makeEnvelope({ ...basePayload, iat: now - 3600 })
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
      freshnessSec: 7200,
    })
    expect(result.ok).toBe(true)
  })

  it.each([
    ['bad purpose', { ...basePayload, purpose: 'atproto/signing' }],
    ['repo purpose smuggled', { ...basePayload, purpose: 'wallet/evil' }],
    ['bad did', { ...basePayload, did: 'not-a-did' }],
    ['zero nonce', { ...basePayload, nonce: 0 }],
    ['float nonce', { ...basePayload, nonce: 1.5 }],
    ['missing digest', { ...basePayload, digestHex: undefined }],
    ['short digest', { ...basePayload, digestHex: 'ab'.repeat(16) }],
  ])('rejects malformed payload: %s', (_name, payload) => {
    const env = makeEnvelope(payload)
    const result = verifyEnvelope({
      payloadB64: env.payloadB64,
      sigB64: env.sigB64,
      requestPubkeyHex: userPubHex,
    })
    expect(result).toEqual({ ok: false, error: 'malformed payload' })
  })

  it('rejects malformed encodings', () => {
    expect(
      verifyEnvelope({
        payloadB64: '!!!not-base64url!!!',
        sigB64: 'AA',
        requestPubkeyHex: userPubHex,
      }),
    ).toEqual({ ok: false, error: 'malformed payload encoding' })
    const env = makeEnvelope(basePayload)
    expect(
      verifyEnvelope({
        payloadB64: env.payloadB64,
        sigB64: 'AAAA',
        requestPubkeyHex: userPubHex,
      }),
    ).toEqual({ ok: false, error: 'malformed signature encoding' })
  })

  it('rejects non-JSON payload bytes', () => {
    const payloadBytes = Buffer.from('this is not json', 'utf8')
    const sig = p256
      .sign(payloadBytes, userPriv, { prehash: true, lowS: false })
      .toBytes('compact')
    const result = verifyEnvelope({
      payloadB64: payloadBytes.toString('base64url'),
      sigB64: Buffer.from(sig).toString('base64url'),
      requestPubkeyHex: userPubHex,
    })
    expect(result).toEqual({ ok: false, error: 'malformed payload' })
  })
})
