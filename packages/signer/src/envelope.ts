/**
 * Wallet envelopes — the user check that makes the wallet
 * self-custodial.
 *
 * A wallet operation is only ever performed for a request the *user*
 * signed with their enrolled request key (P-256, e.g. a WebCrypto
 * non-extractable key or a passkey-wrapped key held by the client app).
 * The PDS merely transports the envelope; it cannot mint one, and a
 * PDS-forwarded OAuth token is deliberately NOT accepted here.
 *
 * Under the 2-of-3 share model the envelope also carries the user's
 * DEVICE SHARE, JWE-encrypted to the enclave's wallet-encryption key —
 * so the signature covers the share, and the PDS relaying the request
 * never sees share plaintext (it would otherwise transiently hold a
 * second share next to the operator's server share, violating the
 * "no single party holds ≥ 2 shares" invariant).
 *
 * Envelope wire format:
 *   {
 *     payload: base64url(JSON payload bytes),
 *     sig:     base64url(compact 64-byte P-256 ECDSA over SHA-256(payload bytes))
 *   }
 *
 * Payload JSON:
 *   {
 *     did:      the user's DID (must match the enrolled DID)
 *     op:       'sign' (default) | 'export'
 *     purpose:  'wallet/evm' | 'wallet/sol'   (op = 'sign' only)
 *     digestHex:      (wallet/evm) 32-byte tx/EIP-712 digest, hex
 *     messageBase64:  (wallet/sol) full serialized message bytes
 *     deviceShareJwe: compact JWE of the device share, addressed to
 *                     the enclave's wallet-encryption key
 *     nonce:    strictly increasing integer per DID (anti-replay)
 *     iat:      unix seconds; must be within the freshness window
 *   }
 */
import { p256 } from '@noble/curves/nist.js'
import { isCompactJwe } from './wallet.js'
import {
  isPlausibleDid,
  isWalletPurpose,
  type WalletPurpose,
} from './purposes.js'

export const DEFAULT_FRESHNESS_SEC = 120
const MAX_PAYLOAD_BYTES = 64 * 1024
const MAX_SOL_MESSAGE_BYTES = 4 * 1024

export type WalletOp = 'sign' | 'export'

export interface WalletEnvelopePayload {
  did: string
  op: WalletOp
  purpose?: WalletPurpose
  digestHex?: string
  messageBase64?: string
  deviceShareJwe: string
  nonce: number
  iat: number
}

export type EnvelopeResult =
  | { ok: true; payload: WalletEnvelopePayload }
  | { ok: false; error: string }

function decodeBase64Url(value: string, maxBytes: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0) return null
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null
  const buf = Buffer.from(value, 'base64url')
  if (buf.length === 0 || buf.length > maxBytes) return null
  return buf
}

function parsePayload(bytes: Buffer): WalletEnvelopePayload | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(bytes.toString('utf8'))
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const p = parsed as Record<string, unknown>
  if (!isPlausibleDid(p.did)) return null
  const op: unknown = p.op ?? 'sign'
  if (op !== 'sign' && op !== 'export') return null
  if (!Number.isSafeInteger(p.nonce) || (p.nonce as number) <= 0) return null
  if (!Number.isSafeInteger(p.iat)) return null
  if (!isCompactJwe(p.deviceShareJwe)) return null

  if (op === 'sign') {
    if (!isWalletPurpose(p.purpose)) return null
    if (p.purpose === 'wallet/evm') {
      if (
        typeof p.digestHex !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(p.digestHex)
      ) {
        return null
      }
    } else {
      const msg =
        typeof p.messageBase64 === 'string'
          ? decodeBase64Url(p.messageBase64, MAX_SOL_MESSAGE_BYTES)
          : null
      if (!msg) return null
    }
  }

  return {
    did: p.did,
    op,
    purpose: p.purpose as WalletPurpose | undefined,
    digestHex: p.digestHex as string | undefined,
    messageBase64: p.messageBase64 as string | undefined,
    deviceShareJwe: p.deviceShareJwe,
    nonce: p.nonce as number,
    iat: p.iat as number,
  }
}

/**
 * Verify an envelope against the enrolled request public key.
 * Performs signature, shape, and freshness checks. Nonce consumption is
 * the caller's job (it needs the store) — do it AFTER this returns ok.
 */
export function verifyEnvelope(opts: {
  payloadB64: string
  sigB64: string
  requestPubkeyHex: string
  expectedOp: WalletOp
  nowSec?: number
  freshnessSec?: number
}): EnvelopeResult {
  const {
    payloadB64,
    sigB64,
    requestPubkeyHex,
    expectedOp,
    nowSec = Math.floor(Date.now() / 1000),
    freshnessSec = DEFAULT_FRESHNESS_SEC,
  } = opts

  const payloadBytes = decodeBase64Url(payloadB64, MAX_PAYLOAD_BYTES)
  if (!payloadBytes) return { ok: false, error: 'malformed payload encoding' }
  const sigBytes = decodeBase64Url(sigB64, 64)
  if (!sigBytes || sigBytes.length !== 64) {
    return { ok: false, error: 'malformed signature encoding' }
  }

  let valid: boolean
  try {
    // prehash: true — P-256's hash (SHA-256) is applied to the payload
    // bytes. lowS: false — WebCrypto signers do not normalize S.
    valid = p256.verify(
      sigBytes,
      payloadBytes,
      Buffer.from(requestPubkeyHex, 'hex'),
      {
        prehash: true,
        lowS: false,
      },
    )
  } catch {
    valid = false
  }
  if (!valid) return { ok: false, error: 'invalid signature' }

  const payload = parsePayload(payloadBytes)
  if (!payload) return { ok: false, error: 'malformed payload' }

  if (payload.op !== expectedOp) {
    return { ok: false, error: `envelope op is not '${expectedOp}'` }
  }

  if (Math.abs(nowSec - payload.iat) > freshnessSec) {
    return { ok: false, error: 'stale envelope' }
  }

  return { ok: true, payload }
}
