/**
 * Integration tests for the signer HTTP service — run against a real
 * express server on an ephemeral port so route wiring, auth middleware,
 * and JSON handling are all exercised end-to-end.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import type { Server } from 'node:http'
import { verifySignature } from '@atproto/crypto'
import { p256 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { createSignerApp, isCompressedP256Hex } from '../service.js'
import { SignerStore } from '../store.js'

const SECRET = 'test-internal-secret'
const seed = Buffer.alloc(32, 5)
const did = 'did:plc:servicetest'

const userPriv = p256.utils.randomSecretKey()
const userPubHex = Buffer.from(p256.getPublicKey(userPriv, true)).toString(
  'hex',
)

let dir: string
let store: SignerStore
let server: Server
let base: string

function signEnvelope(payload: Record<string, unknown>): {
  payload: string
  sig: string
} {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = p256
    .sign(bytes, userPriv, { prehash: true, lowS: false })
    .toBytes('compact')
  return {
    payload: bytes.toString('base64url'),
    sig: Buffer.from(sig).toString('base64url'),
  }
}

async function post(
  route: string,
  body: unknown,
  opts: { secret?: string } = { secret: SECRET },
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${base}${route}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(opts.secret ? { 'x-internal-secret': opts.secret } : {}),
    },
    body: JSON.stringify(body),
  })
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
  }
}

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epds-signer-svc-'))
  store = new SignerStore(path.join(dir, 'signer.sqlite'))
  const app = createSignerApp({
    rootSeed: seed,
    store,
    internalSecret: SECRET,
    dstackSockPath: path.join(dir, 'no-such-socket'),
  })
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      resolve()
    })
  })
  const address = server.address()
  if (typeof address === 'object' && address) {
    base = `http://127.0.0.1:${address.port}`
  }
})

afterAll(async () => {
  await new Promise<void>((resolve) =>
    server.close(() => {
      resolve()
    }),
  )
  store.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('open endpoints', () => {
  it('GET /health', async () => {
    const res = await fetch(`${base}/health`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'ok', service: 'epds-signer' })
  })

  it('GET /v1/attestation returns dev mode outside a TEE', async () => {
    const res = await fetch(`${base}/v1/attestation`)
    const body = (await res.json()) as Record<string, unknown>
    expect(res.status).toBe(200)
    expect(body.mode).toBe('dev')
    expect(body.quote).toBeNull()
    expect(body.reportData).toMatch(/^[0-9a-f]{64}$/)
    expect(body.identityPublicKeyHex).toMatch(/^0[23][0-9a-f]{64}$/)
  })
})

describe('internal-secret gate', () => {
  it.each([
    ['/v1/keys/derive'],
    ['/v1/sign/repo'],
    ['/v1/wallet/enroll'],
    ['/v1/wallet/sign'],
  ])('rejects %s without the secret', async (route) => {
    const res = await post(route, {}, { secret: undefined })
    expect(res.status).toBe(401)
  })

  it('rejects a wrong secret', async () => {
    const res = await post('/v1/keys/derive', {}, { secret: 'wrong' })
    expect(res.status).toBe(401)
  })
})

describe('POST /v1/keys/derive', () => {
  it('returns repo key info with a did:key', async () => {
    const res = await post('/v1/keys/derive', {
      did,
      purpose: 'atproto/signing',
    })
    expect(res.status).toBe(200)
    expect(res.json.didKey).toMatch(/^did:key:z/)
    expect(res.json.curve).toBe('secp256k1')
  })

  it('returns wallet addresses', async () => {
    const evm = await post('/v1/keys/derive', { did, purpose: 'wallet/evm' })
    expect(evm.json.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    const sol = await post('/v1/keys/derive', { did, purpose: 'wallet/sol' })
    expect(sol.json.curve).toBe('ed25519')
    expect(typeof sol.json.address).toBe('string')
  })

  it('rejects bad input', async () => {
    expect(
      (await post('/v1/keys/derive', { did, purpose: 'nope' })).status,
    ).toBe(400)
    expect(
      (await post('/v1/keys/derive', { did: 'junk', purpose: 'wallet/evm' }))
        .status,
    ).toBe(400)
  })
})

describe('POST /v1/sign/repo', () => {
  it('signs a digest verifiable against the repo did:key', async () => {
    const msg = new TextEncoder().encode('commit bytes')
    const digest = await crypto.subtle.digest('SHA-256', msg)
    const digestHex = Buffer.from(digest).toString('hex')

    const res = await post('/v1/sign/repo', { did, digestHex })
    expect(res.status).toBe(200)
    const sig = Uint8Array.from(
      Buffer.from(res.json.signatureHex as string, 'hex'),
    )

    const derive = await post('/v1/keys/derive', {
      did,
      purpose: 'atproto/signing',
    })
    await expect(
      verifySignature(derive.json.didKey as string, msg, sig),
    ).resolves.toBe(true)
  })

  it('rejects malformed digests', async () => {
    expect(
      (await post('/v1/sign/repo', { did, digestHex: 'abcd' })).status,
    ).toBe(400)
    expect(
      (await post('/v1/sign/repo', { did: 'junk', digestHex: 'ab'.repeat(32) }))
        .status,
    ).toBe(400)
  })
})

describe('wallet flow', () => {
  const nowSec = () => Math.floor(Date.now() / 1000)

  it('refuses to sign before enrollment', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: 'ab'.repeat(32),
      nonce: 1,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/no wallet enrollment/)
  })

  it('rejects malformed enrollment keys', async () => {
    const res = await post('/v1/wallet/enroll', {
      did,
      requestPublicKeyHex: 'ffff',
    })
    expect(res.status).toBe(400)
  })

  it('enrolls TOFU, idempotently', async () => {
    expect(isCompressedP256Hex(userPubHex)).toBe(true)
    const first = await post('/v1/wallet/enroll', {
      did,
      requestPublicKeyHex: userPubHex,
    })
    expect(first.status).toBe(200)
    expect(first.json.status).toBe('created')
    const again = await post('/v1/wallet/enroll', {
      did,
      requestPublicKeyHex: userPubHex,
    })
    expect(again.json.status).toBe('unchanged')
  })

  it('reports enrollment status', async () => {
    const res = await fetch(`${base}/v1/wallet/enrollment/${did}`, {
      headers: { 'x-internal-secret': SECRET },
    })
    expect(((await res.json()) as Record<string, unknown>).enrolled).toBe(true)
  })

  it('rejects a conflicting re-enrollment', async () => {
    const otherPub = Buffer.from(
      p256.getPublicKey(p256.utils.randomSecretKey(), true),
    ).toString('hex')
    const res = await post('/v1/wallet/enroll', {
      did,
      requestPublicKeyHex: otherPub,
    })
    expect(res.status).toBe(409)
  })

  it('signs an EVM digest for a valid envelope', async () => {
    const digestHex = 'cd'.repeat(32)
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex,
      nonce: 10,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)
    expect(res.json.recovery === 0 || res.json.recovery === 1).toBe(true)

    // verify against the derived wallet/evm pubkey — NOT the repo key
    const derive = await post('/v1/keys/derive', { did, purpose: 'wallet/evm' })
    const ok = secp256k1.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(Buffer.from(digestHex, 'hex')),
      Uint8Array.from(Buffer.from(derive.json.publicKeyHex as string, 'hex')),
      { prehash: false },
    )
    expect(ok).toBe(true)
  })

  it('rejects a replayed nonce', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: 'ef'.repeat(32),
      nonce: 10,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(409)
    expect(res.json.error).toMatch(/nonce/)
  })

  it('signs a Solana message with the ed25519 wallet key', async () => {
    const message = Buffer.from('solana tx message bytes')
    const env = signEnvelope({
      did,
      purpose: 'wallet/sol',
      messageBase64: message.toString('base64url'),
      nonce: 11,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)

    const derive = await post('/v1/keys/derive', { did, purpose: 'wallet/sol' })
    const ok = ed25519.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(message),
      Uint8Array.from(Buffer.from(derive.json.publicKeyHex as string, 'hex')),
    )
    expect(ok).toBe(true)
  })

  it('rejects an envelope signed by the wrong key', async () => {
    const bytes = Buffer.from(
      JSON.stringify({
        did,
        purpose: 'wallet/evm',
        digestHex: '11'.repeat(32),
        nonce: 12,
        iat: nowSec(),
      }),
    )
    const wrongSig = p256
      .sign(bytes, p256.utils.randomSecretKey(), {
        prehash: true,
        lowS: false,
      })
      .toBytes('compact')
    const res = await post('/v1/wallet/sign', {
      payload: bytes.toString('base64url'),
      sig: Buffer.from(wrongSig).toString('base64url'),
    })
    expect(res.status).toBe(403)
    expect(res.json.error).toBe('invalid signature')
  })

  it('rejects garbage payloads', async () => {
    expect(
      (await post('/v1/wallet/sign', { payload: '!!', sig: 'AA' })).status,
    ).toBe(400)
    expect((await post('/v1/wallet/sign', {})).status).toBe(400)
  })
})
