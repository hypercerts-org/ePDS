/**
 * Integration tests for the signer HTTP service — run against a real
 * express server on an ephemeral port so route wiring, auth middleware,
 * and JSON handling are all exercised end-to-end.
 *
 * The wallet suite walks the whole 2-of-3 share lifecycle the way a
 * real client would: enroll → create (decrypt the share JWEs with the
 * user request key) → sign (device share sent JWE-encrypted to the
 * enclave) → export → recover (recovery share, fresh coefficients,
 * request-key rotation) → sign again with the fresh device share.
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
import { CompactEncrypt, compactDecrypt, importJWK, type JWK } from 'jose'
import { createSignerApp, isCompressedP256Hex } from '../service.js'
import { SignerStore } from '../store.js'

const SECRET = 'test-internal-secret'
const seed = Buffer.alloc(32, 5)
const did = 'did:plc:servicetest'

let userPriv = p256.utils.randomSecretKey()
let userPubHex = Buffer.from(p256.getPublicKey(userPriv, true)).toString('hex')

let dir: string
let store: SignerStore
let server: Server
let base: string
let enclaveJwk: JWK
let deviceShare: Uint8Array
let recoveryShare: Uint8Array
let evmPubkeyHex: string
let solPubkeyHex: string

function userPrivJwk(priv: Uint8Array): JWK {
  const uncompressed = p256.getPublicKey(priv, false)
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(uncompressed.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.subarray(33, 65)).toString('base64url'),
    d: Buffer.from(priv).toString('base64url'),
  }
}

async function decryptAsUser(
  jwe: string,
  priv: Uint8Array = userPriv,
): Promise<Uint8Array> {
  const { plaintext } = await compactDecrypt(
    jwe,
    await importJWK(userPrivJwk(priv), 'ECDH-ES'),
  )
  return plaintext
}

async function encryptToEnclave(bytes: Uint8Array): Promise<string> {
  return new CompactEncrypt(bytes)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
    .encrypt(await importJWK(enclaveJwk, 'ECDH-ES'))
}

function signEnvelope(
  payload: Record<string, unknown>,
  signWith: Uint8Array = userPriv,
): { payload: string; sig: string } {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = p256
    .sign(bytes, signWith, { prehash: true, lowS: false })
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

async function get(
  route: string,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${base}${route}`, {
    headers: { 'x-internal-secret': SECRET },
  })
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
  }
}

const nowSec = () => Math.floor(Date.now() / 1000)

interface WalletInfoJson {
  evm: { address: string; publicKeyHex: string }
  sol: { address: string; publicKeyHex: string }
  version: number
}

interface ExportJson {
  entropyHex: string
  mnemonic: string
  evm: { privateKeyHex: string; address: string }
  sol: { privateKeyHex: string; address: string }
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

  it('GET /v1/attestation returns dev mode and the wallet encryption JWK', async () => {
    const res = await fetch(`${base}/v1/attestation`)
    const body = (await res.json()) as {
      mode: string
      quote: unknown
      reportData: string
      identityPublicKeyHex: string
      walletEncryptionPublicJwk?: JWK
    }
    expect(res.status).toBe(200)
    expect(body.mode).toBe('dev')
    expect(body.quote).toBeNull()
    expect(body.reportData).toMatch(/^[0-9a-f]{64}$/)
    expect(body.identityPublicKeyHex).toMatch(/^0[23][0-9a-f]{64}$/)
    expect(body.walletEncryptionPublicJwk?.kty).toBe('EC')
    expect(body.walletEncryptionPublicJwk?.crv).toBe('P-256')
    enclaveJwk = body.walletEncryptionPublicJwk as JWK
  })
})

describe('internal-secret gate', () => {
  it.each([
    ['/v1/keys/derive'],
    ['/v1/sign/repo'],
    ['/v1/wallet/pregenerate'],
    ['/v1/wallet/enroll'],
    ['/v1/wallet/create'],
    ['/v1/wallet/sign'],
    ['/v1/wallet/export'],
    ['/v1/wallet/recover'],
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

  it('refuses to derive wallet keys — they are per-wallet secrets', async () => {
    for (const purpose of ['wallet/evm', 'wallet/sol']) {
      const res = await post('/v1/keys/derive', { did, purpose })
      expect(res.status).toBe(400)
      expect(res.json.error).toMatch(/cannot be derived/)
    }
  })

  it('rejects bad input', async () => {
    expect(
      (await post('/v1/keys/derive', { did, purpose: 'nope' })).status,
    ).toBe(400)
    expect(
      (
        await post('/v1/keys/derive', {
          did: 'junk',
          purpose: 'atproto/signing',
        })
      ).status,
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

describe('wallet lifecycle (2-of-3 shares)', () => {
  it('refuses to create a wallet before enrollment', async () => {
    const res = await post('/v1/wallet/create', { did })
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/enroll a request key/)
  })

  it('rejects malformed enrollment keys (including off-curve points)', async () => {
    expect(
      (await post('/v1/wallet/enroll', { did, requestPublicKeyHex: 'ffff' }))
        .status,
    ).toBe(400)
    expect(
      (
        await post('/v1/wallet/enroll', {
          did,
          requestPublicKeyHex: '02' + 'ff'.repeat(32),
        })
      ).status,
    ).toBe(400)
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
    const res = await get(`/v1/wallet/enrollment/${did}`)
    expect(res.json.enrolled).toBe(true)
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

  it('refuses to sign before the wallet exists', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: 'ab'.repeat(32),
      deviceShareJwe: 'AAAA..BBBB.CCCC.DDDD',
      nonce: 1,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/no wallet exists/)
  })

  it('creates the wallet and returns user shares as JWEs', async () => {
    const res = await post('/v1/wallet/create', { did })
    expect(res.status).toBe(200)
    expect(res.json.status).toBe('created')
    const wallet = res.json.wallet as WalletInfoJson
    expect(wallet.evm.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(wallet.sol.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
    expect(wallet.version).toBe(1)
    evmPubkeyHex = wallet.evm.publicKeyHex
    solPubkeyHex = wallet.sol.publicKeyHex

    // The user (and only the user) can open the share JWEs.
    deviceShare = await decryptAsUser(res.json.deviceShareJwe as string)
    recoveryShare = await decryptAsUser(res.json.recoveryShareJwe as string)
    expect(deviceShare.length).toBeGreaterThan(16)
    expect(recoveryShare.length).toBeGreaterThan(16)
  })

  it('refuses to create the wallet twice', async () => {
    const res = await post('/v1/wallet/create', { did })
    expect(res.status).toBe(409)
  })

  it('exposes public wallet info', async () => {
    const res = await get(`/v1/wallet/info/${did}`)
    expect(res.status).toBe(200)
    expect(res.json.enrolled).toBe(true)
    const wallet = res.json.wallet as WalletInfoJson
    expect(wallet.evm.publicKeyHex).toBe(evmPubkeyHex)
    expect((res.json.walletEncryptionPublicJwk as JWK).crv).toBe('P-256')
    const missing = await get('/v1/wallet/info/did:plc:nobody')
    expect(missing.json.wallet).toBeNull()
  })

  it('signs an EVM digest for a valid envelope carrying the device share', async () => {
    const digestHex = 'cd'.repeat(32)
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex,
      deviceShareJwe: await encryptToEnclave(deviceShare),
      nonce: 10,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)
    expect(res.json.recovery === 0 || res.json.recovery === 1).toBe(true)
    const ok = secp256k1.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(Buffer.from(digestHex, 'hex')),
      Uint8Array.from(Buffer.from(evmPubkeyHex, 'hex')),
      { prehash: false },
    )
    expect(ok).toBe(true)
  })

  it('rejects a replayed nonce', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: 'ef'.repeat(32),
      deviceShareJwe: await encryptToEnclave(deviceShare),
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
      deviceShareJwe: await encryptToEnclave(deviceShare),
      nonce: 11,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)
    const ok = ed25519.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(message),
      Uint8Array.from(Buffer.from(solPubkeyHex, 'hex')),
    )
    expect(ok).toBe(true)
  })

  it('rejects an envelope signed by the wrong key', async () => {
    const env = signEnvelope(
      {
        did,
        purpose: 'wallet/evm',
        digestHex: '11'.repeat(32),
        deviceShareJwe: await encryptToEnclave(deviceShare),
        nonce: 12,
        iat: nowSec(),
      },
      p256.utils.randomSecretKey(),
    )
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toBe('invalid signature')
  })

  it('rejects a share that is not this wallet’s share', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: '22'.repeat(32),
      deviceShareJwe: await encryptToEnclave(
        Uint8Array.from({ length: deviceShare.length }, (_, i) => i + 1),
      ),
      nonce: 13,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/does not match wallet|reconstruction/)
  })

  it('rejects an undecryptable device share JWE', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: '33'.repeat(32),
      deviceShareJwe: 'AAAA..BBBB.CCCC.DDDD',
      nonce: 14,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/reconstruction failed/)
  })

  it('rejects garbage payloads', async () => {
    expect(
      (await post('/v1/wallet/sign', { payload: '!!', sig: 'AA' })).status,
    ).toBe(400)
    expect((await post('/v1/wallet/sign', {})).status).toBe(400)
  })

  it('exports the wallet, encrypted to the user request key', async () => {
    const env = signEnvelope({
      did,
      op: 'export',
      deviceShareJwe: await encryptToEnclave(deviceShare),
      nonce: 15,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/export', env)
    expect(res.status).toBe(200)
    const exported = JSON.parse(
      new TextDecoder().decode(
        await decryptAsUser(res.json.exportJwe as string),
      ),
    ) as ExportJson
    expect(exported.mnemonic.split(' ')).toHaveLength(12)
    expect(exported.entropyHex).toMatch(/^[0-9a-f]{32}$/)
    expect(exported.evm.privateKeyHex).toMatch(/^[0-9a-f]{64}$/)
    // The exported key really is the wallet key.
    expect(
      Buffer.from(
        secp256k1.getPublicKey(
          Buffer.from(exported.evm.privateKeyHex, 'hex'),
          true,
        ),
      ).toString('hex'),
    ).toBe(evmPubkeyHex)
  })

  it('rejects a sign envelope smuggled to the export route', async () => {
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: '44'.repeat(32),
      deviceShareJwe: await encryptToEnclave(deviceShare),
      nonce: 16,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/export', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/op is not 'export'/)
  })

  it('recovers with the recovery share, rotating the request key and re-sharding', async () => {
    const newPriv = p256.utils.randomSecretKey()
    const newPubHex = Buffer.from(p256.getPublicKey(newPriv, true)).toString(
      'hex',
    )
    const res = await post('/v1/wallet/recover', {
      did,
      recoveryShareJwe: await encryptToEnclave(recoveryShare),
      requestPublicKeyHex: newPubHex,
    })
    expect(res.status).toBe(200)
    expect(res.json.status).toBe('recovered')
    expect(res.json.version).toBe(2)

    const oldDeviceShare = deviceShare
    deviceShare = await decryptAsUser(
      res.json.deviceShareJwe as string,
      newPriv,
    )
    recoveryShare = await decryptAsUser(
      res.json.recoveryShareJwe as string,
      newPriv,
    )
    userPriv = newPriv
    userPubHex = newPubHex

    // Old shares are useless after the fresh-coefficient re-shard.
    const stale = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex: '55'.repeat(32),
      deviceShareJwe: await encryptToEnclave(oldDeviceShare),
      nonce: 20,
      iat: nowSec(),
    })
    const staleRes = await post('/v1/wallet/sign', stale)
    expect(staleRes.status).toBe(403)
  })

  it('signs with the fresh device share and rotated request key — same address', async () => {
    const digestHex = '66'.repeat(32)
    const env = signEnvelope({
      did,
      purpose: 'wallet/evm',
      digestHex,
      deviceShareJwe: await encryptToEnclave(deviceShare),
      nonce: 21,
      iat: nowSec(),
    })
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)
    const ok = secp256k1.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(Buffer.from(digestHex, 'hex')),
      Uint8Array.from(Buffer.from(evmPubkeyHex, 'hex')),
      { prehash: false },
    )
    expect(ok).toBe(true)
  })

  it('rejects recovery with a wrong share', async () => {
    const res = await post('/v1/wallet/recover', {
      did,
      recoveryShareJwe: await encryptToEnclave(
        Uint8Array.from({ length: recoveryShare.length }, (_, i) => 99 - i),
      ),
    })
    expect(res.status).toBe(403)
  })

  it('rejects recovery with an undecryptable JWE or bad input', async () => {
    expect(
      (
        await post('/v1/wallet/recover', {
          did,
          recoveryShareJwe: 'AAAA..BBBB.CCCC.DDDD',
        })
      ).status,
    ).toBe(403)
    expect(
      (await post('/v1/wallet/recover', { did, recoveryShareJwe: 'nope' }))
        .status,
    ).toBe(400)
    expect(
      (
        await post('/v1/wallet/recover', {
          did,
          recoveryShareJwe: 'AAAA..BBBB.CCCC.DDDD',
          requestPublicKeyHex: 'ffff',
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await post('/v1/wallet/recover', {
          did: 'did:plc:nobody',
          recoveryShareJwe: 'AAAA..BBBB.CCCC.DDDD',
        })
      ).status,
    ).toBe(403)
  })
})

describe('wallet pregeneration (defer-split)', () => {
  // A DID with no local account coupling — pregeneration is keyed by
  // DID alone, so this could equally be a DID living on another PDS.
  const pregenDid = 'did:plc:pregentest'
  const pregenPriv = p256.utils.randomSecretKey()
  const pregenPubHex = Buffer.from(
    p256.getPublicKey(pregenPriv, true),
  ).toString('hex')
  let advertisedEvmAddress: string
  let advertisedSolAddress: string
  let pregenEvmPubkeyHex: string
  let pregenDeviceShare: Uint8Array

  it('rejects a bad did', async () => {
    const res = await post('/v1/wallet/pregenerate', { did: 'garbage' })
    expect(res.status).toBe(400)
  })

  it('pregenerates a receive-only wallet with no enrollment', async () => {
    const res = await post('/v1/wallet/pregenerate', { did: pregenDid })
    expect(res.status).toBe(200)
    expect(res.json.status).toBe('pregenerated')
    const wallet = res.json.wallet as WalletInfoJson
    expect(wallet.evm.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(wallet.sol.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
    advertisedEvmAddress = wallet.evm.address
    advertisedSolAddress = wallet.sol.address
    pregenEvmPubkeyHex = wallet.evm.publicKeyHex
  })

  it('is idempotent — repeat calls return the same addresses', async () => {
    const res = await post('/v1/wallet/pregenerate', { did: pregenDid })
    expect(res.status).toBe(200)
    expect(res.json.status).toBe('exists')
    const wallet = res.json.wallet as WalletInfoJson
    expect(wallet.evm.address).toBe(advertisedEvmAddress)
    expect(wallet.sol.address).toBe(advertisedSolAddress)
  })

  it('exposes the unclaimed wallet as pregen in wallet info', async () => {
    const res = await get(`/v1/wallet/info/${pregenDid}`)
    expect(res.status).toBe(200)
    expect(res.json.enrolled).toBe(false)
    expect(res.json.wallet).toBeNull()
    const pregen = res.json.pregen as WalletInfoJson
    expect(pregen.evm.address).toBe(advertisedEvmAddress)
  })

  it('cannot sign before claim — unclaimed wallets are receive-only', async () => {
    // Even a correctly enrolled user cannot sign until the wallet is
    // claimed: no wallet row exists yet.
    const enroll = await post('/v1/wallet/enroll', {
      did: pregenDid,
      requestPublicKeyHex: pregenPubHex,
    })
    expect(enroll.status).toBe(200)
    const env = signEnvelope(
      {
        did: pregenDid,
        purpose: 'wallet/evm',
        digestHex: 'ab'.repeat(32),
        deviceShareJwe: 'AAAA..BBBB.CCCC.DDDD',
        nonce: 1,
        iat: nowSec(),
      },
      pregenPriv,
    )
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(403)
    expect(res.json.error).toMatch(/no wallet exists/)
  })

  it('claims the pregenerated wallet on create — same addresses, shares issued', async () => {
    const res = await post('/v1/wallet/create', { did: pregenDid })
    expect(res.status).toBe(200)
    expect(res.json.status).toBe('claimed')
    const wallet = res.json.wallet as WalletInfoJson
    // The claimed wallet IS the pregenerated one — assets sent to the
    // advertised addresses now sit under the user's 2-of-3 split.
    expect(wallet.evm.address).toBe(advertisedEvmAddress)
    expect(wallet.sol.address).toBe(advertisedSolAddress)
    expect(wallet.version).toBe(1)
    pregenDeviceShare = await decryptAsUser(
      res.json.deviceShareJwe as string,
      pregenPriv,
    )
    expect(pregenDeviceShare.length).toBeGreaterThan(16)
  })

  it('deletes the pregen record after claim', async () => {
    const res = await get(`/v1/wallet/info/${pregenDid}`)
    expect(res.json.pregen).toBeNull()
    expect((res.json.wallet as WalletInfoJson).evm.address).toBe(
      advertisedEvmAddress,
    )
  })

  it('signs after claim with the issued device share', async () => {
    const digestHex = 'aa'.repeat(32)
    const env = signEnvelope(
      {
        did: pregenDid,
        purpose: 'wallet/evm',
        digestHex,
        deviceShareJwe: await encryptToEnclave(pregenDeviceShare),
        nonce: 2,
        iat: nowSec(),
      },
      pregenPriv,
    )
    const res = await post('/v1/wallet/sign', env)
    expect(res.status).toBe(200)
    const ok = secp256k1.verify(
      Uint8Array.from(Buffer.from(res.json.signatureHex as string, 'hex')),
      Uint8Array.from(Buffer.from(digestHex, 'hex')),
      Uint8Array.from(Buffer.from(pregenEvmPubkeyHex, 'hex')),
      { prehash: false },
    )
    expect(ok).toBe(true)
  })

  it('refuses to pregenerate once a wallet exists', async () => {
    const res = await post('/v1/wallet/pregenerate', { did: pregenDid })
    expect(res.status).toBe(409)
  })
})
