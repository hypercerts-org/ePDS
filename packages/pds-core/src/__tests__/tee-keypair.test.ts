import { describe, expect, it, vi } from 'vitest'
import * as nodeCrypto from 'node:crypto'
import type { SignerClient } from '@certified-app/shared'
import { TeeKeypair } from '../tee/tee-keypair.js'

const KEY_DID = 'did:key:zQ3shTestTestTestTestTestTestTestTestTestTestTest'

describe('TeeKeypair', () => {
  it('exposes the enclave did:key and ES256K alg', () => {
    const kp = new TeeKeypair('did:plc:acct', KEY_DID, {} as SignerClient)
    expect(kp.did()).toBe(KEY_DID)
    expect(kp.jwtAlg).toBe('ES256K')
  })

  it('hashes the message with SHA-256 exactly once and delegates the digest', async () => {
    const fakeSig = Uint8Array.from(Buffer.alloc(64, 0xaa))
    const signRepoDigest = vi.fn((_did: string, _digestHex: string) =>
      Promise.resolve(fakeSig),
    )
    const signer = { signRepoDigest } as unknown as SignerClient
    const kp = new TeeKeypair('did:plc:acct', KEY_DID, signer)

    const msg = new TextEncoder().encode('dag-cbor commit bytes')
    const sig = await kp.sign(msg)

    const expectedDigest = nodeCrypto
      .createHash('sha256')
      .update(msg)
      .digest('hex')
    expect(signRepoDigest).toHaveBeenCalledExactlyOnceWith(
      'did:plc:acct',
      expectedDigest,
    )
    expect(sig).toBe(fakeSig)
  })
})
