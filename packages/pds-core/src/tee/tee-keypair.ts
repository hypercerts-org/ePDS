/**
 * TeeKeypair — the repo-signing seam.
 *
 * Implements `@atproto/crypto`'s `Keypair` interface, but `sign()`
 * delegates to the TEE signer instead of using a local private key.
 * The private key never exists on this host: we hash the commit bytes
 * locally (SHA-256 — the only hash ATProto commit signatures use) and
 * send the 32-byte digest to the signer, which returns the compact
 * 64-byte low-S `r || s` signature the ATProto ecosystem requires.
 *
 * This class belongs exclusively to the REPO path. It cannot request
 * wallet signatures — the SignerClient method it holds only reaches
 * the signer's repo route.
 */
import { sha256 } from '@atproto/crypto'
import type { Keypair } from '@atproto/crypto'
import type { SignerClient } from '@certified-app/shared'

export class TeeKeypair implements Keypair {
  jwtAlg = 'ES256K'

  constructor(
    /** The account whose repo this key signs. */
    private readonly accountDid: string,
    /** did:key of the enclave-held public key (from the TEE marker). */
    private readonly keyDid: string,
    private readonly signer: SignerClient,
  ) {}

  did(): string {
    return this.keyDid
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    const digest = await sha256(msg)
    return this.signer.signRepoDigest(
      this.accountDid,
      Buffer.from(digest).toString('hex'),
    )
  }
}
