/**
 * Signer HTTP service.
 *
 * Two strictly separate flows share this process but nothing else:
 *
 *   REPO PATH (server-to-server trust):
 *     POST /v1/sign/repo — signs a repo-commit digest with the user's
 *     `atproto/signing` key (root-derived, disposable). Caller is the
 *     PDS, authenticated with the internal secret. This is the normal
 *     ATProto write path; it can never reach a wallet key.
 *
 *   WALLET PATH (user trust, Privy-style 2-of-3 shares — wallet.ts):
 *     POST /v1/wallet/pregenerate — defer-split provisioning for a DID
 *       with no enrollment yet (PDS-trusted, like the repo path): the
 *       whole entropy is persisted KEK-encrypted so assets can be sent
 *       to the addresses before first login. Receive-only and
 *       enclave-custodial until claimed; works for ANY plausible DID,
 *       including ones still living on another PDS.
 *     POST /v1/wallet/enroll  — TOFU-registers the user's request key.
 *     POST /v1/wallet/create  — generates per-wallet entropy in-enclave
 *       (or claims a pregenerated wallet's entropy — same addresses),
 *       splits it 2-of-3, keeps only the KEK-encrypted server share,
 *       and returns the device + recovery shares encrypted to the
 *       enrolled request key (the PDS relays ciphertext it cannot read).
 *       Claiming deletes the whole-entropy pregen blob atomically.
 *     POST /v1/wallet/sign    — reconstructs the key transiently from
 *       server share + the envelope's device share, signs, wipes. ONLY
 *       for envelopes signed by the enrolled user request key.
 *     POST /v1/wallet/export  — same reconstruction, returns the seed
 *       material encrypted to the request key (credible exit).
 *     POST /v1/wallet/recover — server share + user's recovery share;
 *       re-shards with fresh coefficients, optionally rotates the
 *       enrolled request key. Authorization is possession of a share
 *       that actually reconstructs this wallet — not the caller.
 *
 *     The internal secret still gates transport on all wallet routes
 *     (the PDS is the only network peer), but it is never sufficient:
 *     no user share / signed envelope, no wallet operation.
 *
 *   SHARED (read-only):
 *     POST /v1/keys/derive  — repo signing key info (wallet keys are
 *       not derivable — they are per-wallet secrets, see /v1/wallet/*).
 *     GET  /v1/wallet/info/:did — wallet public material + enrollment.
 *     GET  /v1/attestation, GET /health — open.
 */
import * as crypto from 'node:crypto'
import express, {
  type Application,
  type Request,
  type Response,
  type NextFunction,
} from 'express'
import { timingSafeEqual, createLogger } from '@certified-app/shared'
import { getAttestation, type AttestationResult } from './attestation.js'
import { deriveIdentityPublicKey, signRepoDigest } from './derive.js'
import {
  DEFAULT_FRESHNESS_SEC,
  verifyEnvelope,
  type WalletEnvelopePayload,
  type WalletOp,
} from './envelope.js'
import { bytesToHex, getRepoKeyInfo, hexToBytes } from './keys.js'
import {
  REPO_SIGNING_PURPOSE,
  isKeyPurpose,
  isPlausibleDid,
} from './purposes.js'
import {
  buildExportPayload,
  combineWalletShares,
  decryptJweToEnclave,
  decryptPregenEntropy,
  decryptServerShare,
  deriveChainKeys,
  deriveShareKek,
  encryptPregenEntropy,
  encryptServerShare,
  encryptToRequestKey,
  generateWalletEntropy,
  getWalletEncryptionPublicJwk,
  isCompactJwe,
  isValidP256PublicKeyHex,
  signEvmDigestWithKey,
  signSolMessageWithKey,
  splitWalletEntropy,
  wipe,
  type WalletChainKeys,
} from './wallet.js'
import type { PregenRow, SignerStore, WalletRow } from './store.js'

const logger = createLogger('epds-signer')

export interface SignerServiceOptions {
  rootSeed: Uint8Array
  store: SignerStore
  internalSecret: string
  freshnessSec?: number
  dstackSockPath?: string
}

/** Compressed P-256 public key: 33 bytes, 0x02/0x03 prefix. */
export function isCompressedP256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^0[23][0-9a-fA-F]{64}$/.test(value)
}

/** Public wallet info — safe to return to anyone who may know the DID. */
function walletPublicInfo(row: WalletRow): Record<string, unknown> {
  return {
    did: row.did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    version: row.version,
    createdAt: row.createdAt,
  }
}

/** Public info for an unclaimed pregenerated wallet (receive-only). */
function pregenPublicInfo(row: PregenRow): Record<string, unknown> {
  return {
    did: row.did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    createdAt: row.createdAt,
  }
}

export function createSignerApp(opts: SignerServiceOptions): Application {
  const { rootSeed, store, internalSecret } = opts
  const freshnessSec = opts.freshnessSec ?? DEFAULT_FRESHNESS_SEC

  const identityPubkeyHex = bytesToHex(deriveIdentityPublicKey(rootSeed))
  const reportDataHex = crypto
    .createHash('sha256')
    .update(Buffer.from(identityPubkeyHex, 'hex'))
    .digest('hex')
  const shareKek = deriveShareKek(rootSeed)
  const walletEncryptionPublicJwk = getWalletEncryptionPublicJwk(rootSeed)

  const app = express()
  app.use(express.json({ limit: '128kb' }))

  const requireSecret = (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers['x-internal-secret']
    if (
      !internalSecret ||
      typeof header !== 'string' ||
      !timingSafeEqual(header, internalSecret)
    ) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    next()
  }

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'epds-signer' })
  })

  app.get('/v1/attestation', async (_req, res) => {
    let attestation: AttestationResult
    try {
      attestation = await getAttestation({
        reportDataHex,
        dstackSockPath: opts.dstackSockPath,
      })
    } catch (err) {
      /* v8 ignore next 3 -- getAttestation traps its own errors */
      logger.error({ err }, 'attestation failed')
      res.status(500).json({ error: 'attestation failed' })
      return
    }
    res.json({
      ...attestation,
      identityPublicKeyHex: identityPubkeyHex,
      walletEncryptionPublicJwk,
    })
  })

  app.post('/v1/keys/derive', requireSecret, (req, res) => {
    const { did, purpose } = req.body ?? {}
    if (!isPlausibleDid(did) || !isKeyPurpose(purpose)) {
      res.status(400).json({ error: 'invalid did or purpose' })
      return
    }
    if (purpose !== REPO_SIGNING_PURPOSE) {
      res.status(400).json({
        error:
          'wallet keys are per-wallet secrets and cannot be derived — use /v1/wallet/create and /v1/wallet/info',
      })
      return
    }
    res.json(getRepoKeyInfo(rootSeed, did))
  })

  // ── REPO PATH ──────────────────────────────────────────────────────
  app.post('/v1/sign/repo', requireSecret, (req, res) => {
    const { did, digestHex } = req.body ?? {}
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    if (typeof digestHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(digestHex)) {
      res.status(400).json({ error: 'digestHex must be 32 bytes of hex' })
      return
    }
    const signature = signRepoDigest(rootSeed, did, hexToBytes(digestHex))
    res.json({ signatureHex: bytesToHex(signature) })
  })

  // ── WALLET PATH ────────────────────────────────────────────────────
  app.post('/v1/wallet/enroll', requireSecret, (req, res) => {
    const { did, requestPublicKeyHex } = req.body ?? {}
    if (
      !isPlausibleDid(did) ||
      !isCompressedP256Hex(requestPublicKeyHex) ||
      !isValidP256PublicKeyHex(requestPublicKeyHex)
    ) {
      res.status(400).json({ error: 'invalid did or requestPublicKeyHex' })
      return
    }
    const outcome = store.enroll(did, requestPublicKeyHex.toLowerCase())
    if (outcome === 'conflict') {
      res.status(409).json({
        error:
          'a different request key is already enrolled for this DID; key rotation requires wallet recovery',
      })
      return
    }
    logger.info({ did, outcome }, 'wallet enrollment')
    res.json({ status: outcome })
  })

  app.get('/v1/wallet/enrollment/:did', requireSecret, (req, res) => {
    const did = req.params.did
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    res.json({ enrolled: store.getEnrollment(did) !== null })
  })

  app.get('/v1/wallet/info/:did', requireSecret, (req, res) => {
    const did = req.params.did
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    const wallet = store.getWallet(did)
    const pregen = wallet ? null : store.getPregen(did)
    res.json({
      enrolled: store.getEnrollment(did) !== null,
      wallet: wallet ? walletPublicInfo(wallet) : null,
      pregen: pregen ? pregenPublicInfo(pregen) : null,
      walletEncryptionPublicJwk,
    })
  })

  /**
   * Pregenerate (defer-split): provision a receive-only wallet for a
   * DID that has no enrollment yet, so assets can be sent to the
   * addresses before the user's first login. The DID only has to be
   * plausible — it may belong to an account that still lives on
   * another PDS and migrates here later; claiming (not pregeneration)
   * is what requires a local, authenticated account.
   *
   * This is the ONE place whole (unsplit) entropy is persisted —
   * KEK-encrypted, distinct AAD domain. Until claimed, custody of the
   * wallet rests entirely with the enclave. Two rules bound that
   * window:
   *   - unclaimed wallets can never sign/export/recover — those paths
   *     all require the wallet row that only claiming creates;
   *   - the first /v1/wallet/create after enrollment splits the
   *     entropy 2-of-3 and DELETES the pregen blob atomically.
   * Idempotent: repeat calls return the existing record's addresses.
   */
  app.post('/v1/wallet/pregenerate', requireSecret, (req, res) => {
    const { did } = req.body ?? {}
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    if (store.getWallet(did)) {
      res.status(409).json({ error: 'wallet already exists for this DID' })
      return
    }
    const existing = store.getPregen(did)
    if (existing) {
      res.json({ status: 'exists', wallet: pregenPublicInfo(existing) })
      return
    }
    const entropy = generateWalletEntropy()
    let keys: WalletChainKeys | undefined
    try {
      keys = deriveChainKeys(entropy)
      const created = store.createPregen({
        did,
        entropyCipherHex: encryptPregenEntropy(shareKek, did, entropy),
        evmPubkeyHex: bytesToHex(keys.evmPublicKey),
        evmAddress: keys.evmAddress,
        solPubkeyHex: bytesToHex(keys.solPublicKey),
        solAddress: keys.solAddress,
      })
      const row = store.getPregen(did)
      /* v8 ignore next 4 -- lost-race guard, not reachable single-threaded */
      if (!row) {
        res.status(500).json({ error: 'wallet pregeneration failed' })
        return
      }
      logger.info(
        { did, created },
        'wallet pregenerated (unclaimed, receive-only)',
      )
      res.json({
        status: created ? 'pregenerated' : 'exists',
        wallet: pregenPublicInfo(row),
      })
      /* v8 ignore next 4 -- CSPRNG/sqlite failures are not reproducible */
    } catch (err) {
      logger.error({ err, did }, 'wallet pregeneration failed')
      res.status(500).json({ error: 'wallet pregeneration failed' })
    } finally {
      wipe(entropy, keys?.evmPrivateKey, keys?.solPrivateKey)
    }
  })

  /**
   * Create the wallet: per-wallet entropy, 2-of-3 split. The server
   * share is the ONLY thing persisted (encrypted under the KEK); the
   * device and recovery shares are returned encrypted to the enrolled
   * request key and are gone from the enclave when the response is
   * sent. The client MUST re-protect the recovery share under a
   * user-controlled recovery factor — it is not re-issuable without a
   * recovery (fresh coefficients) round.
   *
   * If a pregenerated record exists for the DID, this call CLAIMS it:
   * the pregenerated entropy — not fresh CSPRNG output — becomes the
   * wallet (so assets already sent to the advertised addresses are
   * now under the user's 2-of-3 split), and the whole-entropy blob is
   * deleted in the same transaction. Response status 'claimed'
   * instead of 'created'.
   */
  app.post('/v1/wallet/create', requireSecret, async (req, res) => {
    const { did } = req.body ?? {}
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    const enrollment = store.getEnrollment(did)
    if (!enrollment) {
      res.status(403).json({
        error: 'enroll a request key before creating a wallet',
      })
      return
    }
    if (store.getWallet(did)) {
      res.status(409).json({ error: 'wallet already exists for this DID' })
      return
    }

    const pregen = store.getPregen(did)
    let entropy: Uint8Array | undefined
    let keys: WalletChainKeys | undefined
    let shares: [Uint8Array, Uint8Array, Uint8Array] | undefined
    try {
      entropy = pregen
        ? decryptPregenEntropy(shareKek, did, pregen.entropyCipherHex)
        : generateWalletEntropy()
      keys = deriveChainKeys(entropy)
      // A pregen blob that decrypts (KEK + AAD verified) but does not
      // reproduce the advertised addresses is corrupt — refuse rather
      // than bind the user to unknown material.
      /* v8 ignore next 5 -- requires a corrupted-but-authentic blob */
      if (pregen && bytesToHex(keys.evmPublicKey) !== pregen.evmPubkeyHex) {
        res
          .status(500)
          .json({ error: 'pregenerated wallet integrity check failed' })
        return
      }
      shares = await splitWalletEntropy(entropy)
      const walletRow = {
        did,
        serverShareCipherHex: encryptServerShare(shareKek, did, shares[0]),
        evmPubkeyHex: bytesToHex(keys.evmPublicKey),
        evmAddress: keys.evmAddress,
        solPubkeyHex: bytesToHex(keys.solPublicKey),
        solAddress: keys.solAddress,
      }
      const created = pregen
        ? store.claimPregen(did, walletRow)
        : store.createWallet(walletRow)
      if (!created) {
        res.status(409).json({ error: 'wallet already exists for this DID' })
        return
      }
      const [deviceShareJwe, recoveryShareJwe] = await Promise.all([
        encryptToRequestKey(enrollment.requestPubkeyHex, shares[1]),
        encryptToRequestKey(enrollment.requestPubkeyHex, shares[2]),
      ])
      logger.info(
        { did, claimedPregen: pregen !== null },
        'wallet created (2-of-3 shares issued)',
      )
      res.json({
        status: pregen ? 'claimed' : 'created',
        wallet: walletPublicInfo(store.getWallet(did) as WalletRow),
        deviceShareJwe,
        recoveryShareJwe,
      })
    } catch (err) {
      logger.error({ err, did }, 'wallet creation failed')
      res.status(500).json({ error: 'wallet creation failed' })
    } finally {
      wipe(entropy, keys?.evmPrivateKey, keys?.solPrivateKey, ...(shares ?? []))
    }
  })

  /**
   * Verify an envelope, consume its nonce, and reconstruct the wallet
   * entropy from server share + envelope device share. Returns null
   * after writing the HTTP error response on any failure. The caller
   * MUST wipe the returned material.
   */
  async function reconstructForEnvelope(
    req: Request,
    res: Response,
    expectedOp: WalletOp,
  ): Promise<{
    payload: WalletEnvelopePayload
    entropy: Uint8Array
    keys: WalletChainKeys
    wallet: WalletRow
  } | null> {
    const { payload, sig } = req.body ?? {}
    if (typeof payload !== 'string' || typeof sig !== 'string') {
      res.status(400).json({ error: 'missing payload or sig' })
      return null
    }

    // Peek at the DID inside the payload to find the enrolled key, but
    // trust NOTHING until verifyEnvelope has checked the signature.
    let claimedDid: unknown
    try {
      claimedDid = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf8'),
      )?.did
    } catch {
      res.status(400).json({ error: 'malformed payload' })
      return null
    }
    if (!isPlausibleDid(claimedDid)) {
      res.status(400).json({ error: 'malformed payload' })
      return null
    }
    const enrollment = store.getEnrollment(claimedDid)
    if (!enrollment) {
      res.status(403).json({ error: 'no wallet enrollment for this DID' })
      return null
    }

    const result = verifyEnvelope({
      payloadB64: payload,
      sigB64: sig,
      requestPubkeyHex: enrollment.requestPubkeyHex,
      expectedOp,
      freshnessSec,
    })
    if (!result.ok) {
      logger.warn(
        { did: claimedDid, reason: result.error },
        'wallet envelope rejected',
      )
      res.status(403).json({ error: result.error })
      return null
    }
    const p = result.payload

    const wallet = store.getWallet(p.did)
    if (!wallet) {
      res.status(403).json({ error: 'no wallet exists for this DID' })
      return null
    }

    if (!store.consumeNonce(p.did, p.nonce)) {
      res.status(409).json({ error: 'nonce replayed or out of order' })
      return null
    }

    let deviceShare: Uint8Array | undefined
    let serverShare: Uint8Array | undefined
    let entropy: Uint8Array | undefined
    try {
      deviceShare = await decryptJweToEnclave(rootSeed, p.deviceShareJwe)
      serverShare = decryptServerShare(
        shareKek,
        p.did,
        wallet.serverShareCipherHex,
      )
      entropy = await combineWalletShares(serverShare, deviceShare)
      const keys = deriveChainKeys(entropy)
      // Integrity check: a share that does not reproduce the wallet's
      // registered public keys is not this wallet's share.
      if (bytesToHex(keys.evmPublicKey) !== wallet.evmPubkeyHex) {
        wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey)
        res.status(403).json({ error: 'device share does not match wallet' })
        return null
      }
      return { payload: p, entropy, keys, wallet }
    } catch (err) {
      wipe(entropy)
      logger.warn({ err, did: p.did }, 'wallet share reconstruction failed')
      res.status(403).json({ error: 'share reconstruction failed' })
      return null
    } finally {
      wipe(deviceShare, serverShare)
    }
  }

  app.post('/v1/wallet/sign', requireSecret, async (req, res) => {
    const rec = await reconstructForEnvelope(req, res, 'sign')
    if (!rec) return
    const { payload: p, entropy, keys } = rec
    try {
      if (p.purpose === 'wallet/evm') {
        const { signature, recovery } = signEvmDigestWithKey(
          keys.evmPrivateKey,
          // Payload shape already validated by verifyEnvelope
          hexToBytes(p.digestHex as string),
        )
        logger.info(
          { did: p.did, purpose: p.purpose },
          'wallet signature issued',
        )
        res.json({ signatureHex: bytesToHex(signature), recovery })
        return
      }
      const signature = signSolMessageWithKey(
        keys.solPrivateKey,
        Uint8Array.from(Buffer.from(p.messageBase64 as string, 'base64url')),
      )
      logger.info({ did: p.did, purpose: p.purpose }, 'wallet signature issued')
      res.json({ signatureHex: bytesToHex(signature) })
      /* v8 ignore next 4 -- payload shapes are pre-validated */
    } catch (err) {
      logger.error({ err, did: p.did }, 'wallet signing failed')
      res.status(500).json({ error: 'wallet signing failed' })
    } finally {
      wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey)
    }
  })

  /**
   * Credible exit: hand the user their key material, encrypted to
   * their enrolled request key. The PDS relays ciphertext; the
   * operator alone can never satisfy this route (it needs the user's
   * device share inside a user-signed envelope).
   */
  app.post('/v1/wallet/export', requireSecret, async (req, res) => {
    const rec = await reconstructForEnvelope(req, res, 'export')
    if (!rec) return
    const { payload: p, entropy, keys } = rec
    let exportBytes: Uint8Array | undefined
    try {
      const enrollment = store.getEnrollment(p.did)
      /* v8 ignore next 4 -- enrollment checked in reconstructForEnvelope */
      if (!enrollment) {
        res.status(403).json({ error: 'no wallet enrollment for this DID' })
        return
      }
      exportBytes = buildExportPayload(entropy, keys)
      const exportJwe = await encryptToRequestKey(
        enrollment.requestPubkeyHex,
        exportBytes,
      )
      logger.info({ did: p.did }, 'wallet exported to user')
      res.json({ exportJwe })
      /* v8 ignore next 4 -- enrolled keys are validated on-curve */
    } catch (err) {
      logger.error({ err, did: p.did }, 'wallet export failed')
      res.status(500).json({ error: 'wallet export failed' })
    } finally {
      wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey, exportBytes)
    }
  })

  /**
   * Device-loss recovery. The user proves control by presenting the
   * RECOVERY share (their recovery factor protects it; the operator
   * never could read it). The wallet entropy is reconstructed from
   * server + recovery shares, verified against the stored public keys,
   * and re-split with FRESH coefficients — old shares (including one
   * on a stolen device) become useless. Optionally rotates the
   * enrolled request key to the user's new device key.
   */
  app.post('/v1/wallet/recover', requireSecret, async (req, res) => {
    const { did, recoveryShareJwe, requestPublicKeyHex } = req.body ?? {}
    if (!isPlausibleDid(did) || !isCompactJwe(recoveryShareJwe)) {
      res.status(400).json({ error: 'invalid did or recoveryShareJwe' })
      return
    }
    if (
      requestPublicKeyHex !== undefined &&
      (!isCompressedP256Hex(requestPublicKeyHex) ||
        !isValidP256PublicKeyHex(requestPublicKeyHex))
    ) {
      res.status(400).json({ error: 'invalid requestPublicKeyHex' })
      return
    }
    const wallet = store.getWallet(did)
    const enrollment = store.getEnrollment(did)
    if (!wallet || !enrollment) {
      res.status(403).json({ error: 'no wallet exists for this DID' })
      return
    }

    let recoveryShare: Uint8Array | undefined
    let serverShare: Uint8Array | undefined
    let entropy: Uint8Array | undefined
    let keys: WalletChainKeys | undefined
    let newShares: [Uint8Array, Uint8Array, Uint8Array] | undefined
    try {
      try {
        recoveryShare = await decryptJweToEnclave(rootSeed, recoveryShareJwe)
        serverShare = decryptServerShare(
          shareKek,
          did,
          wallet.serverShareCipherHex,
        )
        entropy = await combineWalletShares(serverShare, recoveryShare)
        keys = deriveChainKeys(entropy)
      } catch (err) {
        logger.warn({ err, did }, 'wallet recovery reconstruction failed')
        res.status(403).json({ error: 'share reconstruction failed' })
        return
      }
      if (bytesToHex(keys.evmPublicKey) !== wallet.evmPubkeyHex) {
        res.status(403).json({ error: 'recovery share does not match wallet' })
        return
      }

      // Fresh coefficients: every share changes, forward secrecy holds.
      newShares = await splitWalletEntropy(entropy)
      const version = store.replaceServerShare(
        did,
        encryptServerShare(shareKek, did, newShares[0]),
      )
      const targetKeyHex =
        typeof requestPublicKeyHex === 'string'
          ? requestPublicKeyHex.toLowerCase()
          : enrollment.requestPubkeyHex
      if (targetKeyHex !== enrollment.requestPubkeyHex) {
        store.rotateEnrollment(did, targetKeyHex)
        logger.info({ did }, 'request key rotated during recovery')
      }
      const [deviceShareJwe, newRecoveryShareJwe] = await Promise.all([
        encryptToRequestKey(targetKeyHex, newShares[1]),
        encryptToRequestKey(targetKeyHex, newShares[2]),
      ])
      logger.info({ did, version }, 'wallet recovered (re-sharded)')
      res.json({
        status: 'recovered',
        version,
        deviceShareJwe,
        recoveryShareJwe: newRecoveryShareJwe,
      })
      /* v8 ignore next 4 -- request keys are validated on-curve above */
    } catch (err) {
      logger.error({ err, did }, 'wallet recovery failed')
      res.status(500).json({ error: 'wallet recovery failed' })
    } finally {
      wipe(
        recoveryShare,
        serverShare,
        entropy,
        keys?.evmPrivateKey,
        keys?.solPrivateKey,
        ...(newShares ?? []),
      )
    }
  })

  return app
}
