/**
 * Signer HTTP service.
 *
 * Two strictly separate flows share this process but nothing else:
 *
 *   REPO PATH (server-to-server trust):
 *     POST /v1/sign/repo — signs a repo-commit digest with the user's
 *     `atproto/signing` key. Caller is the PDS, authenticated with the
 *     internal secret. This is the normal ATProto write path; it can
 *     never reach a wallet key.
 *
 *   WALLET PATH (user trust):
 *     POST /v1/wallet/enroll — TOFU-registers the user's request key.
 *     POST /v1/wallet/sign  — signs an EVM digest / Solana message with
 *     a `wallet/*` key, but ONLY when the request envelope is signed by
 *     the enrolled user request key (see envelope.ts). The internal
 *     secret still gates transport (the PDS is the only network peer),
 *     but it is never sufficient: no envelope, no wallet signature.
 *
 *   SHARED (read-only):
 *     POST /v1/keys/derive — public key info for any purpose.
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
import {
  deriveIdentityPublicKey,
  signEd25519Message,
  signSecp256k1Digest,
} from './derive.js'
import { DEFAULT_FRESHNESS_SEC, verifyEnvelope } from './envelope.js'
import { bytesToHex, getKeyInfo, hexToBytes } from './keys.js'
import {
  REPO_SIGNING_PURPOSE,
  isKeyPurpose,
  isPlausibleDid,
} from './purposes.js'
import type { SignerStore } from './store.js'

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

export function createSignerApp(opts: SignerServiceOptions): Application {
  const { rootSeed, store, internalSecret } = opts
  const freshnessSec = opts.freshnessSec ?? DEFAULT_FRESHNESS_SEC

  const identityPubkeyHex = bytesToHex(deriveIdentityPublicKey(rootSeed))
  const reportDataHex = crypto
    .createHash('sha256')
    .update(Buffer.from(identityPubkeyHex, 'hex'))
    .digest('hex')

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
    res.json({ ...attestation, identityPublicKeyHex: identityPubkeyHex })
  })

  app.post('/v1/keys/derive', requireSecret, (req, res) => {
    const { did, purpose } = req.body ?? {}
    if (!isPlausibleDid(did) || !isKeyPurpose(purpose)) {
      res.status(400).json({ error: 'invalid did or purpose' })
      return
    }
    res.json(getKeyInfo(rootSeed, did, purpose))
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
    const { signature } = signSecp256k1Digest(
      rootSeed,
      did,
      REPO_SIGNING_PURPOSE,
      hexToBytes(digestHex),
    )
    res.json({ signatureHex: bytesToHex(signature) })
  })

  // ── WALLET PATH ────────────────────────────────────────────────────
  app.post('/v1/wallet/enroll', requireSecret, (req, res) => {
    const { did, requestPublicKeyHex } = req.body ?? {}
    if (!isPlausibleDid(did) || !isCompressedP256Hex(requestPublicKeyHex)) {
      res.status(400).json({ error: 'invalid did or requestPublicKeyHex' })
      return
    }
    const outcome = store.enroll(did, requestPublicKeyHex.toLowerCase())
    if (outcome === 'conflict') {
      res.status(409).json({
        error:
          'a different request key is already enrolled for this DID; key rotation requires a signed request',
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

  app.post('/v1/wallet/sign', requireSecret, (req, res) => {
    const { payload, sig } = req.body ?? {}
    if (typeof payload !== 'string' || typeof sig !== 'string') {
      res.status(400).json({ error: 'missing payload or sig' })
      return
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
      return
    }
    if (!isPlausibleDid(claimedDid)) {
      res.status(400).json({ error: 'malformed payload' })
      return
    }
    const enrollment = store.getEnrollment(claimedDid)
    if (!enrollment) {
      res.status(403).json({ error: 'no wallet enrollment for this DID' })
      return
    }

    const result = verifyEnvelope({
      payloadB64: payload,
      sigB64: sig,
      requestPubkeyHex: enrollment.requestPubkeyHex,
      freshnessSec,
    })
    if (!result.ok) {
      logger.warn(
        { did: claimedDid, reason: result.error },
        'wallet sign rejected',
      )
      res.status(403).json({ error: result.error })
      return
    }

    const p = result.payload
    if (!store.consumeNonce(p.did, p.nonce)) {
      res.status(409).json({ error: 'nonce replayed or out of order' })
      return
    }

    if (p.purpose === 'wallet/evm') {
      const { signature, recovery } = signSecp256k1Digest(
        rootSeed,
        p.did,
        p.purpose,
        // Payload shape already validated by verifyEnvelope
        hexToBytes(p.digestHex as string),
      )
      logger.info({ did: p.did, purpose: p.purpose }, 'wallet signature issued')
      res.json({ signatureHex: bytesToHex(signature), recovery })
      return
    }

    const signature = signEd25519Message(
      rootSeed,
      p.did,
      p.purpose,
      Uint8Array.from(Buffer.from(p.messageBase64 as string, 'base64url')),
    )
    logger.info({ did: p.did, purpose: p.purpose }, 'wallet signature issued')
    res.json({ signatureHex: bytesToHex(signature) })
  })

  return app
}
