/**
 * Wallet routes — the ADDITIVE flow, fully separate from ATProto data.
 *
 * Mounted on pds-core when EPDS_WALLET_ENABLED=1, on two equivalent
 * surfaces backed by the same handlers:
 *
 *   REST:  /wallet/<op>                                   (createWalletRouter)
 *   XRPC:  /xrpc/app.gainforest.wallet.<method>           (createWalletXrpcRouter)
 *
 * The wallet Lexicon namespace is `app.gainforest.wallet.*`:
 *
 *   | XRPC method (NSID)                  | Type      | REST alias           |
 *   | ----------------------------------- | --------- | -------------------- |
 *   | app.gainforest.wallet.enroll        | procedure | POST /wallet/enroll  |
 *   | app.gainforest.wallet.create        | procedure | POST /wallet/create  |
 *   | app.gainforest.wallet.getWallet     | query     | GET  /wallet/info    |
 *   | app.gainforest.wallet.getPublicWallet | query   | GET  /wallet/public-info |
 *   | app.gainforest.wallet.sign          | procedure | POST /wallet/sign    |
 *   | app.gainforest.wallet.export        | procedure | POST /wallet/export  |
 *   | app.gainforest.wallet.recover       | procedure | POST /wallet/recover |
 *
 * These routes never touch the actor store, the repo, or the repo
 * signing key; they relay between the user's client and the TEE signer,
 * which holds each wallet as a Privy-style 2-of-3 Shamir split (server /
 * device / recovery shares). Every share that passes through here is
 * a JWE this host cannot decrypt — shares travel user↔enclave, and
 * the PDS is a ciphertext courier. That is what keeps the operator
 * below the "holds ≥ 2 shares" line.
 *
 * Authorization model per operation:
 *   enroll  — OAuth/access token (who is enrolling). This is the
 *     trust-on-first-use bootstrap; the signer additionally refuses to
 *     overwrite an existing enrollment.
 *   create  — OAuth/access token. Generates the wallet in the enclave
 *     (or claims a pregenerated one — response status 'claimed', same
 *     addresses that were advertised pre-claim); the response's
 *     device/recovery share JWEs are decryptable only by the enrolled
 *     request key.
 *   getWallet/info — OAuth/access token (public material only; an
 *     unclaimed pregenerated wallet appears as `pregen`).
 *   getPublicWallet/public-info — public lookup by DID, returning only
 *     receive addresses and public keys for a claimed or pregenerated
 *     wallet. This lets clients resolve an ATProto handle and transfer
 *     without exposing enrollment state or enclave metadata.
 *   sign    — NO PDS-side authorization on purpose: the envelope inside
 *     the body is signed by the user's enrolled request key and
 *     verified inside the signer. A PDS token is neither necessary nor
 *     sufficient here — that property is what keeps the wallet
 *     self-custodial even against a compromised PDS host.
 *   export  — same as sign (user-signed export envelope); the response
 *     is encrypted to the user's request key. Credible exit: the
 *     operator alone can never satisfy or read it.
 *   recover — OAuth/access token for transport, but the real
 *     authorization is possession of the recovery share, which the
 *     enclave verifies against the wallet's registered keys.
 */
import express, { Router, type Request, type Response } from 'express'
import { SignerClientError, type SignerClient } from '@certified-app/shared'
import type { UserDidVerifier } from './user-auth.js'

interface LoggerLike {
  info: (obj: unknown, msg?: string) => void
  warn: (obj: unknown, msg?: string) => void
}

/** The wallet Lexicon namespace all XRPC methods live under. */
export const WALLET_NSID_PREFIX = 'app.gainforest.wallet'

/** Compressed P-256 public key: 33 bytes, 0x02/0x03 prefix. */
export function isCompressedP256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^0[23][0-9a-fA-F]{64}$/.test(value)
}

/** DID shape accepted by the signer for wallet lookup/pregeneration. */
export function isPlausibleWalletDid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^did:(plc|web):[a-zA-Z0-9._:%-]{1,512}$/.test(value)
  )
}

/** Envelope fields are opaque base64url blobs with sane size caps. */
export function isEnvelopeField(
  value: unknown,
  maxLen: number,
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLen &&
    /^[A-Za-z0-9_-]+$/.test(value)
  )
}

/**
 * Map a signer failure onto our response: pass 4xx statuses through
 * (they are meaningful to the client — 403 bad envelope, 409 replay),
 * translate everything else into a 502.
 */
export function sendSignerError(res: Response, err: unknown): void {
  if (
    err instanceof SignerClientError &&
    err.status >= 400 &&
    err.status < 500
  ) {
    res.status(err.status).json({ error: err.message })
    return
  }
  res.status(502).json({ error: 'signer unavailable' })
}

export interface WalletRouterOptions {
  signer: SignerClient
  verifyUserDid: UserDidVerifier
  logger: LoggerLike
}

type Handler = (req: Request, res: Response) => Promise<void>

interface WalletHandlers {
  enroll: Handler
  create: Handler
  info: Handler
  publicInfo: Handler
  sign: Handler
  export: Handler
  recover: Handler
}

/** The route handlers, shared verbatim by the REST and XRPC surfaces. */
function buildWalletHandlers(opts: WalletRouterOptions): WalletHandlers {
  const { signer, verifyUserDid, logger } = opts

  const enroll: Handler = async (req, res) => {
    const did = await verifyUserDid(req, res)
    if (!did) {
      res.status(401).json({ error: 'authentication required' })
      return
    }
    const requestPublicKeyHex: unknown = req.body?.requestPublicKeyHex
    if (!isCompressedP256Hex(requestPublicKeyHex)) {
      res.status(400).json({
        error:
          'requestPublicKeyHex must be a compressed P-256 public key (66 hex chars)',
      })
      return
    }
    try {
      const result = await signer.walletEnroll(did, requestPublicKeyHex)
      logger.info({ did, status: result.status }, 'wallet enrollment forwarded')
      res.json(result)
    } catch (err) {
      logger.warn({ err, did }, 'wallet enrollment failed')
      sendSignerError(res, err)
    }
  }

  const create: Handler = async (req, res) => {
    const did = await verifyUserDid(req, res)
    if (!did) {
      res.status(401).json({ error: 'authentication required' })
      return
    }
    try {
      const result = await signer.walletCreate(did)
      logger.info({ did }, 'wallet created')
      res.json(result)
    } catch (err) {
      logger.warn({ err, did }, 'wallet creation failed')
      sendSignerError(res, err)
    }
  }

  const info: Handler = async (req, res) => {
    const did = await verifyUserDid(req, res)
    if (!did) {
      res.status(401).json({ error: 'authentication required' })
      return
    }
    try {
      const result = await signer.walletInfo(did)
      res.json({ did, ...result })
    } catch (err) {
      logger.warn({ err, did }, 'wallet info failed')
      sendSignerError(res, err)
    }
  }

  const publicInfo: Handler = async (req, res) => {
    const did: unknown = req.query.did
    if (!isPlausibleWalletDid(did)) {
      res.status(400).json({ error: 'missing or invalid did' })
      return
    }
    try {
      const result = await signer.walletInfo(did)
      const wallet = result.wallet ?? result.pregen
      if (!wallet) {
        res.status(404).json({ error: 'wallet not found' })
        return
      }
      res.json({
        did,
        status: result.wallet ? 'claimed' : 'pregenerated',
        wallet,
      })
    } catch (err) {
      logger.warn({ err, did }, 'public wallet info failed')
      sendSignerError(res, err)
    }
  }

  const sign: Handler = async (req, res) => {
    const payload: unknown = req.body?.payload
    const sig: unknown = req.body?.sig
    if (!isEnvelopeField(payload, 90_000) || !isEnvelopeField(sig, 128)) {
      res.status(400).json({ error: 'missing or malformed payload/sig' })
      return
    }
    try {
      // Deliberately no PDS-side auth: the envelope IS the authorization,
      // and only the signer (holding the enrolled key) can judge it.
      const result = await signer.walletSign({ payload, sig })
      res.json(result)
    } catch (err) {
      sendSignerError(res, err)
    }
  }

  const exportWallet: Handler = async (req, res) => {
    const payload: unknown = req.body?.payload
    const sig: unknown = req.body?.sig
    if (!isEnvelopeField(payload, 90_000) || !isEnvelopeField(sig, 128)) {
      res.status(400).json({ error: 'missing or malformed payload/sig' })
      return
    }
    try {
      // Same trust shape as sign; the response is a JWE only the
      // user's request key opens — we relay ciphertext both ways.
      const result = await signer.walletExport({ payload, sig })
      res.json(result)
    } catch (err) {
      sendSignerError(res, err)
    }
  }

  const recover: Handler = async (req, res) => {
    const did = await verifyUserDid(req, res)
    if (!did) {
      res.status(401).json({ error: 'authentication required' })
      return
    }
    const recoveryShareJwe: unknown = req.body?.recoveryShareJwe
    const requestPublicKeyHex: unknown = req.body?.requestPublicKeyHex
    if (
      typeof recoveryShareJwe !== 'string' ||
      recoveryShareJwe.length === 0 ||
      recoveryShareJwe.length > 16_384
    ) {
      res.status(400).json({ error: 'missing or malformed recoveryShareJwe' })
      return
    }
    if (
      requestPublicKeyHex !== undefined &&
      !isCompressedP256Hex(requestPublicKeyHex)
    ) {
      res.status(400).json({ error: 'malformed requestPublicKeyHex' })
      return
    }
    try {
      const result = await signer.walletRecover({
        did,
        recoveryShareJwe,
        requestPublicKeyHex,
      })
      logger.info({ did }, 'wallet recovered')
      res.json(result)
    } catch (err) {
      logger.warn({ err, did }, 'wallet recovery failed')
      sendSignerError(res, err)
    }
  }

  return {
    enroll,
    create,
    info,
    publicInfo,
    sign,
    export: exportWallet,
    recover,
  }
}

/** REST surface — mount at `/wallet`. */
export function createWalletRouter(opts: WalletRouterOptions): Router {
  const h = buildWalletHandlers(opts)
  const router = Router()
  router.use(express.json({ limit: '128kb' }))

  router.post('/enroll', h.enroll)
  router.post('/create', h.create)
  router.get('/info', h.info)
  router.get('/public-info', h.publicInfo)
  router.post('/sign', h.sign)
  router.post('/export', h.export)
  router.post('/recover', h.recover)

  return router
}

/**
 * XRPC surface — mount at `/xrpc`. Same handlers under the
 * `app.gainforest.wallet.*` Lexicon namespace (queries GET, procedures
 * POST). Body parsing is attached per-route, NOT router-wide, so
 * unrelated `/xrpc/com.atproto.*` requests passing through this router
 * are never touched (the stock PDS does its own body handling).
 */
export function createWalletXrpcRouter(opts: WalletRouterOptions): Router {
  const h = buildWalletHandlers(opts)
  const router = Router()
  const json = express.json({ limit: '128kb' })

  router.post(`/${WALLET_NSID_PREFIX}.enroll`, json, h.enroll)
  router.post(`/${WALLET_NSID_PREFIX}.create`, json, h.create)
  router.get(`/${WALLET_NSID_PREFIX}.getWallet`, h.info)
  router.get(`/${WALLET_NSID_PREFIX}.getPublicWallet`, h.publicInfo)
  router.post(`/${WALLET_NSID_PREFIX}.sign`, json, h.sign)
  router.post(`/${WALLET_NSID_PREFIX}.export`, json, h.export)
  router.post(`/${WALLET_NSID_PREFIX}.recover`, json, h.recover)

  return router
}
