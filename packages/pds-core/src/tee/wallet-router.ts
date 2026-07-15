/**
 * Wallet routes — the ADDITIVE flow, fully separate from ATProto data.
 *
 * Mounted at /wallet on pds-core when EPDS_WALLET_ENABLED=1. These
 * routes never touch the actor store, the repo, or the repo signing
 * key; they exist purely so a logged-in user can (a) enroll their
 * wallet request key, (b) look up their wallet addresses, and (c) relay
 * user-signed signing envelopes to the TEE signer.
 *
 * Authorization model per route:
 *   POST /wallet/enroll — OAuth/access token (who is enrolling). This
 *     is the trust-on-first-use bootstrap; the signer additionally
 *     refuses to overwrite an existing enrollment.
 *   GET  /wallet/info   — OAuth/access token (public key material only).
 *   POST /wallet/sign   — NO PDS-side authorization on purpose: the
 *     envelope inside the body is signed by the user's enrolled request
 *     key and verified inside the signer. A PDS token is neither
 *     necessary nor sufficient here — that property is what keeps the
 *     wallet self-custodial even against a compromised PDS host.
 */
import express, { Router, type Request, type Response } from 'express'
import { SignerClientError, type SignerClient } from '@certified-app/shared'
import type { UserDidVerifier } from './user-auth.js'

interface LoggerLike {
  info: (obj: unknown, msg?: string) => void
  warn: (obj: unknown, msg?: string) => void
}

/** Compressed P-256 public key: 33 bytes, 0x02/0x03 prefix. */
export function isCompressedP256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^0[23][0-9a-fA-F]{64}$/.test(value)
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

export function createWalletRouter(opts: {
  signer: SignerClient
  verifyUserDid: UserDidVerifier
  logger: LoggerLike
}): Router {
  const { signer, verifyUserDid, logger } = opts
  const router = Router()
  router.use(express.json({ limit: '128kb' }))

  router.post('/enroll', async (req: Request, res: Response) => {
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
  })

  router.get('/info', async (req: Request, res: Response) => {
    const did = await verifyUserDid(req, res)
    if (!did) {
      res.status(401).json({ error: 'authentication required' })
      return
    }
    try {
      const [evm, sol, enrollment] = await Promise.all([
        signer.deriveKey(did, 'wallet/evm'),
        signer.deriveKey(did, 'wallet/sol'),
        signer.walletEnrollment(did),
      ])
      res.json({
        did,
        enrolled: enrollment.enrolled,
        evm: { address: evm.address, publicKeyHex: evm.publicKeyHex },
        sol: { address: sol.address, publicKeyHex: sol.publicKeyHex },
      })
    } catch (err) {
      logger.warn({ err, did }, 'wallet info failed')
      sendSignerError(res, err)
    }
  })

  router.post('/sign', async (req: Request, res: Response) => {
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
  })

  return router
}
