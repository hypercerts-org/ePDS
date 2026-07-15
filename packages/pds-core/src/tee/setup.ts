/**
 * TEE integration wiring for pds-core.
 *
 * Reads the EPDS_SIGNER_* / EPDS_TEE_* / EPDS_WALLET_* env vars and
 * installs, per flag:
 *
 *   EPDS_SIGNER_URL       — master switch. Unset = everything off, the
 *                           PDS behaves exactly like stock ePDS.
 *   EPDS_SIGNER_SECRET    — required with EPDS_SIGNER_URL; transport
 *                           auth for PDS -> signer calls.
 *   EPDS_SIGNER_REQUIRE_ATTESTATION=1
 *                         — refuse to start unless the signer presents
 *                           a hardware quote (mode 'dstack'). Leave off
 *                           only in development.
 *   EPDS_TEE_REPO_SIGNING=1
 *                         — patch the actor store so TEE-adopted actors
 *                           sign repo commits in the enclave, and expose
 *                           POST /_internal/tee/adopt for migrating
 *                           accounts (internal-secret gated).
 *   EPDS_TEE_ADOPT_ON_SIGNUP=1
 *                         — additionally adopt every newly created
 *                           account right after signup (fire-and-forget;
 *                           accounts remain fully functional on the
 *                           local key until adoption lands).
 *   EPDS_WALLET_ENABLED=1 — mount the wallet routes (the additive,
 *                           strictly separate wallet flow) on both
 *                           surfaces: REST /wallet/* and the XRPC
 *                           Lexicon namespace
 *                           /xrpc/app.gainforest.wallet.*.
 *
 * The two flows never share anything but the SignerClient transport:
 * repo signing goes through TeeKeypair -> /v1/sign/repo; the wallet
 * goes through /wallet/* (or app.gainforest.wallet.*) -> /v1/wallet/*
 * with user-signed envelopes.
 */
import express, { type Application } from 'express'
import {
  SignerClient,
  verifyInternalSecret,
  type SignerClientOptions,
} from '@certified-app/shared'
import {
  adoptAccountIntoTee,
  installTeeRepoSigning,
  type AdoptionCtx,
} from './actor-store-tee.js'
import { createUserDidVerifier, type UserDidVerifier } from './user-auth.js'
import { createWalletRouter, createWalletXrpcRouter } from './wallet-router.js'

interface LoggerLike {
  info: (obj: unknown, msg?: string) => void
  warn: (obj: unknown, msg?: string) => void
  error: (obj: unknown, msg?: string) => void
  debug: (obj: unknown, msg?: string) => void
}

export interface TeeEnv {
  EPDS_SIGNER_URL?: string
  EPDS_SIGNER_SECRET?: string
  EPDS_SIGNER_REQUIRE_ATTESTATION?: string
  EPDS_TEE_REPO_SIGNING?: string
  EPDS_TEE_ADOPT_ON_SIGNUP?: string
  EPDS_WALLET_ENABLED?: string
}

export interface PdsLike {
  app: Application
  ctx: AdoptionCtx & { authVerifier: unknown }
}

export interface TeeIntegration {
  enabled: boolean
  signer: SignerClient | null
  /**
   * Finalize wallet XRPC mount order after all normal ePDS routes have
   * been installed, immediately before `pds.start()`. When wallets are
   * enabled this wraps the fully configured stock app with the custom
   * app.gainforest.wallet.* router first, so the upstream /xrpc
   * catch-all cannot intercept custom NSIDs. Idempotent; otherwise noop.
   */
  finalizeApp: () => void
  /**
   * Fire-and-forget adoption hook for freshly created accounts. A noop
   * unless both EPDS_TEE_REPO_SIGNING and EPDS_TEE_ADOPT_ON_SIGNUP are
   * on. Never throws — signup must not fail because adoption did.
   */
  adoptOnSignup: (did: string) => void
}

const DISABLED: TeeIntegration = {
  enabled: false,
  signer: null,
  finalizeApp: () => {},
  adoptOnSignup: () => {},
}

export async function setupTeeIntegration(opts: {
  pds: PdsLike
  logger: LoggerLike
  env?: TeeEnv
  /** Test seam — swap in a stub SignerClient. */
  signerFactory?: (options: SignerClientOptions) => SignerClient
  /** Test seam — swap in a stub user-DID verifier. */
  userDidVerifier?: UserDidVerifier
}): Promise<TeeIntegration> {
  const { pds, logger } = opts
  const env = opts.env ?? (process.env as TeeEnv)

  const signerUrl = env.EPDS_SIGNER_URL
  if (!signerUrl) {
    return DISABLED
  }
  const secret = env.EPDS_SIGNER_SECRET
  if (!secret) {
    throw new Error(
      'EPDS_SIGNER_SECRET must be set when EPDS_SIGNER_URL is set',
    )
  }

  const signerFactory =
    opts.signerFactory ?? ((options) => new SignerClient(options))
  const signer = signerFactory({ baseUrl: signerUrl, secret })

  // Attestation gate: in a split-host deployment the signer must prove
  // it runs the expected code inside genuine TEE hardware before we
  // trust it with anything.
  const attestation = await signer.attestation()
  if (env.EPDS_SIGNER_REQUIRE_ATTESTATION === '1') {
    if (attestation.mode !== 'dstack' || !attestation.quote) {
      throw new Error(
        'EPDS_SIGNER_REQUIRE_ATTESTATION=1 but the signer presented no hardware quote ' +
          `(mode: ${attestation.mode}${attestation.note ? `, note: ${attestation.note}` : ''})`,
      )
    }
    logger.info(
      { reportData: attestation.reportData },
      'signer attestation verified (dstack quote present)',
    )
  } else if (attestation.mode !== 'dstack') {
    logger.warn(
      { mode: attestation.mode, note: attestation.note },
      'signer is UNATTESTED — acceptable in development only',
    )
  }

  const repoSigning = env.EPDS_TEE_REPO_SIGNING === '1'
  const adoptOnSignupFlag = env.EPDS_TEE_ADOPT_ON_SIGNUP === '1'
  const walletEnabled = env.EPDS_WALLET_ENABLED === '1'

  let adoptOnSignup: TeeIntegration['adoptOnSignup'] = () => {}
  let finalizeApp: TeeIntegration['finalizeApp'] = () => {}

  if (repoSigning) {
    installTeeRepoSigning({ actorStore: pds.ctx.actorStore, signer, logger })

    // Internal migration endpoint: adopt an existing account into TEE
    // signing. Same auth convention as the other /_internal routes.
    pds.app.post('/_internal/tee/adopt', express.json(), async (req, res) => {
      if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const did: unknown = req.body?.did
      if (typeof did !== 'string' || !did.startsWith('did:')) {
        res.status(400).json({ error: 'missing or invalid did' })
        return
      }
      try {
        const marker = await adoptAccountIntoTee({
          ctx: pds.ctx,
          signer,
          did,
          logger,
        })
        res.json({
          ok: true,
          keyDid: marker.keyDid,
          adoptedAt: marker.adoptedAt,
        })
      } catch (err) {
        logger.error({ err, did }, 'TEE adoption failed')
        res.status(502).json({ error: 'adoption failed' })
      }
    })

    if (adoptOnSignupFlag) {
      adoptOnSignup = (did: string) => {
        adoptAccountIntoTee({ ctx: pds.ctx, signer, did, logger }).catch(
          (err: unknown) => {
            logger.error(
              { err, did },
              'TEE adoption on signup failed (account remains on local key)',
            )
          },
        )
      }
    }
  } else if (adoptOnSignupFlag) {
    logger.warn(
      'EPDS_TEE_ADOPT_ON_SIGNUP=1 has no effect without EPDS_TEE_REPO_SIGNING=1',
    )
  }

  if (walletEnabled) {
    const verifyUserDid =
      opts.userDidVerifier ?? createUserDidVerifier(pds, logger)
    const walletOpts = { signer, verifyUserDid, logger }
    pds.app.use('/wallet', createWalletRouter(walletOpts))
    const walletXrpc = createWalletXrpcRouter(walletOpts)
    let finalized = false
    finalizeApp = () => {
      if (finalized) return
      finalized = true
      // @atproto/pds mounts its own /xrpc catch-all while constructing
      // pds.app. Appending custom NSIDs would therefore never reach us.
      // Wrap the COMPLETE app only now (after all ePDS routes exist):
      // custom wallet XRPC first, untouched stock/ePDS app as fallback.
      const upstream = pds.app
      const gateway = express()
      gateway.use('/xrpc', walletXrpc)
      gateway.use(upstream)
      pds.app = gateway
    }
    logger.info(
      'wallet REST routes mounted at /wallet; app.gainforest.wallet.* XRPC gateway prepared',
    )
  }

  logger.info(
    { signerUrl, repoSigning, adoptOnSignup: adoptOnSignupFlag, walletEnabled },
    'TEE signer integration active',
  )
  return { enabled: true, signer, finalizeApp, adoptOnSignup }
}
