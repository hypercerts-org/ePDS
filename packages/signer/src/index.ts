/**
 * ePDS signer entry point.
 *
 * IMPORTANT deployment note: this service holds the root seed. It must
 * run on confidential-compute hardware (dstack on TDX/SEV-SNP, a cloud
 * confidential VM, or Phala) in any real deployment — never on the same
 * trust domain as the PDS operator's ordinary infrastructure (and never
 * on platforms like Railway, where the platform IS the host the TEE is
 * meant to lock out). Plain-process mode exists for development only.
 *
 * See docs/design/tee-signer.md for the architecture and threat model.
 */
import * as dotenv from 'dotenv'
dotenv.config()

import * as path from 'node:path'
import * as fs from 'node:fs'
import { createLogger } from '@certified-app/shared'
import { loadRootSeed } from './root-seed.js'
import { createSignerApp } from './service.js'
import { SignerStore } from './store.js'

const logger = createLogger('epds-signer')

function main(): void {
  const port = parseInt(process.env.SIGNER_PORT || '3010', 10)
  const dataDir = process.env.SIGNER_DATA_DIR || './data/signer'
  const internalSecret = process.env.SIGNER_INTERNAL_SECRET || ''

  if (!internalSecret) {
    throw new Error('SIGNER_INTERNAL_SECRET must be set')
  }

  const rootSeed = loadRootSeed({
    SIGNER_ROOT_SEED_HEX: process.env.SIGNER_ROOT_SEED_HEX,
    SIGNER_ROOT_SEED_FILE:
      process.env.SIGNER_ROOT_SEED_FILE || path.join(dataDir, 'root-seed'),
    SIGNER_ALLOW_DEV_SEED: process.env.SIGNER_ALLOW_DEV_SEED,
  })

  fs.mkdirSync(dataDir, { recursive: true })
  const store = new SignerStore(path.join(dataDir, 'signer.sqlite'))

  const app = createSignerApp({
    rootSeed,
    store,
    internalSecret,
    freshnessSec: process.env.SIGNER_WALLET_FRESHNESS_SEC
      ? parseInt(process.env.SIGNER_WALLET_FRESHNESS_SEC, 10)
      : undefined,
    dstackSockPath: process.env.SIGNER_DSTACK_SOCK,
  })

  const server = app.listen(port, () => {
    logger.info({ port }, 'ePDS signer running')
  })

  const shutdown = () => {
    logger.info('ePDS signer shutting down')
    server.close(() => {
      store.close()
      process.exit(0)
    })
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

try {
  main()
} catch (err) {
  logger.fatal({ err }, 'Failed to start ePDS signer')
  process.exit(1)
}
