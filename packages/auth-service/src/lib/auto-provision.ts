import * as crypto from 'node:crypto'
import type { AuthServiceContext } from '../context.js'
import { createLogger } from '@magic-pds/shared'

const logger = createLogger('auth:auto-provision')

/**
 * Auto-provision a new PDS account for the given email.
 * Generates a random handle and password, calls the PDS createAccount API,
 * and registers the email->DID mapping in the auth DB.
 *
 * Returns the new DID on success, or null on failure.
 */
export async function autoProvisionAccount(ctx: AuthServiceContext, email: string): Promise<string | null> {
  // Use internal Docker URL to avoid going through Caddy
  const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl

  const localPart = (email.split('@')[0]?.replace(/[^a-zA-Z0-9]/g, '') || 'user').slice(0, 11).toLowerCase()
  const suffix = crypto.randomBytes(3).toString('hex')
  const handle = `${localPart}-${suffix}.${ctx.config.pdsHostname}`

  const password = crypto.randomBytes(32).toString('hex')

  try {
    const res = await fetch(`${pdsUrl}/xrpc/com.atproto.server.createAccount`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, handle, password }),
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      logger.error({ status: res.status, err }, 'PDS createAccount failed')
      return null
    }

    const data = await res.json() as { did: string; handle: string }
    logger.info({ did: data.did, handle: data.handle, email }, 'Auto-provisioned new account')

    ctx.db.setAccountEmail(email, data.did)

    return data.did
  } catch (err) {
    logger.error({ err }, 'Failed to call PDS createAccount')
    return null
  }
}
