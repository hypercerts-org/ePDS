import type { AuthServiceContext } from '../context.js'
import { createLogger, generateRandomHandle } from '@certified-app/shared'

const logger = createLogger('auth:auto-provision')

/**
 * Auto-provision a new PDS account for the given email.
 * Generates a random handle, calls the PDS createAccount API (passwordless),
 * and registers the email->DID mapping in the auth DB.
 *
 * Returns the new DID on success, or null on failure.
 */
export async function autoProvisionAccount(
  ctx: AuthServiceContext,
  email: string,
): Promise<string | null> {
  // Use internal Docker URL to avoid going through Caddy
  const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl

  const handle = generateRandomHandle(ctx.config.pdsHostname)

  try {
    const res = await fetch(`${pdsUrl}/xrpc/com.atproto.server.createAccount`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // No password — creates a passwordless account that cannot be used with
      // createSession. The XRPC lexicon accepts password as optional.
      body: JSON.stringify({ email, handle }),
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      logger.error({ status: res.status, err }, 'PDS createAccount failed')
      return null
    }

    const data = (await res.json()) as { did: string; handle: string }
    logger.info(
      { did: data.did, handle: data.handle, email },
      'Auto-provisioned new account',
    )

    return data.did
  } catch (err) {
    logger.error({ err }, 'Failed to call PDS createAccount')
    return null
  }
}
