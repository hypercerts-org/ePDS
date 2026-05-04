/**
 * Translate a recovery-session email (a verified backup email) into the
 * corresponding primary account email + DID.
 *
 * /auth/complete receives the session's verified email and normally looks
 * it up directly via pds-core's account-by-email endpoint. Recovery flows
 * break that assumption: the session holds the user's backup email, which
 * pds-core does not index. This helper closes the gap by consulting the
 * auth-service-owned backup_email table (DID lookup) and then resolving
 * the DID back to its primary email via the existing
 * /_internal/account-by-handle endpoint.
 *
 * Returns `{ email, did }` with the primary email and DID when translation
 * succeeds, or `null` when the input email is not a registered backup or
 * the primary email cannot be resolved — the caller then treats the
 * session as new-account.
 */
import type { AuthServiceContext } from '../context.js'
import { resolveLoginHint } from './resolve-login-hint.js'

export async function resolveRecoveryEmail(
  backupEmail: string,
  ctx: AuthServiceContext,
  pdsUrl: string,
  internalSecret: string,
): Promise<{ email: string; did: string } | null> {
  const did = ctx.db.getDidByBackupEmail(backupEmail)
  if (!did) return null
  const primaryEmail = await resolveLoginHint(did, pdsUrl, internalSecret)
  if (!primaryEmail) return null
  return { email: primaryEmail.toLowerCase(), did }
}
