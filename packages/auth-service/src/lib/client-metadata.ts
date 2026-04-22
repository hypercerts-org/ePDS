/**
 * Re-exports client metadata utilities from @certified-app/shared.
 *
 * The implementation was moved to the shared package so that pds-core can
 * also resolve custom ePDS metadata fields (e.g. epds_skip_consent_on_signup).
 * Auth-service imports are preserved for backwards compatibility.
 */
import {
  resolveClientMetadata,
  resolveClientName,
  getClientCss,
  createLogger,
} from '@certified-app/shared'
import type { ClientMetadata } from '@certified-app/shared'

export {
  resolveClientMetadata,
  resolveClientName,
  escapeCss,
  getClientCss,
  clearClientMetadataCache,
} from '@certified-app/shared'
export type { ClientMetadata, ClientBranding } from '@certified-app/shared'

const logger = createLogger('auth:client-metadata')

/**
 * Best-effort branding resolution. Returns safe defaults on any error so that
 * a transient metadata fetch failure never breaks a page render.
 *
 * In practice resolveClientMetadata/resolveClientName never throw (they catch
 * internally), but this wrapper makes that resilience explicit at the call site
 * and guards against future regressions.
 *
 * The catch branch is intentional belt-and-suspenders — it is not currently
 * reachable in normal operation.
 */
export async function resolveClientBranding(
  clientId: string,
  trustedClients: string[],
): Promise<{
  clientMeta: ClientMetadata
  clientName: string
  customCss: string | null
}> {
  try {
    const clientMeta = await resolveClientMetadata(clientId)
    const clientName =
      clientMeta.client_name || (await resolveClientName(clientId))
    const customCss = getClientCss(clientId, clientMeta, trustedClients)
    logger.debug(
      { clientId, trusted: customCss !== null },
      'client CSS trust check',
    )
    return { clientMeta, clientName, customCss }
  } catch (err) {
    logger.warn(
      { err, clientId },
      'Failed to resolve client branding, using defaults',
    )
    return { clientMeta: {}, clientName: 'the application', customCss: null }
  }
}
