import type { Logger } from 'pino'

import type { ClientMetadata } from '@certified-app/shared'

/** Dependencies needed to resolve trusted-client CSS for callback fallback pages. */
export type TrustedCallbackCssOptions = {
  clientId: string | undefined
  trustedClients: string[]
  resolveClientMetadata: (clientId: string) => Promise<ClientMetadata>
  getClientCss: (
    clientId: string,
    metadata: ClientMetadata,
    trustedClients: string[],
  ) => string | null
  logger: Pick<Logger, 'warn' | 'debug'>
}

/**
 * Resolves trusted-client CSS for /oauth/epds-callback fallback pages.
 *
 * Use this only after the callback flow has established the client ID from
 * signed state. Trust is exact PDS_OAUTH_TRUSTED_CLIENTS membership; the helper
 * intentionally avoids URL, origin, prefix, or hostname matching.
 */
export async function resolveTrustedCallbackCss({
  clientId,
  trustedClients,
  resolveClientMetadata,
  getClientCss,
  logger,
}: TrustedCallbackCssOptions): Promise<string | null> {
  if (!clientId || !trustedClients.includes(clientId)) {
    return null
  }

  try {
    const metadata = await resolveClientMetadata(clientId)
    return getClientCss(clientId, metadata, trustedClients)
  } catch (err) {
    logger.warn(
      { err, clientId },
      'ePDS callback branding: failed to resolve trusted client CSS',
    )
    return null
  }
}
