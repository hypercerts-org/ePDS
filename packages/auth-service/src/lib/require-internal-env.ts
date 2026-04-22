import { ensurePdsUrl } from './pds-url.js'

/**
 * Validate that PDS_INTERNAL_URL and EPDS_INTERNAL_SECRET are set,
 * and that PDS_INTERNAL_URL includes an http(s) scheme.
 *
 * Called at router-creation time so the process fails fast at startup
 * rather than at first request.  The error message names exactly which
 * variable(s) are missing or malformed.
 */
export function requireInternalEnv(): {
  pdsUrl: string
  internalSecret: string
} {
  const internalSecret = process.env.EPDS_INTERNAL_SECRET
  if (!internalSecret) {
    throw new Error('EPDS_INTERNAL_SECRET must be set')
  }
  return { pdsUrl: ensurePdsUrl(process.env.PDS_INTERNAL_URL), internalSecret }
}
