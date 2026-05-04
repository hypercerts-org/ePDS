/**
 * Auth-service client for pds-core's `/_internal/device-accounts`
 * endpoint. Auth-service uses this to enumerate the emails bound to a
 * (dev-id, ses-id) cookie pair so it can decide whether a Flow 1
 * `login_hint` matches an existing device session, and therefore
 * whether the chooser is the right next step.
 *
 * Returns:
 *   - `string[]` — lowercased emails of every bound account (may be
 *     empty if the device has no bindings yet).
 *   - `null` — pds-core could not validate the cookie pair (malformed,
 *     unknown, or stale), or the call failed entirely. Callers should
 *     treat this as "no usable session" and bypass session reuse.
 *
 * Errors are swallowed and logged: a transient pds-core blip should
 * degrade Flow 1 to the email/OTP form rather than 500 the whole
 * authorize request.
 */
import { createLogger } from '@certified-app/shared'

const logger = createLogger('auth:fetch-device-accounts')

const DEVICE_ACCOUNTS_TIMEOUT_MS = 3000

export async function fetchDeviceAccountEmails(
  pdsInternalUrl: string,
  devId: string,
  sesId: string,
  internalSecret: string,
): Promise<string[] | null> {
  if (!devId || !sesId) return null
  try {
    const url =
      `${pdsInternalUrl}/_internal/device-accounts` +
      `?dev_id=${encodeURIComponent(devId)}` +
      `&ses_id=${encodeURIComponent(sesId)}`
    const res = await fetch(url, {
      headers: { 'x-internal-secret': internalSecret },
      signal: AbortSignal.timeout(DEVICE_ACCOUNTS_TIMEOUT_MS),
    })
    if (!res.ok) {
      logger.warn(
        { status: res.status },
        'pds-core /_internal/device-accounts returned non-2xx',
      )
      return null
    }
    const data = (await res.json()) as { emails: string[] | null }
    return data.emails ?? null
  } catch (err) {
    logger.warn({ err }, 'Failed to fetch device-bound account emails')
    return null
  }
}
