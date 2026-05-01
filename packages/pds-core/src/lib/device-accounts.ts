/**
 * Device-bound account lookup shared between auth-ui-guard and the
 * /_internal/device-accounts endpoint.
 *
 * Validates a (dev-id, ses-id) cookie pair against the live device row,
 * then asks `accountManager.listDeviceAccounts` for the bindings.
 *
 * "Validation fails" means: either id is syntactically malformed, the
 * device row is missing, the device row's active sessionId does not match
 * the supplied ses-id, or any underlying call throws. In every miss we
 * return null — never partial data — so callers don't accidentally trust
 * a stale half-state.
 */
import type {
  DeviceAccount,
  DeviceId,
  OAuthProvider,
} from '@atproto/oauth-provider'
import {
  DEVICE_ID_BYTES_LENGTH,
  DEVICE_ID_PREFIX,
  SESSION_ID_BYTES_LENGTH,
  SESSION_ID_PREFIX,
} from '@atproto/oauth-provider'
import type { Logger } from 'pino'

const DEVICE_ID_RE = new RegExp(
  `^${DEVICE_ID_PREFIX}[0-9a-f]{${DEVICE_ID_BYTES_LENGTH * 2}}$`,
)
const SESSION_ID_RE = new RegExp(
  `^${SESSION_ID_PREFIX}[0-9a-f]{${SESSION_ID_BYTES_LENGTH * 2}}$`,
)

type DeviceStoreLike = {
  readDevice: (deviceId: DeviceId) => Promise<{ sessionId: string } | null>
}

export type LoadDeviceBindingsOpts = {
  provider: OAuthProvider
  deviceId: string
  sessionId: string
  /** Free-form prefix used in error log messages so multiple call sites
   *  remain distinguishable in logs. */
  logCtx: string
  logger?: Partial<Pick<Logger, 'error' | 'debug'>>
}

/** Validate the cookie pair against the device row + return every binding
 *  for the device. Returns null on any miss (malformed ids, missing device
 *  row, ses-id mismatch, underlying error) — never partial data. Both the
 *  guard middleware and the /_internal/device-accounts endpoint use this. */
export async function loadDeviceBindings(
  opts: LoadDeviceBindingsOpts,
): Promise<DeviceAccount[] | null> {
  const { provider, deviceId, sessionId, logCtx, logger } = opts
  if (!DEVICE_ID_RE.test(deviceId)) return null
  if (!SESSION_ID_RE.test(sessionId)) return null

  const deviceStore = (
    provider.deviceManager as unknown as { store: DeviceStoreLike }
  ).store
  try {
    const data = await deviceStore.readDevice(deviceId as DeviceId)
    if (!data || data.sessionId !== sessionId) return null
  } catch (err) {
    logger?.error?.({ err, deviceId }, `${logCtx}: readDevice failed`)
    return null
  }

  try {
    return await provider.accountManager.listDeviceAccounts(
      deviceId as DeviceId,
    )
  } catch (err) {
    logger?.error?.({ err, deviceId }, `${logCtx}: listDeviceAccounts failed`)
    return null
  }
}

export type LoadDeviceAccountEmailsOpts = {
  provider: OAuthProvider
  deviceId: string
  sessionId: string
  logger?: Partial<Pick<Logger, 'error' | 'debug'>>
}

/** Validate the cookie pair and return the lowercased emails of every
 *  account bound to the device, or `null` on any miss.
 *
 *  Lowercases emails to mirror `/_internal/account-by-email`'s normalised
 *  lookup so callers can compare a resolved login_hint email directly. */
export async function loadDeviceAccountEmails(
  opts: LoadDeviceAccountEmailsOpts,
): Promise<string[] | null> {
  const bindings = await loadDeviceBindings({
    ...opts,
    logCtx: 'device-accounts',
  })
  if (!bindings) return null
  return bindings
    .map((b) => b.account.email)
    .filter((e): e is string => typeof e === 'string' && e.length > 0)
    .map((e) => e.toLowerCase())
}
