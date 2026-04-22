/**
 * Ping a pending PAR request_uri to reset the atproto inactivity timer.
 *
 * Calls pds-core's /_internal/ping-request endpoint. atproto's
 * AUTHORIZATION_INACTIVITY_TIMEOUT is 5 minutes — callers invoke this
 * before redirecting to epds-callback so users who spend time on
 * intermediate pages (handle picker, etc.) don't hit "This request has
 * expired" inside pds-core after account creation.
 *
 * Returns a plain result object rather than throwing or logging so each
 * call site can decide whether the failure is fatal or non-fatal and
 * supply its own context-specific log message.
 */

export type PingParResult =
  | { ok: true }
  | { ok: false; status?: number; err?: unknown }

export async function pingParRequest(
  requestUri: string,
  pdsUrl: string,
  internalSecret: string,
): Promise<PingParResult> {
  try {
    const res = await fetch(
      `${pdsUrl}/_internal/ping-request?request_uri=${encodeURIComponent(requestUri)}`,
      {
        headers: { 'x-internal-secret': internalSecret },
        signal: AbortSignal.timeout(3000),
      },
    )
    if (!res.ok) {
      return { ok: false, status: res.status }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, err }
  }
}
