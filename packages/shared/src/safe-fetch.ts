/**
 * SSRF-hardened fetch utility.
 *
 * Thin wrapper around @atproto-labs/fetch-node's safeFetchWrap, which
 * provides proper DNS-level SSRF protection via a custom undici dispatcher
 * (no TOCTOU race between DNS resolution and connection).
 */

import { safeFetchWrap } from '@atproto-labs/fetch-node'

export type SafeFetchOptions = {
  /** Request timeout in milliseconds. Default: 5_000 */
  timeoutMs?: number
  /** Maximum allowed response body in bytes. Default: 100_000 (100 KB) */
  maxBodyBytes?: number
  /**
   * Allow requests to private/loopback IP ranges. Default: false.
   *
   * **Production default is false** — SSRF protection should not be
   * disabled on internet-facing deployments. The opt-out exists purely
   * so local docker-compose e2e runs can exercise flows where services
   * talk to each other via their public hostnames that resolve (on the
   * compose network) to private docker IPs. Plumbed via the
   * `EPDS_ALLOW_PRIVATE_IPS` env var in the auth-service factory.
   */
  allowPrivateIps?: boolean
}

/**
 * Returns an SSRF-hardened fetch function.
 *
 * @example
 * const safeFetch = makeSafeFetch({ timeoutMs: 5_000, maxBodyBytes: 100_000 })
 * const res = await safeFetch('https://example.com/data.json')
 */
export function makeSafeFetch(options: SafeFetchOptions = {}) {
  const {
    timeoutMs = 5_000,
    maxBodyBytes = 100_000,
    allowPrivateIps = false,
  } = options

  const wrappedFetch = safeFetchWrap({
    timeout: timeoutMs,
    responseMaxSize: maxBodyBytes,
    allowHttp: allowPrivateIps,
    allowPrivateIps,
    allowImplicitRedirect: false,
  })

  return async function safeFetch(
    url: string,
    init?: RequestInit,
  ): Promise<Response> {
    return wrappedFetch(url, { ...init, redirect: 'error' })
  }
}
