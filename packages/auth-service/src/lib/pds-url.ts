/**
 * Validates and returns the internal PDS URL.
 *
 * Ensures the URL includes an HTTP(S) scheme — a missing scheme causes
 * `fetch()` to throw `TypeError: Invalid URL` at runtime, which is hard
 * to diagnose in production (see: Railway prod incident with
 * `certified-apppds-core.railway.internal/…`).
 */
export function ensurePdsUrl(
  raw: string | undefined,
  fallback?: string,
): string {
  const url = raw || fallback
  if (!url) {
    throw new Error(
      'PDS_INTERNAL_URL is not set and no fallback URL was provided',
    )
  }

  if (!/^https?:\/\//i.test(url)) {
    throw new Error(
      `PDS_INTERNAL_URL is missing the http:// or https:// scheme: "${url}"`,
    )
  }

  // Strip trailing slash for consistent concatenation
  return url.replace(/\/+$/, '')
}
