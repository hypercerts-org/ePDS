/**
 * Shared utility helpers for step definitions.
 */

import type { EpdsWorld } from './world.js'
import { testEnv } from './env.js'

/**
 * Returns the Playwright Page from the world, throwing a clear error if
 * it has not been initialised. Use this in every step that needs the page
 * instead of non-null asserting `world.page!`.
 */
export function getPage(world: EpdsWorld) {
  const page = world.page
  if (!page) throw new Error('page is not initialised')
  return page
}

/**
 * Makes an HTTP call to a /_internal/* endpoint on pds-core.
 *
 * - Pass `secret` as a string to include the x-internal-secret header.
 * - Pass `null` to omit the header entirely (for testing missing-secret scenarios).
 * - Safely handles non-JSON responses (e.g. 502 proxy errors) by falling back
 *   to `{ raw: <text> }` rather than throwing a SyntaxError.
 */
export async function callInternalApi(
  path: string,
  secret: string | null,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (secret !== null) {
    headers['x-internal-secret'] = secret
  }
  const res = await fetch(`${testEnv.pdsUrl}${path}`, { headers })
  let body: Record<string, unknown>
  try {
    body = (await res.json()) as Record<string, unknown>
  } catch {
    const raw = await res.text().catch(() => '<unreadable>')
    body = { raw }
  }
  return { status: res.status, body }
}
