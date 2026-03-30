/**
 * Shared utility helpers for step definitions.
 */

import type { EpdsWorld } from './world.js'

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
