/**
 * Handle validation utilities for ePDS.
 *
 * Provides validateLocalPart() which combines atproto spec validation
 * (normalizeAndEnsureValidHandle) with product-level constraints on the
 * local segment of a hosted handle (no dots, 5–20 chars).
 *
 * Used by both auth-service (primary validation on user input) and
 * pds-core (defense-in-depth re-check at the epds-callback trust boundary).
 */
import {
  normalizeAndEnsureValidHandle,
  InvalidHandleError,
} from '@atproto/syntax'

/** Minimum length for the local part of a hosted handle (product constraint). */
export const LOCAL_PART_MIN = 5

/** Maximum length for the local part of a hosted handle (product constraint). */
export const LOCAL_PART_MAX = 20

/**
 * Validates and normalizes the local part of a handle against the atproto spec
 * and product-level constraints.
 *
 * Composes the full handle (`localPart.handleDomain`), runs
 * normalizeAndEnsureValidHandle (spec validation + ASCII lowercasing), then
 * strips the domain back off and applies product constraints:
 *   - No dots in the local part (single-label only)
 *   - Length between LOCAL_PART_MIN and LOCAL_PART_MAX (inclusive)
 *
 * Returns the normalized local part on success, or null if invalid.
 */
export function validateLocalPart(
  localPart: string,
  handleDomain: string,
): string | null {
  const fullHandle = `${localPart}.${handleDomain}`
  let normalized: string
  try {
    normalized = normalizeAndEnsureValidHandle(fullHandle)
  } catch (err) {
    if (err instanceof InvalidHandleError) return null
    throw err
  }
  const normalizedLocal = normalized.slice(
    0,
    normalized.length - handleDomain.length - 1,
  )
  if (
    normalizedLocal.includes('.') ||
    normalizedLocal.length < LOCAL_PART_MIN ||
    normalizedLocal.length > LOCAL_PART_MAX
  ) {
    return null
  }
  return normalizedLocal
}

/** Valid handle assignment modes for the OAuth signup flow. */
export const VALID_HANDLE_MODES = [
  'random',
  'picker',
  'picker-with-random',
] as const
export type HandleMode = (typeof VALID_HANDLE_MODES)[number]

/**
 * Resolve the handle assignment mode for an OAuth flow using the three-level
 * precedence shared between auth-service (signup page) and pds-core (chooser
 * enrichment):
 *
 *   1. explicit `epds_handle_mode` query-string value on the authorize URL,
 *   2. the client metadata's `epds_handle_mode`,
 *   3. the `EPDS_DEFAULT_HANDLE_MODE` env var,
 *   4. `'picker-with-random'` as the final fallback.
 *
 * Exported from shared so both services resolve identically — otherwise the
 * signup form and the chooser can disagree about whether to hide the handle.
 *
 * Invalid values at any level are silently skipped rather than erroring: the
 * OAuth flow must not 500 because a client shipped a typo'd value.
 */
export function resolveHandleMode(
  queryParam: string | undefined,
  clientMetaHandleMode: string | undefined,
  envDefault: string | undefined = process.env.EPDS_DEFAULT_HANDLE_MODE,
): HandleMode {
  for (const raw of [queryParam, clientMetaHandleMode, envDefault]) {
    if (raw && (VALID_HANDLE_MODES as readonly string[]).includes(raw)) {
      return raw as HandleMode
    }
  }
  return 'picker-with-random'
}
