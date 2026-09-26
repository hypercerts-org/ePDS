import {
  baseNormalizeAndValidate,
  ensureHandleServiceConstraints,
} from '@atproto/pds/dist/handle/index.js'

type HandleConstraintError = {
  customErrorName?: unknown
}

/**
 * Return whether upstream rejects a service handle specifically because its
 * local part is reserved. Other validation failures and unexpected errors are
 * rethrown so callers do not silently misclassify them as an availability hit.
 */
export function isReservedServiceHandle(
  fullHandle: string,
  serviceHandleDomains: string[],
): boolean {
  try {
    const normalized = baseNormalizeAndValidate(fullHandle)
    ensureHandleServiceConstraints(normalized, serviceHandleDomains)
    return false
  } catch (err: unknown) {
    if (
      typeof err === 'object' &&
      err !== null &&
      (err as HandleConstraintError).customErrorName === 'HandleNotAvailable'
    ) {
      return true
    }
    throw err
  }
}
