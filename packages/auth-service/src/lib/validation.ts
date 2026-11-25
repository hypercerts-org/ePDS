/** Treat non-string values from request parsers as absent, without coercion. */
export function asRequestString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

// Keep the existing format rules. After the first domain character, stop at
// the first dot so the matcher never retries different domain/suffix splits.
const EMAIL_FORMAT = /^[^\s@]+@[^\s@][^.\s@]*\.[^\s@]+$/

export function hasEmailFormat(email: string): boolean {
  return EMAIL_FORMAT.test(email)
}
