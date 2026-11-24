/** Treat non-string values from request parsers as absent, without coercion. */
export function asRequestString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}
