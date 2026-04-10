/**
 * Pure validation helpers for the auth-service OTP configuration. The
 * entry-point reads `OTP_LENGTH` and `OTP_CHARSET` from environment
 * variables and rejects malformed values at startup. Extracting the
 * validation lets us unit-test the boundary conditions (4–12 length,
 * numeric vs alphanumeric charset) without booting an Express app.
 */

export type OtpCharset = 'numeric' | 'alphanumeric'

const VALID_CHARSETS: readonly string[] = ['numeric', 'alphanumeric']

/**
 * Validate the parsed OTP_LENGTH value. Allowed range is [4, 12]
 * inclusive — anything outside (or NaN) throws a descriptive Error
 * including the original env-var input so operators can diagnose
 * misconfiguration quickly.
 */
export function validateOtpLength(
  value: number,
  rawInput: string | undefined,
): number {
  if (isNaN(value) || value < 4 || value > 12) {
    throw new Error(
      `Invalid OTP_LENGTH: must be between 4 and 12, got "${rawInput}"`,
    )
  }
  return value
}

/**
 * Validate the OTP_CHARSET value. Returns the value narrowed to
 * `OtpCharset` if it's one of the two allowed strings, or throws a
 * descriptive Error if not.
 */
export function validateOtpCharset(value: string): OtpCharset {
  if (!VALID_CHARSETS.includes(value)) {
    throw new Error(
      `Invalid OTP_CHARSET: must be 'numeric' or 'alphanumeric', got "${value}"`,
    )
  }
  return value as OtpCharset
}
