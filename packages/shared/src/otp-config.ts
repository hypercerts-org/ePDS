/**
 * OTP configuration — reads OTP_LENGTH and OTP_FORMAT from env vars.
 *
 * Provides:
 * - `otpConfig`: resolved config object (length, format, character set)
 * - `generateOtp()`: custom OTP generator for better-auth's `generateOTP` callback
 * - `otpHtmlAttrs()`: HTML input attributes matching the configured format
 * - `otpDescriptionText()`: human-readable description (e.g. "6-digit code")
 */
import * as crypto from 'node:crypto'

export type OtpFormat = 'numeric' | 'alphanumeric'

export interface OtpConfig {
  length: number
  format: OtpFormat
}

/**
 * Uppercase alphanumeric alphabet excluding ambiguous characters:
 * 0/O (zero vs. letter O) and 1/I (one vs. letter I).
 */
const ALPHANUMERIC_CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'

/** Read and validate OTP config from environment variables. */
function resolveOtpConfig(): OtpConfig {
  const rawLength = process.env.OTP_LENGTH
  const length = rawLength ? parseInt(rawLength, 10) : 6
  if (isNaN(length) || length < 4 || length > 12) {
    throw new Error(
      `OTP_LENGTH must be an integer between 4 and 12, got: ${rawLength}`,
    )
  }

  const rawFormat = process.env.OTP_FORMAT ?? 'numeric'
  if (rawFormat !== 'numeric' && rawFormat !== 'alphanumeric') {
    throw new Error(
      `OTP_FORMAT must be 'numeric' or 'alphanumeric', got: ${rawFormat}`,
    )
  }

  return { length, format: rawFormat }
}

/** Resolved OTP configuration (read once at import time). */
export const otpConfig: OtpConfig = resolveOtpConfig()

/**
 * Generate a cryptographically secure OTP code.
 *
 * For numeric: uniform random digits via crypto.randomInt.
 * For alphanumeric: rejection-sampled from ALPHANUMERIC_CHARS (31 chars,
 * not a power of 2, so we reject to avoid modulo bias).
 */
export function generateOtp(): string {
  if (otpConfig.format === 'numeric') {
    const max = 10 ** otpConfig.length
    const num = crypto.randomInt(0, max)
    return num.toString().padStart(otpConfig.length, '0')
  }

  // Alphanumeric: rejection sampling to avoid modulo bias
  const chars = ALPHANUMERIC_CHARS
  const result: string[] = []
  for (let i = 0; i < otpConfig.length; i++) {
    // randomInt gives uniform [0, chars.length)
    result.push(chars[crypto.randomInt(0, chars.length)])
  }
  return result.join('')
}

/**
 * HTML input attributes for the OTP input field, matching the configured format.
 *
 * Returns an object with maxlength, pattern, inputmode, and placeholder
 * suitable for spreading into an HTML template.
 */
export function otpHtmlAttrs(): {
  maxlength: number
  pattern: string
  inputmode: string
  placeholder: string
} {
  const { length, format } = otpConfig
  if (format === 'numeric') {
    return {
      maxlength: length,
      pattern: `[0-9]{${length}}`,
      inputmode: 'numeric',
      placeholder: '0'.repeat(length),
    }
  }
  // Alphanumeric: accept uppercase letters (excluding ambiguous) and digits (excluding 0, 1)
  return {
    maxlength: length,
    pattern: `[2-9A-HJ-NP-Z]{${length}}`,
    inputmode: 'text',
    placeholder: 'X'.repeat(length),
  }
}

/**
 * Human-readable description of the OTP code for UI text.
 * e.g. "6-digit code" or "6-character code"
 */
export function otpDescriptionText(): string {
  const { length, format } = otpConfig
  const unit = format === 'numeric' ? 'digit' : 'character'
  return `${length}-${unit} code`
}
