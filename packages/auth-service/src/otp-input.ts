/**
 * Pure helper for deriving HTML input attributes from OTP configuration.
 *
 * Extracted so that both the recovery and account-login routes use identical
 * logic, and so the logic can be unit-tested without rendering or parsing HTML.
 */

export type OtpCharset = 'numeric' | 'alphanumeric'

export interface OtpInputProps {
  pattern: string
  placeholder: string
  inputmode: 'numeric' | 'text'
  autocapitalize: 'characters' | 'off'
}

/** The one-character selection a segmented OTP control should show. */
export interface OtpSelection {
  start: number
  end: number
  direction: 'forward' | 'backward' | 'none'
}

/**
 * Resolve a collapsed browser caret into segmented-field replacement mode.
 *
 * A caret at the end of a partial code remains collapsed so typing appends.
 * Elsewhere the character beside the caret is selected so arrow-key edits
 * replace one slot instead of inserting and shifting the remaining code.
 */
export function resolveOtpSelection(
  valueLength: number,
  otpLength: number,
  start: number | null,
  end: number | null,
  previousStart: number | null,
  previousEnd: number | null,
): OtpSelection | null {
  if (valueLength === 0 || start === null || end === null || start !== end) {
    return null
  }

  const isInsertionAtEnd = start === valueLength && valueLength < otpLength
  if (isInsertionAtEnd) return null

  if (start === 0) {
    return { start: 0, end: 1, direction: 'forward' }
  }
  if (start === valueLength) {
    return { start: start - 1, end: start, direction: 'backward' }
  }

  const movingBackward = previousEnd !== null && start < previousEnd
  const wasInserting =
    previousStart === previousEnd &&
    previousStart !== null &&
    previousStart < otpLength
  const nextStart = movingBackward && !wasInserting ? start - 1 : start

  return {
    start: nextStart,
    end: nextStart + 1,
    direction: movingBackward ? 'backward' : 'forward',
  }
}

/**
 * Normalize a value entered or pasted into the sign-in code field.
 *
 * Use this before rendering or submitting a code so mobile autofill, pasted
 * whitespace, and unsupported characters cannot produce a value outside the
 * configured length and character set.
 */
export function normalizeOtpValue(
  value: string,
  otpLength: number,
  otpCharset: 'numeric' | 'alphanumeric',
): string {
  const compactValue = value.replace(/\s/g, '')
  const allowedValue =
    otpCharset === 'alphanumeric'
      ? compactValue.toUpperCase().replace(/[^A-Z0-9]/g, '')
      : compactValue.replace(/\D/g, '')

  return allowedValue.slice(0, otpLength)
}

export function buildOtpInputProps(
  otpLength: number,
  otpCharset: OtpCharset,
): OtpInputProps {
  if (otpCharset === 'alphanumeric') {
    return {
      pattern: `[A-Z0-9]{${otpLength}}`,
      placeholder: 'X'.repeat(otpLength),
      inputmode: 'text',
      autocapitalize: 'characters',
    }
  }
  return {
    pattern: `[0-9]{${otpLength}}`,
    placeholder: '0'.repeat(otpLength),
    inputmode: 'numeric',
    autocapitalize: 'off',
  }
}

/** Build the character-removal pattern shared by server-rendered OTP inputs. */
export function buildOtpInputFilter(otpCharset: OtpCharset): RegExp {
  return otpCharset === 'alphanumeric' ? /[^A-Za-z0-9]/g : /\D/g
}

/** Accept a supported preview override, otherwise preserve the configured policy. */
export function resolvePreviewOtpCharset(
  requested: string | undefined,
  configured: OtpCharset,
): OtpCharset {
  return requested === 'numeric' || requested === 'alphanumeric'
    ? requested
    : configured
}
