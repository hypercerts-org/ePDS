/**
 * Pure helper for deriving HTML input attributes from OTP configuration.
 *
 * Extracted so that both the recovery and account-login routes use identical
 * logic, and so the logic can be unit-tested without rendering or parsing HTML.
 */

export interface OtpInputProps {
  pattern: string
  placeholder: string
  inputmode: 'numeric' | 'text'
  autocapitalize: 'characters' | 'off'
}

export function buildOtpInputProps(
  otpLength: number,
  otpCharset: 'numeric' | 'alphanumeric',
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
