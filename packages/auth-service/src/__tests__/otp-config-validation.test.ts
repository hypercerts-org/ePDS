import { describe, expect, it } from 'vitest'
import {
  validateOtpCharset,
  validateOtpLength,
} from '../lib/otp-config-validation.js'

describe('validateOtpLength', () => {
  it('accepts the minimum length 4', () => {
    expect(validateOtpLength(4, '4')).toBe(4)
  })

  it('accepts the maximum length 12', () => {
    expect(validateOtpLength(12, '12')).toBe(12)
  })

  it('accepts a typical default length 8', () => {
    expect(validateOtpLength(8, '8')).toBe(8)
  })

  it('rejects values below 4', () => {
    expect(() => validateOtpLength(3, '3')).toThrow(
      /Invalid OTP_LENGTH: must be between 4 and 12, got "3"/,
    )
    expect(() => validateOtpLength(0, '0')).toThrow()
  })

  it('rejects values above 12', () => {
    expect(() => validateOtpLength(13, '13')).toThrow(
      /Invalid OTP_LENGTH: must be between 4 and 12, got "13"/,
    )
    expect(() => validateOtpLength(100, '100')).toThrow()
  })

  it('rejects NaN (when the env var is non-numeric)', () => {
    expect(() => validateOtpLength(NaN, 'banana')).toThrow(
      /Invalid OTP_LENGTH: must be between 4 and 12, got "banana"/,
    )
  })

  it('includes the raw input in the error message', () => {
    // The error must surface the original env-var value so operators
    // can see exactly what they had set without grepping for it.
    try {
      validateOtpLength(99, '99')
      expect.fail('expected throw')
    } catch (err) {
      expect((err as Error).message).toContain('"99"')
    }
  })
})

describe('validateOtpCharset', () => {
  it('accepts "numeric"', () => {
    expect(validateOtpCharset('numeric')).toBe('numeric')
  })

  it('accepts "alphanumeric"', () => {
    expect(validateOtpCharset('alphanumeric')).toBe('alphanumeric')
  })

  it('rejects unknown charsets', () => {
    expect(() => validateOtpCharset('hex')).toThrow(
      /Invalid OTP_CHARSET: must be 'numeric' or 'alphanumeric', got "hex"/,
    )
  })

  it('rejects empty string', () => {
    expect(() => validateOtpCharset('')).toThrow()
  })

  it('rejects case variations (case-sensitive match)', () => {
    expect(() => validateOtpCharset('Numeric')).toThrow()
    expect(() => validateOtpCharset('NUMERIC')).toThrow()
  })

  it('returns the value narrowed to the OtpCharset literal type', () => {
    // Type-level: assignment compiles only because the return type is
    // 'numeric' | 'alphanumeric'. Runtime assertion mirrors that.
    const result: 'numeric' | 'alphanumeric' = validateOtpCharset('numeric')
    expect(result).toBe('numeric')
  })
})
