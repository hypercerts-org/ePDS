/**
 * Tests for buildOtpInputProps — derives HTML input attributes from OTP config.
 *
 * Covers:
 * 1. Correct pattern and placeholder for numeric charset
 * 2. Correct pattern and placeholder for alphanumeric charset
 * 3. Pattern and placeholder length match the requested otpLength
 * 4. Numeric pattern rejects letters
 * 5. Alphanumeric pattern accepts both letters and digits
 */
import { describe, it, expect } from 'vitest'
import { buildOtpInputProps } from '../otp-input.js'

describe('Recovery flow: OTP input props', () => {
  it('numeric charset produces digit-only pattern and zero placeholder', () => {
    const props = buildOtpInputProps(8, 'numeric')
    expect(props.pattern).toBe('[0-9]{8}')
    expect(props.placeholder).toBe('00000000')
    expect(props.inputmode).toBe('numeric')
    expect(props.autocapitalize).toBe('off')
  })

  it('alphanumeric charset produces alphanumeric pattern and X placeholder', () => {
    const props = buildOtpInputProps(8, 'alphanumeric')
    expect(props.pattern).toBe('[A-Z0-9]{8}')
    expect(props.placeholder).toBe('XXXXXXXX')
    expect(props.inputmode).toBe('text')
    expect(props.autocapitalize).toBe('characters')
  })

  it('pattern and placeholder length match otpLength', () => {
    const numeric = buildOtpInputProps(6, 'numeric')
    expect(numeric.pattern).toBe('[0-9]{6}')
    expect(numeric.placeholder).toHaveLength(6)
    const numericRe = new RegExp(`^${numeric.pattern}$`)
    expect(numericRe.test('123456')).toBe(true)
    expect(numericRe.test('12345')).toBe(false) // too short
    expect(numericRe.test('1234567')).toBe(false) // too long

    const alpha = buildOtpInputProps(6, 'alphanumeric')
    expect(alpha.pattern).toBe('[A-Z0-9]{6}')
    expect(alpha.placeholder).toHaveLength(6)
    const alphaRe = new RegExp(`^${alpha.pattern}$`)
    expect(alphaRe.test('A1B2C3')).toBe(true)
    expect(alphaRe.test('A1B2C')).toBe(false) // too short
    expect(alphaRe.test('A1B2C3D')).toBe(false) // too long
  })

  it('numeric pattern does not accept letters', () => {
    const { pattern } = buildOtpInputProps(8, 'numeric')
    const re = new RegExp(`^${pattern}$`)
    expect(re.test('12345678')).toBe(true)
    expect(re.test('1234567A')).toBe(false)
  })

  it('alphanumeric pattern accepts both letters and digits', () => {
    const { pattern } = buildOtpInputProps(8, 'alphanumeric')
    const re = new RegExp(`^${pattern}$`)
    expect(re.test('A1B2C3D4')).toBe(true)
    expect(re.test('12345678')).toBe(true)
    expect(re.test('ABCDEFGH')).toBe(true)
    expect(re.test('abcdefgh')).toBe(false) // lowercase rejected
    expect(re.test('A1B2C3D')).toBe(false) // one short
  })
})
