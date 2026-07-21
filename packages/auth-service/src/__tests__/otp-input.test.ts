/**
 * Tests for the pure OTP input helpers.
 *
 * Covers segmented selection, one-shot mobile paste/autofill normalization,
 * and HTML input attributes derived from the configured OTP format.
 */
import { describe, it, expect } from 'vitest'
import {
  buildOtpInputFilter,
  buildOtpInputProps,
  normalizeOtpValue,
  resolveOtpClickSelection,
  resolveOtpSelection,
  resolvePreviewOtpCharset,
} from '../otp-input.js'

describe('OTP input selection', () => {
  it('leaves empty values and existing selections unchanged', () => {
    expect(resolveOtpSelection(0, 6, 0, 0, 0, 0)).toBeNull()
    expect(resolveOtpSelection(4, 6, 2, 3, 2, 3)).toBeNull()
  })

  it('keeps a collapsed caret at the end of a partial code for appending', () => {
    expect(resolveOtpSelection(4, 6, 4, 4, 4, 4)).toBeNull()
  })

  it('selects the previous slot after moving left from append mode', () => {
    expect(resolveOtpSelection(4, 6, 3, 3, 4, 4)).toEqual({
      start: 3,
      end: 4,
      direction: 'backward',
    })
  })

  it('continues selecting previous slots on repeated left-arrow presses', () => {
    expect(resolveOtpSelection(4, 6, 3, 3, 3, 4)).toEqual({
      start: 2,
      end: 3,
      direction: 'backward',
    })
  })

  it('selects the first slot when the caret moves to the beginning', () => {
    expect(resolveOtpSelection(4, 6, 0, 0, 1, 2)).toEqual({
      start: 0,
      end: 1,
      direction: 'forward',
    })
  })

  it('selects the next slot when moving forward', () => {
    expect(resolveOtpSelection(4, 6, 2, 2, 1, 2)).toEqual({
      start: 2,
      end: 3,
      direction: 'forward',
    })
  })

  it('selects the final slot when a complete code receives focus', () => {
    expect(resolveOtpSelection(6, 6, 6, 6, 6, 6)).toEqual({
      start: 5,
      end: 6,
      direction: 'backward',
    })
  })
})

describe('OTP click selection', () => {
  it('selects the clicked character when the slot is populated', () => {
    expect(resolveOtpClickSelection(4, 2)).toEqual({
      start: 2,
      end: 3,
      direction: 'forward',
    })
  })

  it('places the caret at the end when an empty later slot is clicked', () => {
    expect(resolveOtpClickSelection(4, 6)).toEqual({
      start: 4,
      end: 4,
      direction: 'forward',
    })
  })
})

describe('OTP input value normalization', () => {
  it('accepts a complete numeric code delivered at once', () => {
    expect(normalizeOtpValue('123456', 6, 'numeric')).toBe('123456')
  })

  it('caps input at the configured code length', () => {
    expect(normalizeOtpValue('123456789', 6, 'numeric')).toBe('123456')
  })

  it('removes whitespace from a copied code', () => {
    expect(normalizeOtpValue('123 456', 6, 'numeric')).toBe('123456')
  })

  it('normalizes alphanumeric codes to supported uppercase characters', () => {
    expect(normalizeOtpValue('a1-b2 c3', 6, 'alphanumeric')).toBe('A1B2C3')
  })
})

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

describe('Server-rendered OTP character filter', () => {
  it('removes unsupported characters under the numeric policy', () => {
    expect('a1-!'.replace(buildOtpInputFilter('numeric'), '')).toBe('1')
  })

  it('preserves letters and digits under the alphanumeric policy', () => {
    expect('a1-!'.replace(buildOtpInputFilter('alphanumeric'), '')).toBe('a1')
  })
})

describe('Recovery preview: OTP charset override', () => {
  it.each(['numeric', 'alphanumeric'] as const)(
    'uses a supported %s override',
    (requested) => {
      expect(resolvePreviewOtpCharset(requested, 'numeric')).toBe(requested)
    },
  )

  it('falls back to the configured policy for unsupported values', () => {
    expect(resolvePreviewOtpCharset('unsupported', 'alphanumeric')).toBe(
      'alphanumeric',
    )
    expect(resolvePreviewOtpCharset(undefined, 'numeric')).toBe('numeric')
  })
})
