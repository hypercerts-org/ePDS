/**
 * Tests for generateOtpCode (uncovered in the base crypto.test.ts).
 */
import { describe, it, expect } from 'vitest'
import { generateOtpCode, hashToken } from '../crypto.js'

describe('generateOtpCode', () => {
  it('returns an 8-digit numeric code', () => {
    const { code } = generateOtpCode()
    expect(code).toMatch(/^\d{8}$/)
  })

  it('returns a SHA-256 hash of the code', () => {
    const { code, codeHash } = generateOtpCode()
    expect(codeHash).toBe(hashToken(code))
  })

  it('pads short numbers with leading zeros', () => {
    // Run multiple times to increase chance of hitting a low number
    const codes: string[] = []
    for (let i = 0; i < 50; i++) {
      const { code } = generateOtpCode()
      codes.push(code)
      expect(code).toHaveLength(8)
    }
    // All codes should be 8 digits
    expect(codes.every((c) => c.length === 8)).toBe(true)
  })

  it('generates different codes', () => {
    const a = generateOtpCode()
    const b = generateOtpCode()
    // While theoretically possible to get the same code, it's extremely unlikely
    // with 10^8 possibilities
    expect(a.code !== b.code || a.codeHash !== b.codeHash).toBe(true)
  })
})
