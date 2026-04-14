/**
 * Unit tests for the handle selection flow.
 *
 * Only tests the product-level constraints owned by validateLocalPart:
 *   - Local part length (5–20 chars)
 *   - No dots in the local part (single-label only)
 *
 * Spec-level validation (invalid chars, leading/trailing hyphens, empty
 * string, etc.) is delegated to @atproto/syntax and not re-tested here.
 */
import { describe, it, expect } from 'vitest'
import { validateLocalPart } from '@certified-app/shared'

const TEST_DOMAIN = 'test.bsky.social'

/** Thin wrapper around validateLocalPart for boolean test assertions. */
function isValidLocalPart(localPart: string): boolean {
  return validateLocalPart(localPart, TEST_DOMAIN) !== null
}

describe('validateLocalPart — length constraints', () => {
  it('accepts a 5-character handle (min length)', () => {
    expect(isValidLocalPart('abcde')).toBe(true)
  })

  it('rejects a 4-character handle (too short)', () => {
    expect(isValidLocalPart('abcd')).toBe(false)
  })

  it('accepts a 20-character handle (max length)', () => {
    expect(isValidLocalPart('a'.repeat(20))).toBe(true)
  })

  it('rejects a 21-character handle (too long)', () => {
    expect(isValidLocalPart('a'.repeat(21))).toBe(false)
  })
})

describe('validateLocalPart — dot guard', () => {
  it('rejects a local part containing a dot', () => {
    expect(isValidLocalPart('my.handle')).toBe(false)
  })
})

describe('validateLocalPart — happy path', () => {
  it('accepts a valid handle and returns the normalized local part', () => {
    expect(validateLocalPart('Alice', TEST_DOMAIN)).toBe('alice')
  })
})
