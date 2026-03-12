/**
 * Unit tests for the handle selection flow.
 *
 * Tests the exported HANDLE_REGEX and RESERVED_HANDLES constants from
 * choose-handle.ts, covering format validation edge cases and the reserved
 * handle blocklist.
 */
import { describe, it, expect } from 'vitest'
import { HANDLE_REGEX, RESERVED_HANDLES } from '../routes/choose-handle.js'

describe('HANDLE_REGEX — valid handles', () => {
  it('accepts a simple lowercase word', () => {
    expect(HANDLE_REGEX.test('alice')).toBe(true)
  })

  it('accepts a handle with a hyphen in the middle', () => {
    expect(HANDLE_REGEX.test('my-handle')).toBe(true)
  })

  it('accepts a handle with digits', () => {
    expect(HANDLE_REGEX.test('a1b')).toBe(true)
  })

  it('accepts a 3-character handle', () => {
    expect(HANDLE_REGEX.test('abc')).toBe(true)
  })

  it('accepts a 20-character handle (max length)', () => {
    expect(HANDLE_REGEX.test('a'.repeat(20))).toBe(true)
  })

  it('accepts alphanumeric mix', () => {
    expect(HANDLE_REGEX.test('user123')).toBe(true)
  })

  it('accepts handle with multiple hyphens', () => {
    expect(HANDLE_REGEX.test('my-cool-handle')).toBe(true)
  })
})

describe('HANDLE_REGEX — invalid handles', () => {
  it('rejects a single character (too short)', () => {
    expect(HANDLE_REGEX.test('a')).toBe(false)
  })

  it('rejects two characters (too short)', () => {
    expect(HANDLE_REGEX.test('ab')).toBe(false)
  })

  it('rejects a handle starting with a hyphen', () => {
    expect(HANDLE_REGEX.test('-abc')).toBe(false)
  })

  it('rejects a handle ending with a hyphen', () => {
    expect(HANDLE_REGEX.test('abc-')).toBe(false)
  })

  it('rejects uppercase letters', () => {
    expect(HANDLE_REGEX.test('ABC')).toBe(false)
  })

  it('rejects mixed case', () => {
    expect(HANDLE_REGEX.test('Alice')).toBe(false)
  })

  it('rejects a handle with a space', () => {
    expect(HANDLE_REGEX.test('a b')).toBe(false)
  })

  it('rejects an empty string', () => {
    expect(HANDLE_REGEX.test('')).toBe(false)
  })

  it('rejects a 21-character handle (too long)', () => {
    expect(HANDLE_REGEX.test('a'.repeat(21))).toBe(false)
  })

  it('rejects a handle with special characters', () => {
    expect(HANDLE_REGEX.test('abc!')).toBe(false)
  })

  it('rejects a handle with dots', () => {
    expect(HANDLE_REGEX.test('my.handle')).toBe(false)
  })

  it('rejects a handle with underscores', () => {
    expect(HANDLE_REGEX.test('my_handle')).toBe(false)
  })
})

describe('RESERVED_HANDLES — blocklist', () => {
  it('includes "admin"', () => {
    expect(RESERVED_HANDLES.has('admin')).toBe(true)
  })

  it('includes "root"', () => {
    expect(RESERVED_HANDLES.has('root')).toBe(true)
  })

  it('includes "support"', () => {
    expect(RESERVED_HANDLES.has('support')).toBe(true)
  })

  it('includes "help"', () => {
    expect(RESERVED_HANDLES.has('help')).toBe(true)
  })

  it('includes "abuse"', () => {
    expect(RESERVED_HANDLES.has('abuse')).toBe(true)
  })

  it('includes "system"', () => {
    expect(RESERVED_HANDLES.has('system')).toBe(true)
  })

  it('includes "moderator"', () => {
    expect(RESERVED_HANDLES.has('moderator')).toBe(true)
  })

  it('includes "api"', () => {
    expect(RESERVED_HANDLES.has('api')).toBe(true)
  })

  it('includes "auth"', () => {
    expect(RESERVED_HANDLES.has('auth')).toBe(true)
  })

  it('includes "security"', () => {
    expect(RESERVED_HANDLES.has('security')).toBe(true)
  })

  it('does not block a normal user handle', () => {
    expect(RESERVED_HANDLES.has('alice')).toBe(false)
  })

  it('does not block a handle with digits', () => {
    expect(RESERVED_HANDLES.has('user123')).toBe(false)
  })
})
