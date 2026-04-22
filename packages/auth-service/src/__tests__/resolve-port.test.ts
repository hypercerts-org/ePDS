/**
 * Tests for resolveAuthPort().
 *
 * Verifies the AUTH_PORT > PORT > default priority chain without
 * touching process.env directly.
 */
import { describe, it, expect } from 'vitest'
import { resolveAuthPort } from '../lib/resolve-port.js'

describe('resolveAuthPort', () => {
  it('returns AUTH_PORT when set', () => {
    expect(resolveAuthPort({ AUTH_PORT: '4000', PORT: '5000' })).toBe(4000)
  })

  it('falls back to PORT when AUTH_PORT is unset', () => {
    expect(resolveAuthPort({ PORT: '8080' })).toBe(8080)
  })

  it('falls back to 3001 when neither AUTH_PORT nor PORT is set', () => {
    expect(resolveAuthPort({})).toBe(3001)
  })

  it('returns 3001 when AUTH_PORT is empty string', () => {
    expect(resolveAuthPort({ AUTH_PORT: '' })).toBe(3001)
  })

  it('returns PORT value when AUTH_PORT is empty string', () => {
    expect(resolveAuthPort({ AUTH_PORT: '', PORT: '9000' })).toBe(9000)
  })

  it('parses port as integer (ignores decimals)', () => {
    expect(resolveAuthPort({ AUTH_PORT: '3001.9' })).toBe(3001)
  })
})
