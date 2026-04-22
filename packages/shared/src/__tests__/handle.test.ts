import { describe, it, expect } from 'vitest'
import { validateLocalPart, LOCAL_PART_MIN, LOCAL_PART_MAX } from '../handle.js'

const DOMAIN = 'pds.example.com'

describe('validateLocalPart', () => {
  it('accepts a valid local part', () => {
    expect(validateLocalPart('alice', DOMAIN)).toBe('alice')
  })

  it('normalizes to lowercase', () => {
    expect(validateLocalPart('Alice', DOMAIN)).toBe('alice')
    expect(validateLocalPart('BOB99', DOMAIN)).toBe('bob99')
  })

  it('accepts hyphens in the middle', () => {
    expect(validateLocalPart('my-handle', DOMAIN)).toBe('my-handle')
  })

  it('accepts exactly LOCAL_PART_MIN characters', () => {
    const handle = 'a'.repeat(LOCAL_PART_MIN)
    expect(validateLocalPart(handle, DOMAIN)).toBe(handle)
  })

  it('accepts exactly LOCAL_PART_MAX characters', () => {
    const handle = 'a'.repeat(LOCAL_PART_MAX)
    expect(validateLocalPart(handle, DOMAIN)).toBe(handle)
  })

  it('rejects local part shorter than LOCAL_PART_MIN', () => {
    const handle = 'a'.repeat(LOCAL_PART_MIN - 1)
    expect(validateLocalPart(handle, DOMAIN)).toBeNull()
  })

  it('rejects local part longer than LOCAL_PART_MAX', () => {
    const handle = 'a'.repeat(LOCAL_PART_MAX + 1)
    expect(validateLocalPart(handle, DOMAIN)).toBeNull()
  })

  it('rejects dots in the local part', () => {
    expect(validateLocalPart('has.dot', DOMAIN)).toBeNull()
  })

  it('rejects empty string', () => {
    expect(validateLocalPart('', DOMAIN)).toBeNull()
  })

  it('rejects invalid atproto handle characters', () => {
    expect(validateLocalPart('user@name', DOMAIN)).toBeNull()
    expect(validateLocalPart('user name', DOMAIN)).toBeNull()
    expect(validateLocalPart('user_name', DOMAIN)).toBeNull()
  })

  it('rejects handle starting with hyphen', () => {
    expect(validateLocalPart('-alice', DOMAIN)).toBeNull()
  })

  it('rejects handle ending with hyphen', () => {
    expect(validateLocalPart('alice-', DOMAIN)).toBeNull()
  })

  it('exports correct min/max constants', () => {
    expect(LOCAL_PART_MIN).toBe(5)
    expect(LOCAL_PART_MAX).toBe(20)
  })
})
