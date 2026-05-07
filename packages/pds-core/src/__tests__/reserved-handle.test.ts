import { describe, it, expect } from 'vitest'
import { isReservedSubdomain } from '../lib/reserved-handle.js'

describe('isReservedSubdomain', () => {
  it.each([
    // Common reserved subdomains from upstream's @atproto/pds list.
    // The list is curated; we don't reproduce it here, just sample
    // a few that should always be reserved.
    ['admin'],
    ['www'],
    ['support'],
    ['help'],
    ['api'],
    ['bsky'],
  ])('flags reserved subdomain "%s" as reserved', (local) => {
    expect(isReservedSubdomain(local)).toBe(true)
  })

  it('treats reserved subdomains case-insensitively', () => {
    expect(isReservedSubdomain('ADMIN')).toBe(true)
    expect(isReservedSubdomain('Www')).toBe(true)
  })

  it('returns false for normal handles', () => {
    expect(isReservedSubdomain('alice')).toBe(false)
    expect(isReservedSubdomain('bob42')).toBe(false)
    expect(isReservedSubdomain('my-handle')).toBe(false)
  })

  it('returns false for the empty string (handle picker passes "" while still typing)', () => {
    expect(isReservedSubdomain('')).toBe(false)
  })
})
