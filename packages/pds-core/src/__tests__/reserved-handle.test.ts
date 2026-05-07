import { describe, it, expect } from 'vitest'
import {
  isReservedSubdomain,
  handleIsUnavailable,
} from '../lib/reserved-handle.js'

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

  it('returns false for whitespace-only or punctuation-only inputs', () => {
    // The picker normalises before calling, but defence-in-depth on the
    // helper. Reserved list doesn't contain spaces, so these all miss.
    expect(isReservedSubdomain('   ')).toBe(false)
    expect(isReservedSubdomain('---')).toBe(false)
  })
})

describe('handleIsUnavailable', () => {
  // The handle picker's live availability check treats "exists" as
  // "unavailable" — and "unavailable" has two sources: someone owns
  // the handle in the DB, OR it's a reserved subdomain. The helper
  // OR-combines them so the picker doesn't paint a misleading
  // "✓ Available" on a reserved handle.

  it('returns true when the account already exists in the DB', () => {
    expect(
      handleIsUnavailable({
        fullHandle: 'someone.epds-poc1.test.certified.app',
        accountExists: true,
      }),
    ).toBe(true)
  })

  it('returns true when the local part is a reserved subdomain', () => {
    expect(
      handleIsUnavailable({
        fullHandle: 'admin.epds-poc1.test.certified.app',
        accountExists: false,
      }),
    ).toBe(true)
  })

  it('returns true when both the account exists AND the local part is reserved', () => {
    // Pathological case: someone managed to get a row created with a
    // reserved local part (e.g. via a config change after an account
    // existed). Either condition alone makes the handle unavailable.
    expect(
      handleIsUnavailable({
        fullHandle: 'admin.epds-poc1.test.certified.app',
        accountExists: true,
      }),
    ).toBe(true)
  })

  it('returns false for a fresh, non-reserved handle', () => {
    expect(
      handleIsUnavailable({
        fullHandle: 'alice.epds-poc1.test.certified.app',
        accountExists: false,
      }),
    ).toBe(false)
  })

  it('matches reserved local parts case-insensitively', () => {
    expect(
      handleIsUnavailable({
        fullHandle: 'ADMIN.epds-poc1.test.certified.app',
        accountExists: false,
      }),
    ).toBe(true)
  })

  it('handles an empty fullHandle gracefully (route handler rejects empty before calling)', () => {
    expect(handleIsUnavailable({ fullHandle: '', accountExists: false })).toBe(
      false,
    )
  })
})
