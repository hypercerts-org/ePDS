import { describe, expect, it } from 'vitest'
import {
  canLookUpAccountByHandle,
  canCheckHandle,
  canResolveHandle,
} from '../lib/identifier-guards.js'

describe('canLookUpAccountByHandle', () => {
  it('accepts a valid handle', () => {
    expect(canLookUpAccountByHandle('alice.example.com')).toBe(true)
  })

  it('accepts a valid DID', () => {
    expect(canLookUpAccountByHandle('did:plc:abc123')).toBe(true)
  })

  it('rejects a syntactically invalid identifier', () => {
    expect(canLookUpAccountByHandle('not a handle')).toBe(false)
  })

  it('rejects an empty string', () => {
    expect(canLookUpAccountByHandle('')).toBe(false)
  })

  it('rejects a bare word with no dot and no did: prefix', () => {
    expect(canLookUpAccountByHandle('alice')).toBe(false)
  })
})

describe('canCheckHandle', () => {
  it('accepts a valid handle', () => {
    expect(canCheckHandle('alice.example.com')).toBe(true)
  })

  it('rejects a DID (this endpoint only accepts handles)', () => {
    // A DID is not a HandleString, so availability-check treats it as invalid
    // — which the endpoint reports as "taken", never "free".
    expect(canCheckHandle('did:plc:abc123')).toBe(false)
  })

  it('rejects a syntactically invalid handle', () => {
    expect(canCheckHandle('has spaces.example.com')).toBe(false)
  })

  it('rejects a handle with no dot', () => {
    expect(canCheckHandle('alice')).toBe(false)
  })
})

describe('canResolveHandle', () => {
  it('accepts a valid hosted handle', () => {
    expect(canResolveHandle('alice.hosted.example')).toBe(true)
  })

  it('rejects a syntactically invalid handle', () => {
    expect(canResolveHandle('bad handle')).toBe(false)
  })

  it('rejects an empty domain', () => {
    expect(canResolveHandle('')).toBe(false)
  })
})
