import { describe, it, expect } from 'vitest'
import { isEmailLoginHint, splitResolvedHint } from '../lib/login-hint.js'

describe('isEmailLoginHint', () => {
  it.each([
    ['alice@example.com', true],
    ['alice.pds.example.com', false],
    ['did:plc:abc123', false],
    ['did:web:example.com', false],
  ])('%s → %s', (hint, expected) => {
    expect(isEmailLoginHint(hint)).toBe(expected)
  })
})

describe('splitResolvedHint', () => {
  const email = 'alice.private@example.com'

  it('pre-fills an email hint, which the caller already knows', () => {
    expect(splitResolvedHint('alice.private@example.com', email)).toEqual({
      prefillEmail: email,
      flowEmail: null,
    })
  })

  it.each(['alice.pds.example.com', 'did:plc:abc123'])(
    'keeps the address resolved from %s server-side',
    (hint) => {
      expect(splitResolvedHint(hint, email)).toEqual({
        prefillEmail: '',
        flowEmail: email,
      })
    },
  )

  it.each([
    [null, null],
    ['alice.pds.example.com', null],
    [null, email],
  ])('yields nothing for hint=%s resolved=%s', (hint, resolved) => {
    expect(splitResolvedHint(hint, resolved)).toEqual({
      prefillEmail: '',
      flowEmail: null,
    })
  })
})
