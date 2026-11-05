/**
 * Unit tests for the strict Google `email_verified` check
 * (lib/google-email-verified.ts). better-auth-social-sign-in.test.ts runs
 * the same rules through a real better-auth instance.
 */
import { describe, it, expect } from 'vitest'
import {
  googleEmailVerified,
  isGoogleAuthoritativeFor,
  isTrueClaim,
} from '../lib/google-email-verified.js'

describe('isTrueClaim', () => {
  it.each([
    [true, true],
    ['true', true],
    [false, false],
    ['false', false],
    ['TRUE', false],
    [' true', false],
    [1, false],
    ['1', false],
    ['yes', false],
    [null, false],
    [undefined, false],
    [{}, false],
  ])('%j -> %s', (value, expected) => {
    expect(isTrueClaim(value)).toBe(expected)
  })
})

describe('isGoogleAuthoritativeFor', () => {
  it.each([
    ['alice@gmail.com', undefined, true],
    ['Alice@GMail.com', undefined, true],
    ['alice@googlemail.com', undefined, true],
    ['alice@example.com', 'example.com', true],
    // hd and the address's domain are compared case-insensitively.
    ['alice@Example.COM', 'example.com', true],
    ['alice@example.com', 'EXAMPLE.com', true],
    ['ALICE@EXAMPLE.COM', 'Example.Com', true],
    // hd vouches only for its own domain: a different domain (including a
    // Workspace secondary domain), a parent or a subdomain does not count.
    ['alice@example.org', 'example.com', false],
    ['alice@example.com', 'attacker.example', false],
    ['alice@mail.example.com', 'example.com', false],
    ['alice@example.com', 'mail.example.com', false],
    ['alice@example.com', '*', false],
    ['alice@example.com', '@example.com', false],
    // An hd claim does not stop a Gmail address from counting.
    ['alice@gmail.com', 'example.com', true],
    ['alice@', 'example.com', false],
    ['alice@example.com', undefined, false],
    ['alice@example.com', '', false],
    ['alice@example.com', '  ', false],
    ['alice@example.com', 42, false],
    ['alice@gmail.com.example.com', undefined, false],
    ['alice@notgmail.com', undefined, false],
    ['gmail.com', undefined, false],
    [undefined, undefined, false],
  ])('%j with hd=%j -> %s', (email, hd, expected) => {
    expect(isGoogleAuthoritativeFor(email, hd)).toBe(expected)
  })
})

describe('googleEmailVerified', () => {
  it('accepts a verified Gmail address', () => {
    expect(
      googleEmailVerified({ email: 'alice@gmail.com', email_verified: true }),
    ).toBe(true)
  })

  it('accepts the string "true" for a Gmail address', () => {
    expect(
      googleEmailVerified({ email: 'alice@gmail.com', email_verified: 'true' }),
    ).toBe(true)
  })

  it('rejects the string "false", which is truthy', () => {
    expect(
      googleEmailVerified({
        email: 'alice@gmail.com',
        email_verified: 'false',
      }),
    ).toBe(false)
  })

  it('rejects an unverified Gmail address', () => {
    expect(
      googleEmailVerified({ email: 'alice@gmail.com', email_verified: false }),
    ).toBe(false)
  })

  it('rejects a missing claim', () => {
    expect(googleEmailVerified({ email: 'alice@gmail.com' })).toBe(false)
  })

  it('accepts a verified Workspace address', () => {
    expect(
      googleEmailVerified({
        email: 'alice@example.com',
        email_verified: true,
        hd: 'example.com',
      }),
    ).toBe(true)
  })

  it('rejects a Workspace address whose claim is false', () => {
    expect(
      googleEmailVerified({
        email: 'alice@example.com',
        email_verified: false,
        hd: 'example.com',
      }),
    ).toBe(false)
  })

  it('rejects an address outside the hd domain', () => {
    expect(
      googleEmailVerified({
        email: 'person@example.com',
        email_verified: true,
        hd: 'attacker.example',
      }),
    ).toBe(false)
  })

  it('rejects a wildcard hd', () => {
    expect(
      googleEmailVerified({
        email: 'person@example.com',
        email_verified: true,
        hd: '*',
      }),
    ).toBe(false)
  })

  it('rejects a non-Google address even when Google says it is verified', () => {
    expect(
      googleEmailVerified({ email: 'alice@example.com', email_verified: true }),
    ).toBe(false)
  })
})
