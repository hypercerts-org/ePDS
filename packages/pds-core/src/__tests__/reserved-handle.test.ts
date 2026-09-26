import { describe, expect, it } from 'vitest'
import { isReservedServiceHandle } from '../lib/reserved-handle.js'

const SERVICE_DOMAINS = ['.pds.example.com']

describe('isReservedServiceHandle', () => {
  it.each(['admin', 'www', 'support', 'help', 'api', 'bsky'])(
    'flags upstream-reserved local part %s',
    (local) => {
      expect(
        isReservedServiceHandle(`${local}.pds.example.com`, SERVICE_DOMAINS),
      ).toBe(true)
    },
  )

  it('accepts a normal unclaimed local part', () => {
    expect(
      isReservedServiceHandle('alice.pds.example.com', SERVICE_DOMAINS),
    ).toBe(false)
  })

  it('uses upstream normalization before checking the reserved list', () => {
    expect(
      isReservedServiceHandle('ADMIN.pds.example.com', SERVICE_DOMAINS),
    ).toBe(true)
  })

  it('rethrows unrelated upstream validation failures', () => {
    expect(() =>
      isReservedServiceHandle('ab.pds.example.com', SERVICE_DOMAINS),
    ).toThrow('Handle too short')
  })
})
