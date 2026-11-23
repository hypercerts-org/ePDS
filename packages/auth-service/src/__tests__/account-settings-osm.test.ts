/**
 * The fixed notices account settings shows after connecting or
 * disconnecting OpenStreetMap. Only known `?osm=` values produce one;
 * nothing from the query string is reflected into the page.
 */
import { describe, expect, it } from 'vitest'
import { osmNotice } from '../routes/account-settings.js'

describe('osmNotice', () => {
  it.each([
    ['connected', false],
    ['connect_failed', true],
    ['disconnected', false],
    ['disconnect_failed', true],
  ])('has a notice for %s', (value, error) => {
    expect(osmNotice(value)).toEqual({ text: expect.any(String), error })
  })

  it.each([
    undefined,
    '',
    '<script>alert(1)</script>',
    'toString',
    '__proto__',
    ['connected'],
  ])('has none for %j', (value) => {
    expect(osmNotice(value)).toBeNull()
  })
})
