/**
 * A client metadata document that is valid JSON but not an object must fall
 * back to domain-derived metadata and never reach string-handling code.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { mockSafeFetch } = vi.hoisted(() => ({ mockSafeFetch: vi.fn() }))
vi.mock('../safe-fetch.js', () => ({
  makeSafeFetch: () => mockSafeFetch,
}))

import {
  clearClientMetadataCache,
  resolveClientMetadata,
} from '../client-metadata.js'

const CLIENT_ID = 'https://cool.app/client-metadata.json'

function respondWith(body: unknown): void {
  mockSafeFetch.mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  } as unknown as Response)
}

beforeEach(() => {
  mockSafeFetch.mockReset()
  clearClientMetadataCache()
})

describe('resolveClientMetadata with a non-object body', () => {
  it.each([
    ['null', null],
    ['an array', ['client_name']],
    ['a string', 'hello'],
    ['a number', 5],
  ])(
    'falls back, also on a cached repeat, when the body is %s',
    async (_l, body) => {
      respondWith(body)
      const expected = { client_name: 'cool.app' }
      expect(await resolveClientMetadata(CLIENT_ID)).toEqual(expected)
      // A second call must not surface the raw body from the cache.
      expect(await resolveClientMetadata(CLIENT_ID)).toEqual(expected)
    },
  )
})
