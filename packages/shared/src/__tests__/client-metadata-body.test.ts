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
  ])('falls back when the body is %s', async (_label, body) => {
    respondWith(body)
    const metadata = await resolveClientMetadata(CLIENT_ID)
    expect(metadata).toEqual({ client_name: 'cool.app' })
  })

  it('does not cache the raw body', async () => {
    respondWith(['x'])
    await resolveClientMetadata(CLIENT_ID)
    const again = await resolveClientMetadata(CLIENT_ID)
    expect(Array.isArray(again)).toBe(false)
    expect(again).toEqual({ client_name: 'cool.app' })
  })
})
