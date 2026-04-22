/**
 * Tests for auth-service client metadata — resolveClientBranding and
 * SSRF-blocked URL fallback behaviour.
 *
 * Core resolveClientMetadata / resolveClientName / getClientCss logic is
 * covered by packages/shared/src/__tests__/client-metadata.test.ts. This
 * file only tests auth-service-specific additions (resolveClientBranding)
 * and verifies that the safeFetch SSRF guards produce graceful fallbacks
 * through the re-export layer.
 *
 * Tests seed the metadata cache directly via _seedClientMetadataCacheForTest
 * because the SSRF-hardened safeFetch (backed by @atproto-labs/fetch-node)
 * uses a custom undici dispatcher that bypasses globalThis.fetch mocks.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import {
  resolveClientMetadata,
  resolveClientBranding,
  clearClientMetadataCache,
} from '../lib/client-metadata.js'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'

beforeEach(() => {
  clearClientMetadataCache()
})

// ── SSRF fallback via re-export layer ──────────────────────────────────────

describe('resolveClientMetadata — SSRF-blocked URLs fall back gracefully', () => {
  it.each([
    [
      'http:// (non-HTTPS)',
      'http://local.app/client-metadata.json', // NOSONAR — intentional: testing SSRF guard
      'local.app',
    ],
    [
      'private IPv4 (10.x)',
      'https://10.0.0.1/client-metadata.json', // NOSONAR — intentional: testing SSRF guard
      '10.0.0.1', // NOSONAR — intentional: testing SSRF guard
    ],
    ['loopback IPv4', 'https://127.0.0.1/client-metadata.json', '127.0.0.1'], // NOSONAR
    [
      'link-local (metadata)',
      'https://169.254.169.254/latest/meta-data/', // NOSONAR — intentional: testing SSRF guard
      '169.254.169.254', // NOSONAR
    ],
    ['IPv6 loopback', 'https://[::1]/client-metadata.json', '[::1]'],
    [
      'IPv4-mapped IPv6',
      'https://[::ffff:192.168.1.1]/client-metadata.json',
      '[::ffff:c0a8:101]',
    ],
  ])('falls back to domain for %s', async (_label, url, expectedDomain) => {
    const metadata = await resolveClientMetadata(url)
    expect(metadata.client_name).toBe(expectedDomain)
  })
})

// ── resolveClientBranding ──────────────────────────────────────────────────

describe('resolveClientBranding', () => {
  it('returns clientMeta, clientName, and null customCss for untrusted client', async () => {
    _seedClientMetadataCacheForTest('https://myapp.dev/client-metadata.json', {
      client_name: 'My App',
    })

    const result = await resolveClientBranding(
      'https://myapp.dev/client-metadata.json',
      [],
    )

    expect(result.clientMeta.client_name).toBe('My App')
    expect(result.clientName).toBe('My App')
    expect(result.customCss).toBeNull()
  })

  it('falls back to domain for clientName when client_name is missing', async () => {
    _seedClientMetadataCacheForTest('https://cool.app/client-metadata.json', {})

    const result = await resolveClientBranding(
      'https://cool.app/client-metadata.json',
      [],
    )

    expect(result.clientName).toBe('cool.app')
    expect(result.customCss).toBeNull()
  })
})
