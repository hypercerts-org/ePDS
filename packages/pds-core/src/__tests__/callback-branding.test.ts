import { describe, expect, it, vi } from 'vitest'

import type { ClientMetadata } from '@certified-app/shared'

import { resolveTrustedCallbackCss } from '../lib/callback-branding.js'

function mockLogger() {
  return { warn: vi.fn(), debug: vi.fn() }
}

describe('resolveTrustedCallbackCss', () => {
  const trustedClient = 'https://trusted.app/client-metadata.json'
  const trustedClients = [trustedClient]
  const metadata: ClientMetadata = { client_name: 'Trusted App' }

  it('returns null for missing client ID without fetching metadata', async () => {
    const resolveClientMetadata = vi.fn()
    const getClientCss = vi.fn()

    await expect(
      resolveTrustedCallbackCss({
        clientId: undefined,
        trustedClients,
        resolveClientMetadata,
        getClientCss,
        logger: mockLogger(),
      }),
    ).resolves.toBeNull()

    expect(resolveClientMetadata).not.toHaveBeenCalled()
    expect(getClientCss).not.toHaveBeenCalled()
  })

  it('returns null for empty client ID without fetching metadata', async () => {
    const resolveClientMetadata = vi.fn()
    const getClientCss = vi.fn()

    await expect(
      resolveTrustedCallbackCss({
        clientId: '',
        trustedClients,
        resolveClientMetadata,
        getClientCss,
        logger: mockLogger(),
      }),
    ).resolves.toBeNull()

    expect(resolveClientMetadata).not.toHaveBeenCalled()
    expect(getClientCss).not.toHaveBeenCalled()
  })

  it('returns null for untrusted client ID without fetching metadata', async () => {
    const resolveClientMetadata = vi.fn()
    const getClientCss = vi.fn()

    await expect(
      resolveTrustedCallbackCss({
        clientId: 'https://untrusted.app/client-metadata.json',
        trustedClients,
        resolveClientMetadata,
        getClientCss,
        logger: mockLogger(),
      }),
    ).resolves.toBeNull()

    expect(resolveClientMetadata).not.toHaveBeenCalled()
    expect(getClientCss).not.toHaveBeenCalled()
  })

  it('fetches metadata and returns CSS for trusted client ID', async () => {
    const resolveClientMetadata = vi.fn().mockResolvedValue(metadata)
    const getClientCss = vi.fn().mockReturnValue('body { color: red; }')

    await expect(
      resolveTrustedCallbackCss({
        clientId: trustedClient,
        trustedClients,
        resolveClientMetadata,
        getClientCss,
        logger: mockLogger(),
      }),
    ).resolves.toBe('body { color: red; }')

    expect(resolveClientMetadata).toHaveBeenCalledWith(trustedClient)
    expect(getClientCss).toHaveBeenCalledWith(
      trustedClient,
      metadata,
      trustedClients,
    )
  })

  it('returns null when trusted client has no CSS', async () => {
    const resolveClientMetadata = vi.fn().mockResolvedValue(metadata)
    const getClientCss = vi.fn().mockReturnValue(null)

    await expect(
      resolveTrustedCallbackCss({
        clientId: trustedClient,
        trustedClients,
        resolveClientMetadata,
        getClientCss,
        logger: mockLogger(),
      }),
    ).resolves.toBeNull()

    expect(resolveClientMetadata).toHaveBeenCalledWith(trustedClient)
    expect(getClientCss).toHaveBeenCalledWith(
      trustedClient,
      metadata,
      trustedClients,
    )
  })

  it('logs and returns null when metadata resolution throws', async () => {
    const logger = mockLogger()
    const err = new Error('metadata unavailable')
    const getClientCss = vi.fn()

    await expect(
      resolveTrustedCallbackCss({
        clientId: trustedClient,
        trustedClients,
        resolveClientMetadata: vi.fn().mockRejectedValue(err),
        getClientCss,
        logger,
      }),
    ).resolves.toBeNull()

    expect(getClientCss).not.toHaveBeenCalled()
    expect(logger.warn).toHaveBeenCalledWith(
      { err, clientId: trustedClient },
      'ePDS callback branding: failed to resolve trusted client CSS',
    )
  })

  it('logs and returns null when CSS extraction throws', async () => {
    const logger = mockLogger()
    const err = new Error('invalid css metadata')

    await expect(
      resolveTrustedCallbackCss({
        clientId: trustedClient,
        trustedClients,
        resolveClientMetadata: vi.fn().mockResolvedValue(metadata),
        getClientCss: vi.fn(() => {
          throw err
        }),
        logger,
      }),
    ).resolves.toBeNull()

    expect(logger.warn).toHaveBeenCalledWith(
      { err, clientId: trustedClient },
      'ePDS callback branding: failed to resolve trusted client CSS',
    )
  })
})
