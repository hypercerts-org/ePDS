import { describe, expect, it, vi } from 'vitest'
import { loadDeviceAccountEmails } from '../lib/device-accounts.js'

const VALID_DEV = 'dev-0123456789abcdef0123456789abcdef'
const VALID_SES = 'ses-fedcba9876543210fedcba9876543210'

type Bindings = Array<{ account: { email: string | null } }>

function makeProvider(opts: {
  bindings?: Bindings | (() => Promise<Bindings>)
  sessionId?: string | null
  readDeviceThrows?: Error
  listDeviceAccountsThrows?: Error
}) {
  const ses = opts.sessionId === undefined ? VALID_SES : opts.sessionId
  const readDeviceErr = opts.readDeviceThrows
  const readDevice = readDeviceErr
    ? vi.fn(() => Promise.reject(readDeviceErr))
    : vi.fn(() => Promise.resolve(ses === null ? null : { sessionId: ses }))
  const listErr = opts.listDeviceAccountsThrows
  const listDeviceAccounts = listErr
    ? vi.fn(() => Promise.reject(listErr))
    : vi.fn(() =>
        typeof opts.bindings === 'function'
          ? opts.bindings()
          : Promise.resolve(opts.bindings ?? []),
      )
  return {
    accountManager: { listDeviceAccounts },
    deviceManager: { store: { readDevice } },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any
}

describe('loadDeviceAccountEmails', () => {
  it('returns lowercased emails for every binding', async () => {
    const provider = makeProvider({
      bindings: [
        { account: { email: 'Alice@Example.COM' } },
        { account: { email: 'bob@example.com' } },
      ],
    })
    const got = await loadDeviceAccountEmails({
      provider,
      deviceId: VALID_DEV,
      sessionId: VALID_SES,
    })
    expect(got).toEqual(['alice@example.com', 'bob@example.com'])
  })

  it('skips bindings with a missing email', async () => {
    const provider = makeProvider({
      bindings: [
        { account: { email: null } },
        { account: { email: 'alice@example.com' } },
      ],
    })
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
      }),
    ).toEqual(['alice@example.com'])
  })

  it('returns null when deviceId is malformed', async () => {
    const provider = makeProvider({})
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: 'not-a-device-id',
        sessionId: VALID_SES,
      }),
    ).toBeNull()
    expect(provider.deviceManager.store.readDevice).not.toHaveBeenCalled()
  })

  it('returns null when sessionId is malformed', async () => {
    const provider = makeProvider({})
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: 'bogus',
      }),
    ).toBeNull()
    expect(provider.deviceManager.store.readDevice).not.toHaveBeenCalled()
  })

  it('returns null when the device row is missing', async () => {
    const provider = makeProvider({ sessionId: null })
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
      }),
    ).toBeNull()
  })

  it('returns null when ses-id does not match the device row', async () => {
    const provider = makeProvider({
      sessionId: 'ses-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      bindings: [{ account: { email: 'alice@example.com' } }],
    })
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
      }),
    ).toBeNull()
    expect(provider.accountManager.listDeviceAccounts).not.toHaveBeenCalled()
  })

  it('returns null when readDevice throws', async () => {
    const provider = makeProvider({ readDeviceThrows: new Error('boom') })
    const logger = { error: vi.fn(), debug: vi.fn() }
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
        logger,
      }),
    ).toBeNull()
    expect(logger.error).toHaveBeenCalled()
  })

  it('returns null when listDeviceAccounts throws', async () => {
    const provider = makeProvider({
      listDeviceAccountsThrows: new Error('boom'),
    })
    const logger = { error: vi.fn(), debug: vi.fn() }
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
        logger,
      }),
    ).toBeNull()
    expect(logger.error).toHaveBeenCalled()
  })

  it('returns an empty array for a validated device with no bindings', async () => {
    const provider = makeProvider({ bindings: [] })
    expect(
      await loadDeviceAccountEmails({
        provider,
        deviceId: VALID_DEV,
        sessionId: VALID_SES,
      }),
    ).toEqual([])
  })
})
