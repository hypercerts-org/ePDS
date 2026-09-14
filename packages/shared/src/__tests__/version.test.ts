import type * as fs from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'

const readFileSyncMock = vi.hoisted(() => vi.fn())

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>()
  return { ...actual, readFileSync: readFileSyncMock }
})

import { getEpdsVersion } from '../version.js'

describe('getEpdsVersion', () => {
  const originalVersion = process.env.EPDS_VERSION

  beforeEach(() => {
    delete process.env.EPDS_VERSION
    readFileSyncMock.mockReset()
  })

  afterAll(() => {
    if (originalVersion === undefined) delete process.env.EPDS_VERSION
    else process.env.EPDS_VERSION = originalVersion
  })

  it('prefers the EPDS_VERSION environment override', () => {
    process.env.EPDS_VERSION = '0.5.34+test'

    expect(getEpdsVersion()).toBe('0.5.34+test')
    expect(readFileSyncMock).not.toHaveBeenCalled()
  })

  it('uses the build-time .epds-version file before package.json', () => {
    readFileSyncMock.mockImplementation((path: unknown) => {
      if (String(path).endsWith('.epds-version')) return '0.5.34+build\n'
      throw new Error(`Unexpected read: ${String(path)}`)
    })

    expect(getEpdsVersion()).toBe('0.5.34+build')
    expect(readFileSyncMock).toHaveBeenCalledWith(
      expect.stringMatching(/(?:^|\/)\.epds-version$/),
      'utf8',
    )
  })

  it('falls back to the root package.json when .epds-version is absent', () => {
    readFileSyncMock
      .mockImplementationOnce(() => {
        throw new Error('missing .epds-version')
      })
      .mockImplementationOnce(() => JSON.stringify({ version: '0.8.0' }))

    expect(getEpdsVersion()).toBe('0.8.0')
    expect(readFileSyncMock).toHaveBeenNthCalledWith(
      2,
      join(process.cwd(), 'package.json'),
      'utf8',
    )
  })

  it('falls back to the root package.json when .epds-version is empty', () => {
    readFileSyncMock
      .mockImplementationOnce(() => ' \n')
      .mockImplementationOnce(() => JSON.stringify({ version: '0.8.0' }))

    expect(getEpdsVersion()).toBe('0.8.0')
    expect(readFileSyncMock).toHaveBeenNthCalledWith(
      2,
      join(process.cwd(), 'package.json'),
      'utf8',
    )
  })
})
