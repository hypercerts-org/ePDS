import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { RootSeedError, loadRootSeed } from '../root-seed.js'

let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epds-seed-test-'))
})

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('loadRootSeed', () => {
  it('loads a valid hex seed from env', () => {
    const seed = loadRootSeed({ SIGNER_ROOT_SEED_HEX: 'ab'.repeat(32) })
    expect(seed.length).toBe(32)
    expect(seed.toString('hex')).toBe('ab'.repeat(32))
  })

  it('rejects malformed hex seeds', () => {
    expect(() => loadRootSeed({ SIGNER_ROOT_SEED_HEX: 'abc' })).toThrow(
      RootSeedError,
    )
    expect(() =>
      loadRootSeed({ SIGNER_ROOT_SEED_HEX: 'zz'.repeat(32) }),
    ).toThrow(RootSeedError)
  })

  it('requires some seed source', () => {
    expect(() => loadRootSeed({})).toThrow(/No root seed configured/)
  })

  it('reads a 32-byte binary seed file', () => {
    const file = path.join(dir, 'seed')
    fs.writeFileSync(file, Buffer.alloc(32, 3))
    const seed = loadRootSeed({ SIGNER_ROOT_SEED_FILE: file })
    expect(seed.equals(Buffer.alloc(32, 3))).toBe(true)
  })

  it('reads a hex seed file', () => {
    const file = path.join(dir, 'seed')
    fs.writeFileSync(file, 'cd'.repeat(32) + '\n')
    const seed = loadRootSeed({ SIGNER_ROOT_SEED_FILE: file })
    expect(seed.toString('hex')).toBe('cd'.repeat(32))
  })

  it('refuses to generate a seed without SIGNER_ALLOW_DEV_SEED', () => {
    const file = path.join(dir, 'nope', 'seed')
    expect(() => loadRootSeed({ SIGNER_ROOT_SEED_FILE: file })).toThrow(
      /Refusing to generate/,
    )
  })

  it('generates and persists a dev seed when allowed', () => {
    const file = path.join(dir, 'sub', 'seed')
    const seed = loadRootSeed({
      SIGNER_ROOT_SEED_FILE: file,
      SIGNER_ALLOW_DEV_SEED: '1',
    })
    expect(seed.length).toBe(32)
    // second load returns the same seed
    const again = loadRootSeed({ SIGNER_ROOT_SEED_FILE: file })
    expect(again.equals(seed)).toBe(true)
  })
})
