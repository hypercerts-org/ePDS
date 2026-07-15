import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { SignerStore } from '../store.js'

let dir: string
let store: SignerStore

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epds-signer-test-'))
  store = new SignerStore(path.join(dir, 'signer.sqlite'))
})

afterEach(() => {
  store.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('SignerStore.enroll', () => {
  it('is trust-on-first-use', () => {
    expect(store.enroll('did:plc:a', '02aa')).toBe('created')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('02aa')
  })

  it('is idempotent for the same key', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:a', '02aa')).toBe('unchanged')
  })

  it('refuses to overwrite with a different key', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:a', '03bb')).toBe('conflict')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('02aa')
  })

  it('keeps DIDs independent', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:b', '03bb')).toBe('created')
  })
})

describe('SignerStore.consumeNonce', () => {
  it('accepts strictly increasing nonces', () => {
    expect(store.consumeNonce('did:plc:a', 1)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 2)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 10)).toBe(true)
  })

  it('rejects replays and reordering', () => {
    expect(store.consumeNonce('did:plc:a', 5)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 5)).toBe(false)
    expect(store.consumeNonce('did:plc:a', 4)).toBe(false)
  })

  it('tracks nonces per DID', () => {
    expect(store.consumeNonce('did:plc:a', 5)).toBe(true)
    expect(store.consumeNonce('did:plc:b', 5)).toBe(true)
  })
})
