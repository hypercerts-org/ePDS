import process from 'node:process'
import { lstat, open, readFile } from 'node:fs/promises'
import { constants } from 'node:fs'
import { parseArgs } from 'node:util'
import { setTimeout as delay } from 'node:timers/promises'
import { Secp256k1Keypair } from 'npm:@atproto/crypto@0.4.5'
import type { Keypair } from 'npm:@atproto/crypto@0.4.5'
import {
  assureValidOp,
  def,
  normalizeOp,
  updateRotationKeysOp,
} from 'npm:@did-plc/lib@0.0.4'
import type { CompatibleOpOrTombstone, Operation } from 'npm:@did-plc/lib@0.0.4'

export interface RotationClient {
  getLastOp(did: string): Promise<CompatibleOpOrTombstone>
  sendOperation(did: string, op: Operation): Promise<void>
}

export interface RotationOptions {
  dids: string[]
  phase: 'add' | 'remove'
  oldKey: Keypair
  newKey: Keypair
  apply: boolean
}

export interface RotationResult {
  did: string
  status: 'planned' | 'updated' | 'unchanged' | 'missing-old' | 'failed'
  reason?: string
}

class RotationError extends Error {}

class HttpError extends Error {
  constructor(readonly status: number) {
    super('PLC request failed')
  }
}

export function createRotationClient(plcUrl: string): RotationClient {
  const url = new URL(plcUrl)
  if (
    !['https:', 'http:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  ) {
    throw new RotationError('invalid-plc-url')
  }
  const request = async (did: string, op?: Operation): Promise<unknown> => {
    const response = await fetch(
      `${url.origin}/${did}${op ? '' : '/log/last'}`,
      {
        method: op ? 'POST' : 'GET',
        headers: op ? { 'Content-Type': 'application/json' } : undefined,
        body: op ? JSON.stringify(op) : undefined,
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      },
    )
    if (!response.ok) throw new HttpError(response.status)
    return op ? undefined : response.json()
  }
  return {
    async getLastOp(did) {
      return def.compatibleOpOrTombstone.parse(await request(did))
    },
    async sendOperation(did, op) {
      await request(did, op)
    },
  }
}

export function rotationKeys(
  keys: string[],
  oldKey: string,
  newKey: string,
  phase: RotationOptions['phase'],
): string[] | 'missing-old' {
  if (oldKey === newKey) throw new RotationError('identical-keys')
  if (!keys.includes(oldKey)) {
    if (phase === 'remove' && keys.includes(newKey)) return keys
    return 'missing-old'
  }
  if (phase === 'remove') {
    if (!keys.includes(newKey)) throw new RotationError('new-key-not-present')
    return keys.filter((key) => key !== oldKey)
  }
  if (keys.includes(newKey)) return keys
  if (keys.length >= 5) throw new RotationError('rotation-key-capacity')
  const position = keys.indexOf(oldKey) + 1
  return [...keys.slice(0, position), newKey, ...keys.slice(position)]
}

function retryable(error: unknown): boolean {
  return (
    !(error instanceof RotationError) &&
    (!(error instanceof HttpError) ||
      [400, 409, 429].includes(error.status) ||
      error.status >= 500)
  )
}

export async function rotatePlcKeys(
  client: RotationClient,
  options: RotationOptions,
  pause: (ms: number) => Promise<unknown> = delay,
): Promise<RotationResult[]> {
  const oldKey = options.oldKey.did()
  const newKey = options.newKey.did()
  if (oldKey === newKey) throw new RotationError('identical-keys')
  const signer = options.phase === 'add' ? options.oldKey : options.newKey
  const results: RotationResult[] = []
  for (const did of options.dids) {
    let submitted = false
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        await pause(250)
        const last = await client.getLastOp(did)
        if (last.type === 'plc_tombstone') throw new RotationError('tombstoned')
        const normalized = normalizeOp(last)
        await assureValidOp(normalized)
        const keys = rotationKeys(
          normalized.rotationKeys,
          oldKey,
          newKey,
          options.phase,
        )
        if (keys === 'missing-old') {
          results.push({ did, status: 'missing-old' })
          break
        }
        if (JSON.stringify(keys) === JSON.stringify(normalized.rotationKeys)) {
          results.push({ did, status: submitted ? 'updated' : 'unchanged' })
          break
        }
        if (!normalized.rotationKeys.includes(signer.did())) {
          throw new RotationError('signer-not-authorized')
        }
        const op = await updateRotationKeysOp(last, signer, keys)
        await assureValidOp(op)
        if (!options.apply) {
          results.push({ did, status: 'planned' })
          break
        }
        submitted = true
        await pause(250)
        await client.sendOperation(did, op)
        await pause(250)
        const readback = await client.getLastOp(did)
        if (readback.type === 'plc_tombstone')
          throw new RotationError('tombstoned')
        const remaining = rotationKeys(
          normalizeOp(readback).rotationKeys,
          oldKey,
          newKey,
          options.phase,
        )
        if (
          remaining === 'missing-old' ||
          JSON.stringify(remaining) !==
            JSON.stringify(normalizeOp(readback).rotationKeys)
        ) {
          throw new Error('readback-mismatch')
        }
        results.push({ did, status: 'updated' })
        break
      } catch (error) {
        if (attempt < 3 && retryable(error)) {
          await pause(500 * 2 ** attempt)
          continue
        }
        results.push({
          did,
          status: 'failed',
          reason:
            error instanceof RotationError
              ? error.message
              : 'plc-request-or-validation-failed',
        })
      }
    }
  }
  return results
}

async function loadKey(
  file: string | undefined,
  env: string | undefined,
): Promise<Keypair> {
  if (Boolean(file) === Boolean(env))
    throw new RotationError('choose-one-key-source')
  let hex = env
  if (file) {
    const before = await lstat(file)
    if (!before.isFile()) throw new RotationError('key-file-must-be-regular')
    const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
      const stat = await handle.stat()
      const after = await lstat(file)
      if (
        !after.isFile() ||
        before.ino !== stat.ino ||
        before.dev !== stat.dev ||
        after.ino !== stat.ino ||
        after.dev !== stat.dev ||
        !stat.isFile() ||
        (stat.mode & 0o077) !== 0 ||
        stat.uid !== process.getuid?.()
      ) {
        throw new RotationError('key-file-must-be-owner-only')
      }
      hex = await handle.readFile('utf8')
    } finally {
      await handle.close()
    }
  }
  if (!hex || !/^[a-fA-F0-9]{64}$/.test(hex.trim()))
    throw new RotationError('invalid-key-input')
  return Secp256k1Keypair.import(hex.trim())
}

export async function runRotationCli(
  args: string[],
  env: Record<string, string | undefined>,
  output: (line: string) => void,
): Promise<number> {
  try {
    const { values } = parseArgs({
      args,
      options: {
        help: { type: 'boolean' },
        apply: { type: 'boolean', default: false },
        'confirm-cutover': { type: 'boolean', default: false },
        phase: { type: 'string' },
        'plc-url': { type: 'string' },
        did: { type: 'string', multiple: true },
        'did-file': { type: 'string' },
        'old-key-file': { type: 'string' },
        'new-key-file': { type: 'string' },
      },
    })
    if (values.help) {
      output(
        'rotate-plc-key --phase add|remove --plc-url URL (--did DID ... | --did-file PATH) [--apply] [--confirm-cutover] [--old-key-file PATH --new-key-file PATH]. Dry-run by default. Keys: owner-only hex files or PLC_ROTATION_OLD_KEY_HEX / PLC_ROTATION_NEW_KEY_HEX, never CLI hex. Remove --apply requires --confirm-cutover; deployment cutover is manual.',
      )
      return 0
    }
    if (!values['plc-url'] || !['add', 'remove'].includes(values.phase ?? ''))
      throw new RotationError('explicit-url-and-phase-required')
    if (values.apply && values.phase === 'remove' && !values['confirm-cutover'])
      throw new RotationError('confirm-cutover-required')
    if (Boolean(values.did?.length) === Boolean(values['did-file']))
      throw new RotationError('choose-one-did-source')
    const dids = [
      ...new Set(
        values['did-file']
          ? (await readFile(values['did-file'], 'utf8'))
              .split(/\s+/)
              .filter(Boolean)
          : values.did,
      ),
    ]
    if (
      !dids.length ||
      dids.length > 10_000 ||
      dids.some((did) => !/^did:plc:[a-z2-7]{24}$/.test(did))
    )
      throw new RotationError('invalid-did-scope')
    const client = createRotationClient(values['plc-url'])
    const oldKey = await loadKey(
      values['old-key-file'],
      env.PLC_ROTATION_OLD_KEY_HEX,
    )
    const newKey = await loadKey(
      values['new-key-file'],
      env.PLC_ROTATION_NEW_KEY_HEX,
    )
    const results = await rotatePlcKeys(client, {
      dids,
      phase: values.phase as RotationOptions['phase'],
      apply: values.apply,
      oldKey,
      newKey,
    })
    output(
      JSON.stringify({ phase: values.phase, apply: values.apply, results }),
    )
    return results.some((result) =>
      ['failed', 'missing-old'].includes(result.status),
    )
      ? 1
      : 0
  } catch {
    output(
      JSON.stringify({
        error: 'invalid-input-or-key-source',
        hint: 'Use --help; no operation was started.',
      }),
    )
    return 1
  }
}

if (import.meta.main) {
  Deno.exitCode = await runRotationCli(
    Deno.args,
    Deno.args.includes('--help')
      ? {}
      : {
          PLC_ROTATION_OLD_KEY_HEX: Deno.env.get('PLC_ROTATION_OLD_KEY_HEX'),
          PLC_ROTATION_NEW_KEY_HEX: Deno.env.get('PLC_ROTATION_NEW_KEY_HEX'),
        },
    (line) => console.log(line),
  )
}
