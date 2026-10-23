import { parseArgs } from 'node:util'
import { setTimeout as delay } from 'node:timers/promises'
import type { Keypair } from 'npm:@atproto/crypto@0.4.5'
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

class ReportingError extends RotationError {}

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
      const { def } = await import('npm:@did-plc/lib@0.0.4')
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
  const keysWithoutNew = keys.filter((key) => key !== newKey)
  if (!keys.includes(newKey) && keys.length >= 5)
    throw new RotationError('rotation-key-capacity')
  const position = keysWithoutNew.indexOf(oldKey)
  return [
    ...keysWithoutNew.slice(0, position),
    newKey,
    ...keysWithoutNew.slice(position),
  ]
}

function retryable(error: unknown): boolean {
  return (
    !(error instanceof RotationError) &&
    (!(error instanceof HttpError) ||
      [400, 409, 429].includes(error.status) ||
      error.status >= 500)
  )
}

export interface RotationProgress {
  event:
    | 'start'
    | 'did'
    | 'fetch'
    | 'submit'
    | 'readback'
    | 'retry'
    | 'result'
    | 'complete'
    | 'error'
  total?: number
  index?: number
  did?: string
  attempt?: number
  backoffMs?: number
  httpStatus?: number
  reason?: string
  status?: RotationResult['status']
  submitted?: boolean
}

export type Progress = (event: RotationProgress) => void

type Pause = (ms: number) => Promise<unknown>

interface DidRotation {
  client: RotationClient
  options: RotationOptions
  did: string
  submitted: boolean
  pause: Pause
  progress: Progress
  attempt: number
}

async function desiredKeys(
  last: CompatibleOpOrTombstone,
  options: RotationOptions,
) {
  const { normalizeOp } = await import('npm:@did-plc/lib@0.0.4')
  if (last.type === 'plc_tombstone') throw new RotationError('tombstoned')
  const normalized = normalizeOp(last)
  const keys = rotationKeys(
    normalized.rotationKeys,
    options.oldKey.did(),
    options.newKey.did(),
    options.phase,
  )
  return { last, normalized, keys }
}

async function rotateDidAttempt(state: DidRotation): Promise<RotationResult> {
  const { assureValidOp, updateRotationKeysOp } =
    await import('npm:@did-plc/lib@0.0.4')
  const { client, options, did, pause, progress, attempt } = state
  progress({ event: 'fetch', did, attempt })
  await pause(250)
  const { last, normalized, keys } = await desiredKeys(
    await client.getLastOp(did),
    options,
  )
  await assureValidOp(normalized)
  if (keys === 'missing-old') return { did, status: 'missing-old' }
  if (JSON.stringify(keys) === JSON.stringify(normalized.rotationKeys)) {
    return { did, status: state.submitted ? 'updated' : 'unchanged' }
  }
  const signer = options.phase === 'add' ? options.oldKey : options.newKey
  if (!normalized.rotationKeys.includes(signer.did())) {
    throw new RotationError('signer-not-authorized')
  }
  const op = await updateRotationKeysOp(last, signer, keys)
  await assureValidOp(op)
  if (!options.apply) return { did, status: 'planned' }
  await pause(250)
  progress({ event: 'submit', did, attempt })
  state.submitted = true
  await client.sendOperation(did, op)
  progress({ event: 'readback', did, attempt })
  await pause(250)
  const readback = await desiredKeys(await client.getLastOp(did), options)
  if (
    readback.keys === 'missing-old' ||
    JSON.stringify(readback.keys) !==
      JSON.stringify(readback.normalized.rotationKeys)
  ) {
    throw new Error('readback-mismatch')
  }
  return { did, status: 'updated' }
}

async function rotateDid(
  state: DidRotation,
  attempt = 0,
): Promise<RotationResult> {
  try {
    state.attempt = attempt + 1
    return await rotateDidAttempt(state)
  } catch (error) {
    if (error instanceof ReportingError) throw error
    if (attempt < 3 && retryable(error)) {
      state.progress({
        event: 'retry',
        did: state.did,
        attempt: attempt + 1,
        backoffMs: 500 * 2 ** attempt,
        httpStatus: error instanceof HttpError ? error.status : undefined,
        reason: 'plc-request-or-validation-failed',
        submitted: state.submitted,
      })
      await state.pause(500 * 2 ** attempt)
      return rotateDid(state, attempt + 1)
    }
    return {
      did: state.did,
      status: 'failed',
      reason:
        error instanceof RotationError
          ? error.message
          : 'plc-request-or-validation-failed',
    }
  }
}

export async function rotatePlcKeys(
  client: RotationClient,
  options: RotationOptions,
  pause: Pause = delay,
  progress: Progress = () => {},
): Promise<RotationResult[]> {
  if (options.oldKey.did() === options.newKey.did())
    throw new RotationError('identical-keys')
  progress({ event: 'start', total: options.dids.length })
  const results: RotationResult[] = []
  for (const [index, did] of options.dids.entries()) {
    progress({
      event: 'did',
      did,
      index: index + 1,
      total: options.dids.length,
    })
    const state = {
      client,
      options,
      did,
      submitted: false,
      pause,
      progress,
      attempt: 0,
    }
    const result = await rotateDid(state)
    results.push(result)
    progress({ event: 'result', ...result, submitted: state.submitted })
  }
  progress({ event: 'complete', total: results.length })
  return results
}

async function permittedReadPath(file: string): Promise<string> {
  if (
    (await Deno.permissions.query({ name: 'read', path: file })).state !==
    'granted'
  )
    throw new RotationError('file-read-permission-required')
  const canonical = await Deno.realPath(file)
  if (
    (await Deno.permissions.query({ name: 'read', path: canonical })).state !==
    'granted'
  )
    throw new RotationError('file-read-permission-required')
  return canonical
}

async function permittedKeyPath(file: string) {
  const canonical = await permittedReadPath(file)
  const before = await Deno.lstat(file)
  if (!before.isFile) throw new RotationError('key-file-must-be-regular')
  return { canonical, before }
}

async function loadKey(
  file: string | undefined,
  env: string | undefined,
): Promise<Keypair> {
  if (Boolean(file) === Boolean(env))
    throw new RotationError('choose-one-key-source')
  let hex = env
  if (file) {
    const { canonical, before } = await permittedKeyPath(file)
    const handle = await Deno.open(canonical, { read: true })
    try {
      const stat = await handle.stat()
      const after = await Deno.lstat(file)
      if (
        !after.isFile ||
        before.ino !== stat.ino ||
        before.dev !== stat.dev ||
        after.ino !== stat.ino ||
        after.dev !== stat.dev ||
        !stat.isFile ||
        (stat.mode! & 0o077) !== 0 ||
        stat.uid !== Deno.uid()
      ) {
        throw new RotationError('key-file-must-be-owner-only')
      }
      const bytes = new Uint8Array(4096)
      let length = 0
      while (true) {
        const count = await handle.read(bytes.subarray(length))
        if (count === null) break
        length += count
        if (length === bytes.length)
          throw new RotationError('invalid-key-input')
      }
      hex = new TextDecoder().decode(bytes.subarray(0, length))
    } finally {
      handle.close()
    }
  }
  if (!hex || !/^[a-fA-F0-9]{64}$/.test(hex.trim()))
    throw new RotationError('invalid-key-input')
  const { Secp256k1Keypair } = await import('npm:@atproto/crypto@0.4.5')
  return Secp256k1Keypair.import(hex.trim())
}

export class RotationReport {
  private log?: Deno.FsFile
  private partial?: Deno.FsFile
  private partialPath?: string
  private reportPath?: string

  constructor(
    directory: string,
    private diagnostic: (line: string) => void,
  ) {
    try {
      try {
        Deno.mkdirSync(directory, { recursive: true, mode: 0o700 })
      } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) throw error
      }
      const stat = Deno.lstatSync(directory)
      if (!stat.isDirectory || stat.isSymlink)
        throw new ReportingError('invalid-report-directory')
      const base =
        directory +
        '/rotation-' +
        new Date().toISOString().replaceAll(':', '-') +
        '-' +
        crypto.randomUUID()
      this.log = Deno.openSync(base + '.log', {
        write: true,
        createNew: true,
        mode: 0o600,
      })
      this.partialPath = base + '.partial'
      this.partial = Deno.openSync(this.partialPath, {
        write: true,
        createNew: true,
        mode: 0o600,
      })
      this.reportPath = base + '.json'
      Deno.linkSync(this.partialPath, base + '.probe')
      Deno.removeSync(base + '.probe')
      this.message('Rotation starting; private log opened.')
    } catch {
      this.close()
      throw new ReportingError('report-initialization-failed')
    }
  }

  private write(file: Deno.FsFile, text: string) {
    let bytes = new TextEncoder().encode(text)
    while (bytes.length) bytes = bytes.subarray(file.writeSync(bytes))
  }

  message(value: string | RotationProgress) {
    const timestamp = new Date().toISOString()
    const line =
      typeof value === 'string'
        ? timestamp + ' ' + value
        : JSON.stringify({ ...value, timestamp })
    try {
      this.write(this.log!, line + '\n')
      this.log!.syncSync()
      this.diagnostic(line)
    } catch {
      throw new ReportingError('report-log-write-failed')
    }
  }

  publish(json: string) {
    try {
      this.write(this.partial!, json + '\n')
      this.partial!.syncSync()
      Deno.linkSync(this.partialPath!, this.reportPath!)
    } catch {
      throw new ReportingError('report-publication-failed')
    }
    this.message('Saved report: ' + this.reportPath)
  }

  close() {
    this.partial?.close()
    this.partial = undefined
    if (this.partialPath) {
      try {
        Deno.removeSync(this.partialPath)
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound))
          throw new ReportingError('partial-cleanup-failed')
      }
      this.partialPath = undefined
    }
    this.log?.close()
    this.log = undefined
  }
}

export async function runRotationCli(
  args: string[],
  env: Record<string, string | undefined>,
  output: (line: string) => void,
  progress: Progress = () => {},
  diagnostic: (line: string) => void = (line) => console.error(line),
): Promise<number> {
  let started = false
  let report: RotationReport | undefined
  const emit: Progress = (event) => {
    report?.message(event)
    progress(event)
  }
  const interrupt = () => {
    try {
      report?.message(
        'Rotation interrupted; inspect PLC heads before retrying.',
      )
    } finally {
      report?.close()
      Deno.exit(130)
    }
  }
  let listening = false
  try {
    const { values } = parseArgs({
      args,
      options: {
        help: { type: 'boolean' },
        'report-dir': { type: 'string', default: './reports' },
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
      diagnostic(
        'rotate-plc-key --phase add|remove --plc-url URL (--did DID ... | --did-file PATH) [--report-dir PATH] [--apply] [--confirm-cutover] [--old-key-file PATH --new-key-file PATH]. Dry-run by default. Keys: owner-only hex files or PLC_ROTATION_OLD_KEY_HEX / PLC_ROTATION_NEW_KEY_HEX, never CLI hex. PLC only; publish identity separately after verifying results. Remove --apply also requires --confirm-cutover; deployment cutover is manual.',
      )
      return 0
    }
    report = new RotationReport(values['report-dir'], diagnostic)
    Deno.addSignalListener('SIGINT', interrupt)
    Deno.addSignalListener('SIGTERM', interrupt)
    listening = true
    if (!values['plc-url'] || !['add', 'remove'].includes(values.phase ?? ''))
      throw new RotationError('explicit-url-and-phase-required')
    if (values.apply && values.phase === 'remove' && !values['confirm-cutover'])
      throw new RotationError('confirm-cutover-required')
    if (Boolean(values.did?.length) === Boolean(values['did-file']))
      throw new RotationError('choose-one-did-source')
    const dids = [
      ...new Set(
        values['did-file']
          ? (
              await Deno.readTextFile(
                await permittedReadPath(values['did-file']),
              )
            )
              .split(/\r?\n/)
              .map((did) => did.trim())
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
    started = true
    const results = await rotatePlcKeys(
      client,
      {
        dids,
        phase: values.phase as RotationOptions['phase'],
        apply: values.apply,
        oldKey,
        newKey,
      },
      delay,
      emit,
    )
    const json = JSON.stringify({
      phase: values.phase,
      apply: values.apply,
      results,
    })
    report.publish(json)
    const status = results.some((result) =>
      ['failed', 'missing-old'].includes(result.status),
    )
      ? 1
      : 0
    report.message('Rotation exit status: ' + status)
    output(json)
    return status
  } catch (error) {
    const event: RotationProgress = {
      event: 'error',
      reason:
        error instanceof RotationError
          ? error.message
          : started
            ? 'rotation-or-output-failed'
            : 'invalid-input-or-key-source',
      submitted: started,
    }
    try {
      emit(event)
    } catch {
      diagnostic(
        new Date().toISOString() +
          ' Rotation reporting failed; inspect PLC heads if rotation started.',
      )
    }
    const message = started
      ? 'Rotation did not complete; operations may have been submitted. Inspect PLC heads before retrying.'
      : 'Use --help; no operation was started.'
    try {
      if (report) report.message(message)
      else diagnostic(new Date().toISOString() + ' ' + message)
    } catch {
      diagnostic(new Date().toISOString() + ' ' + message)
    }
    return 1
  } finally {
    if (listening) {
      Deno.removeSignalListener('SIGINT', interrupt)
      Deno.removeSignalListener('SIGTERM', interrupt)
    }
    report?.close()
  }
}

if (import.meta.main) {
  try {
    if (!Deno.args.includes('--help')) Deno.env.set('LOG_ENABLED', 'false')
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
  } catch {
    console.error(
      'Rotation could not complete; check runtime permissions and inspect PLC heads if a batch started.',
    )
    Deno.exitCode = 1
  }
}
