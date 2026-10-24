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
  signal?: AbortSignal
  results?: RotationResult[]
}

export interface RotationResult {
  did: string
  status:
    | 'planned'
    | 'updated'
    | 'unchanged'
    | 'missing-old'
    | 'failed'
    | 'not-completed'
    | 'skipped'
  submitted?: boolean
  previous?: { status: 'updated' | 'unchanged'; reportId: string }
  reason?: string
}

class RotationError extends Error {}

class ReportingError extends RotationError {}

class HttpError extends Error {
  constructor(readonly status: number) {
    super('PLC request failed')
  }
}

export function createRotationClient(
  plcUrl: string,
  signal?: AbortSignal,
): RotationClient {
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
        signal: AbortSignal.any([
          AbortSignal.timeout(15_000),
          ...(signal ? [signal] : []),
        ]),
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
  options.signal?.throwIfAborted()
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
  options.signal?.throwIfAborted()
  if (!options.apply) return { did, status: 'planned' }
  await pause(250)
  progress({ event: 'submit', did, attempt })
  options.signal?.throwIfAborted()
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
    state.options.signal?.throwIfAborted()
    return await rotateDidAttempt(state)
  } catch (error) {
    if (state.options.signal?.aborted)
      return {
        did: state.did,
        status: 'not-completed',
        submitted: state.submitted,
        reason: state.submitted
          ? 'submission-uncertain-inspect-plc-head'
          : 'interrupted',
      }
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
      try {
        await state.pause(500 * 2 ** attempt)
      } catch (error) {
        if (!state.options.signal?.aborted) throw error
      }
      return rotateDid(state, attempt + 1)
    }
    return {
      did: state.did,
      status: 'failed',
      submitted: state.submitted,
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
  const results =
    options.results ??
    options.dids.map(
      (did): RotationResult => ({
        did,
        status: 'not-completed',
        reason: 'not-started',
      }),
    )
  for (const [index, did] of options.dids.entries()) {
    if (options.signal?.aborted) break
    if (results[index].status === 'skipped') continue
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
      pause: async (ms: number) => {
        options.signal?.throwIfAborted()
        await pause(ms)
        options.signal?.throwIfAborted()
      },
      progress,
      attempt: 0,
    }
    let result: RotationResult
    try {
      result = await rotateDid(state)
    } catch (error) {
      results[index] = {
        did,
        status: 'not-completed',
        submitted: state.submitted,
        reason: state.submitted
          ? 'submission-uncertain-inspect-plc-head'
          : 'reporting-stopped',
      }
      throw error
    }
    results[index] = result
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
  reportPath?: string
  logPath?: string

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
      this.logPath = base + '.log'
      this.log = Deno.openSync(this.logPath, {
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
      this.message('JSON report: ' + this.reportPath)
      this.message('Log: ' + this.logPath)
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

export interface BatchReport {
  kind: 'plc-key-rotation'
  version: 1
  id: string
  phase: RotationOptions['phase']
  apply: boolean
  plcUrl: string
  oldKey: string
  newKey: string
  inventory: string[]
  results: RotationResult[]
  interrupted: boolean
  startedAt: string
  finishedAt: string
  resumedFrom?: string
}

type Prompt = (message: string) => string | null

type RotationTarget = Pick<
  BatchReport,
  'phase' | 'apply' | 'plcUrl' | 'oldKey' | 'newKey'
>

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new RotationError('invalid-resume-report')
  return value as Record<string, unknown>
}

function validId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
  )
}

function validTime(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  )
}

export function validateResumeReport(
  value: unknown,
  target: RotationTarget,
): BatchReport {
  const data = record(value)
  if (
    data.kind !== 'plc-key-rotation' ||
    data.version !== 1 ||
    !validId(data.id) ||
    !validTime(data.startedAt) ||
    !validTime(data.finishedAt) ||
    data.finishedAt < data.startedAt ||
    typeof data.interrupted !== 'boolean' ||
    (data.resumedFrom !== undefined && !validId(data.resumedFrom)) ||
    (['phase', 'apply', 'plcUrl', 'oldKey', 'newKey'] as const).some(
      (key) => data[key] !== target[key],
    ) ||
    !Array.isArray(data.inventory) ||
    !Array.isArray(data.results)
  )
    throw new RotationError('invalid-or-mismatched-resume-report')
  validateInventory(data.inventory)
  if (data.results.length !== data.inventory.length)
    throw new RotationError('incomplete-resume-inventory')
  const results: RotationResult[] = data.results.map((value, index) => {
    const result = record(value)
    if (
      result.did !== (data.inventory as string[])[index] ||
      ![
        'updated',
        'unchanged',
        'planned',
        'missing-old',
        'failed',
        'not-completed',
        'skipped',
      ].includes(String(result.status)) ||
      (result.submitted !== undefined &&
        typeof result.submitted !== 'boolean') ||
      (result.reason !== undefined &&
        (typeof result.reason !== 'string' ||
          !/^[a-z-]{1,100}$/.test(result.reason))) ||
      (target.apply && result.status === 'planned') ||
      (!target.apply && result.status === 'updated')
    )
      throw new RotationError('invalid-resume-result')
    let previous: RotationResult['previous']
    if (result.status === 'skipped') {
      const prior = record(result.previous)
      if (
        !['updated', 'unchanged'].includes(String(prior.status)) ||
        !validId(prior.reportId) ||
        (!target.apply && prior.status === 'updated') ||
        !validId(data.resumedFrom)
      )
        throw new RotationError('invalid-skip-provenance')
      previous = {
        status: prior.status as 'updated' | 'unchanged',
        reportId: prior.reportId,
      }
    } else if (result.previous !== undefined)
      throw new RotationError('invalid-skip-provenance')
    return {
      did: result.did as string,
      status: result.status as RotationResult['status'],
      ...(result.reason === undefined
        ? {}
        : { reason: result.reason as string }),
      ...(result.submitted === undefined
        ? {}
        : { submitted: result.submitted as boolean }),
      ...(previous ? { previous } : {}),
    }
  })
  return {
    kind: 'plc-key-rotation',
    version: 1,
    id: data.id,
    phase: target.phase,
    apply: target.apply,
    plcUrl: target.plcUrl,
    oldKey: target.oldKey,
    newKey: target.newKey,
    inventory: [...data.inventory] as string[],
    results,
    interrupted: data.interrupted,
    startedAt: data.startedAt,
    finishedAt: data.finishedAt,
    ...(data.resumedFrom ? { resumedFrom: data.resumedFrom as string } : {}),
  }
}

export function resumeResults(report: BatchReport): RotationResult[] {
  return report.results.map((result) => {
    if (result.status === 'skipped')
      return { ...result, previous: { ...result.previous! } }
    if (result.status === 'updated' || result.status === 'unchanged')
      return {
        did: result.did,
        status: 'skipped',
        previous: { status: result.status, reportId: report.id },
      }
    return { did: result.did, status: 'not-completed', reason: 'not-started' }
  })
}

export async function selectResumeReport(
  directory: string,
  target: RotationTarget,
  ask: Prompt,
  inform: (line: string) => void,
  interactive: boolean,
  explicit?: string,
  noResume = false,
): Promise<BatchReport | undefined> {
  if (explicit && noResume) throw new RotationError('invalid-resume-options')
  if (noResume) return undefined
  const read = async (path: string) => {
    const canonical = await permittedReadPath(path)
    if (
      !(await Deno.lstat(path)).isFile ||
      (await Deno.stat(canonical)).size > 8_000_000
    )
      throw new RotationError('invalid-resume-file')
    return validateResumeReport(
      JSON.parse(await Deno.readTextFile(canonical)),
      target,
    )
  }
  let selected: BatchReport | undefined
  if (explicit) selected = await read(explicit)
  else {
    const candidates: { name: string; report: BatchReport }[] = []
    for await (const entry of Deno.readDir(directory)) {
      if (!entry.isFile || !/^rotation-.*\.json$/.test(entry.name)) continue
      try {
        candidates.push({
          name: entry.name,
          report: await read(directory + '/' + entry.name),
        })
      } catch {
        inform('Ignoring invalid or nonmatching rotation report: ' + entry.name)
      }
    }
    candidates.sort((a, b) => a.name.localeCompare(b.name))
    if (!candidates.length) return undefined
    if (!interactive)
      throw new RotationError('choose-no-resume-or-explicit-resume-report')
    inform('0) New run (use current inventory)')
    candidates.forEach((candidate, index) =>
      inform(
        String(index + 1) +
          ') ' +
          candidate.name +
          ' - ' +
          new Date(candidate.report.finishedAt).toLocaleString('en-GB', {
            dateStyle: 'medium',
            timeStyle: 'long',
            timeZone: 'UTC',
          }),
      ),
    )
    const choice = ask(
      'Choose report number, or 0 for a new run (Cancel to stop):',
    )
    if (choice === null) throw new RotationError('resume-cancelled')
    if (choice.trim() === '0') return undefined
    if (
      !/^[1-9][0-9]*$/.test(choice.trim()) ||
      !candidates[Number(choice.trim()) - 1]
    )
      throw new RotationError('invalid-report-selection')
    selected = candidates[Number(choice.trim()) - 1].report
  }
  return selected
}

export function outcomeTable(results: RotationResult[]): string {
  const rows: [string, RotationResult['status']][] = [
    ['Updated', 'updated'],
    ['Missing old key', 'missing-old'],
    ['Failed after retries', 'failed'],
    ['Interrupted/not completed', 'not-completed'],
    ['Unchanged', 'unchanged'],
    ['Planned', 'planned'],
    ['Skipped', 'skipped'],
  ]
  return [
    'Outcome                    Count',
    '-------------------------  -----',
    ...rows
      .filter(
        ([, status], index) =>
          index < 4 || results.some((r) => r.status === status),
      )
      .map(
        ([label, status]) =>
          label.padEnd(27) +
          String(results.filter((r) => r.status === status).length).padStart(5),
      ),
    'Total'.padEnd(27) + String(results.length).padStart(5),
  ].join('\n')
}

export async function runRotationCli(
  args: string[],
  env: Record<string, string | undefined>,
  output: (line: string) => void,
  progress: Progress = () => {},
  diagnostic: (line: string) => void = (line) => console.error(line),
  ask: Prompt = (message) => globalThis.prompt(message),
  interactive: boolean = Deno.stdin.isTerminal(),
): Promise<number> {
  let started = false
  let report: RotationReport | undefined
  let batch: BatchReport | undefined
  const controller = new AbortController()
  const interrupt = () => controller.abort()
  const emit: Progress = (event) => {
    try {
      report?.message(event)
      progress(event)
    } catch {
      throw new ReportingError('progress-reporting-failed')
    }
  }
  let listening = false
  let status = 1
  try {
    const { values } = parseArgs({
      args,
      options: {
        help: { type: 'boolean' },
        'resume-report': { type: 'string' },
        'no-resume': { type: 'boolean', default: false },
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
        'rotate-plc-key --phase add|remove --plc-url URL (--did DID ... | --did-file PATH) [--report-dir PATH] [--resume-report PATH | --no-resume] [--apply] [--confirm-cutover] [--old-key-file PATH --new-key-file PATH]. Dry-run by default. Every run requires terminal confirmation of the DID count before PLC access. Keys: owner-only hex files or PLC_ROTATION_OLD_KEY_HEX / PLC_ROTATION_NEW_KEY_HEX, never CLI hex. PLC only; publish identity separately after verifying results. Remove --apply also requires --confirm-cutover; deployment cutover is manual.',
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
    const client = createRotationClient(values['plc-url'], controller.signal)
    const oldKey = await loadKey(
      values['old-key-file'],
      env.PLC_ROTATION_OLD_KEY_HEX,
    )
    const newKey = await loadKey(
      values['new-key-file'],
      env.PLC_ROTATION_NEW_KEY_HEX,
    )
    const target: RotationTarget = {
      phase: values.phase as RotationOptions['phase'],
      apply: values.apply,
      plcUrl: new URL(values['plc-url']).origin,
      oldKey: oldKey.did(),
      newKey: newKey.did(),
    }
    const previous = await selectResumeReport(
      values['report-dir'],
      target,
      ask,
      diagnostic,
      interactive,
      values['resume-report'],
      values['no-resume'],
    )
    let dids: string[]
    if (previous) dids = previous.inventory
    else {
      if (Boolean(values.did?.length) === Boolean(values['did-file']))
        throw new RotationError('choose-one-did-source')
      dids = values['did-file']
        ? (await Deno.readTextFile(await permittedReadPath(values['did-file'])))
            .split(/\r?\n/)
            .map((did) => did.trim())
            .filter(Boolean)
        : values.did!
      validateInventory(dids)
    }
    const results: RotationResult[] = previous
      ? resumeResults(previous)
      : dids.map((did) => ({
          did,
          status: 'not-completed',
          reason: 'not-started',
        }))
    const skipped = results.filter(
      (result) => result.status === 'skipped',
    ).length
    const pending = results.length - skipped
    report.message(
      'Inventory: ' +
        dids.length +
        ' DIDs; process ' +
        pending +
        ', skip ' +
        skipped +
        '.',
    )
    if (
      !interactive ||
      ask('Process ' + pending + ' DIDs? Type yes to confirm:')
        ?.trim()
        .toLowerCase() !== 'yes'
    )
      throw new RotationError('rotation-not-confirmed')
    controller.signal.throwIfAborted()
    batch = {
      kind: 'plc-key-rotation',
      version: 1,
      id: crypto.randomUUID(),
      phase: values.phase as RotationOptions['phase'],
      apply: values.apply,
      plcUrl: new URL(values['plc-url']).origin,
      oldKey: oldKey.did(),
      newKey: newKey.did(),
      inventory: dids,
      results,
      ...(previous ? { resumedFrom: previous.id } : {}),
      interrupted: false,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
    }
    started = true
    await rotatePlcKeys(
      client,
      {
        dids,
        phase: batch.phase,
        apply: batch.apply,
        oldKey,
        newKey,
        signal: controller.signal,
        results: batch.results,
      },
      (ms) => delay(ms, undefined, { signal: controller.signal }),
      emit,
    )
    status = batch.results.some((result) =>
      ['failed', 'missing-old', 'not-completed'].includes(result.status),
    )
      ? 1
      : 0
  } catch (error) {
    try {
      emit({
        event: 'error',
        reason:
          error instanceof RotationError
            ? error.message
            : started
              ? 'rotation-or-output-failed'
              : 'invalid-input-or-key-source',
        submitted: started,
      })
    } catch {
      diagnostic(
        'Rotation reporting failed; inspect PLC heads if rotation started.',
      )
    }
  } finally {
    if (batch && report) {
      batch.interrupted = controller.signal.aborted
      batch.finishedAt = new Date().toISOString()
      if (batch.interrupted) status = 130
      try {
        report.publish(JSON.stringify(batch))
      } catch {
        diagnostic(
          'Final reporting failed; inspect PLC heads and the private log before retrying.',
        )
        if (status !== 130) status = 1
      }
      output(outcomeTable(batch.results))
      output('JSON report: ' + report.reportPath)
      output('Log: ' + report.logPath)
    }
    if (listening) {
      Deno.removeSignalListener('SIGINT', interrupt)
      Deno.removeSignalListener('SIGTERM', interrupt)
    }
    report?.close()
  }
  return status
}

function validateInventory(dids: string[]) {
  if (
    !dids.length ||
    dids.length > 15_000 ||
    new Set(dids).size !== dids.length ||
    dids.some(
      (did) => typeof did !== 'string' || !/^did:plc:[a-z2-7]{24}$/.test(did),
    )
  )
    throw new RotationError('invalid-did-scope')
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
