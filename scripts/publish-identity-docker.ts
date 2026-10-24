import { parseArgs } from 'node:util'
import { join, resolve } from 'node:path'

export interface IdentityResult {
  did: string
  status: 'planned' | 'queued' | 'failed' | 'not-completed' | 'skipped'
  uncertain?: boolean
  queuedIn?: string
  error?: Diagnostic
}

const stages = [
  'transport',
  'workdir',
  'runtime-user',
  'import',
  'setup',
  'api',
  'account',
  'sequence',
  'cleanup',
  'protocol',
  'reporting',
  'input',
] as const
const codes = [
  'unknown',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'E2BIG',
  'EACCES',
  'EPERM',
  'ENOENT',
  'ENOTDIR',
  'ERR_MODULE_NOT_FOUND',
  'MODULE_NOT_FOUND',
  'ERR_PACKAGE_PATH_NOT_EXPORTED',
  'SQLITE_BUSY',
  'SQLITE_LOCKED',
  'SQLITE_CANTOPEN',
  'SQLITE_READONLY',
  'SQLITE_ERROR',
  'runtime-user',
  'api-unavailable',
  'inactive-or-missing-account',
  'invalid-did',
  'timeout',
  'interrupted',
  'protocol-mismatch',
  'missing-result',
  'output-limit',
  'exit-failure',
  'container-not-running',
  'container-unknown',
  'executable-absent',
  'authentication',
  'ssh-connection',
  'migration-failure',
  'invalid-workdir',
  'confirmation-required',
  'terminal-required',
  'invalid-target',
  'invalid-runtime',
  'invalid-instance',
  'invalid-inventory',
  'choose-one-source',
  'conflicting-resume',
  'invalid-selection',
  'incompatible-report',
  'unsafe-report',
  'untrusted-directory',
  'invalid-transport',
] as const
export interface Diagnostic {
  stage: (typeof stages)[number]
  code: (typeof codes)[number]
  exitCode?: number
  signal?: Deno.Signal
}
function diagnostic(stage: Diagnostic['stage'], err: unknown): Diagnostic {
  const e = err as { code?: unknown; message?: unknown; name?: unknown }
  const candidate = /argument list too long|os error 7/i.test(
    String(e?.message),
  )
    ? 'E2BIG'
    : (e?.code ?? e?.message)
  return {
    stage,
    code: codes.includes(candidate as Diagnostic['code'])
      ? (candidate as Diagnostic['code'])
      : e?.name === 'NotFound'
        ? 'ENOENT'
        : e?.name === 'PermissionDenied'
          ? 'EACCES'
          : 'unknown',
  }
}
function validDiagnostic(value: unknown): value is Diagnostic {
  const e = value as Diagnostic
  return (
    !!e &&
    Object.keys(e).every((k) =>
      ['stage', 'code', 'exitCode', 'signal'].includes(k),
    ) &&
    stages.includes(e.stage) &&
    codes.includes(e.code) &&
    (e.exitCode === undefined ||
      (Number.isInteger(e.exitCode) && e.exitCode >= 0 && e.exitCode <= 255)) &&
    (e.signal === undefined ||
      [
        'SIGINT',
        'SIGTERM',
        'SIGKILL',
        'SIGHUP',
        'SIGABRT',
        'SIGSEGV',
        'SIGPIPE',
      ].includes(e.signal))
  )
}
function stderrCode(text: string): Diagnostic['code'] {
  // Match known diagnostics, then emit a constant; never echo a matched line.
  for (const code of codes)
    if (
      /^(?:E[A-Z]+|SQLITE_|MODULE_|ERR_|SyntaxError|TypeError|RangeError)/.test(
        code,
      ) &&
      new RegExp('\\b' + code + '\\b').test(text)
    )
      return code
  if (/container .* is not running/i.test(text)) return 'container-not-running'
  if (/no such container/i.test(text)) return 'container-unknown'
  if (
    /executable file not found|node: (?:not found|command not found)/i.test(
      text,
    )
  )
    return 'executable-absent'
  if (
    /unauthorized|not logged in|authentication failed|permission denied \(publickey/i.test(
      text,
    )
  )
    return 'authentication'
  if (
    /connection refused|could not resolve hostname|ssh.*connection.*(?:closed|failed)/i.test(
      text,
    )
  )
    return 'ssh-connection'
  if (/permission denied/i.test(text)) return 'EACCES'
  if (/chdir.*(?:no such file|not a directory)/i.test(text))
    return 'invalid-workdir'
  if (/migration.*failed|failed.*migration/i.test(text))
    return 'migration-failure'
  return 'unknown'
}

export function remotePayload(dids: string[], workdir: string): string {
  return `
const dids = ${JSON.stringify(dids)};
const codes = ${JSON.stringify(codes)};
let ctx, timer, stage = 'workdir', attempted = false;
const results = [];
const emit = (kind, value) => console.log('EPDS_IDENTITY_' + kind + ':' + JSON.stringify(value));
const safe = err => ({stage, code: codes.includes(err?.code) ? err.code : codes.includes(err?.message) ? err.message : codes.includes(err?.name) ? err.name : /migration.*failed|failed.*migration/i.test(err?.message || '') ? 'migration-failure' : 'unknown'});
const enter = value => { stage = value; emit('STAGE', {stage}); };
const arm = () => {
  clearTimeout(timer);
  timer = setTimeout(() => {
    const error = {stage, code:'timeout'};
    emit('ERROR', {error, beforeSequence:!attempted});
    process.exit(1);
  }, 10000);
};
try {
  arm();
  enter('workdir');
  process.chdir(${JSON.stringify(workdir)});
  enter('import');
  const {createRequire} = await import('node:module');
  const {pathToFileURL} = await import('node:url');
  const require = createRequire(process.cwd() + '/package.json');
  const {AppContext} = await import(pathToFileURL(require.resolve('@atproto/pds')).href);
  if (typeof AppContext?.fromEnv !== 'function') throw Error('api-unavailable');
  enter('setup');
  ctx = await AppContext.fromEnv();
  enter('api');
  if (typeof ctx?.accountManager?.getAccount !== 'function' || typeof ctx?.sequencer?.sequenceIdentity !== 'function' || typeof ctx?.destroy !== 'function') throw Error('api-unavailable');
  for (const did of dids) {
    arm();
    emit('PROGRESS', {did, status:'started'});
    let sequencingAttempted = false;
    try {
      enter('account');
      if (!/^did:plc:[a-z2-7]{24}$/.test(did)) throw Error('invalid-did');
      const account = await ctx.accountManager.getAccount(did, {includeDeactivated:true, includeTakenDown:true});
      if (!account || account.did !== did || !account.handle || account.deactivatedAt || account.takedownRef) throw Error('inactive-or-missing-account');
      enter('sequence');
      sequencingAttempted = true; attempted = true;
      await ctx.sequencer.sequenceIdentity(did, account.handle);
      results.push({did, status:'queued'});
    } catch (err) {
      console.error(err);
      results.push({did, status:sequencingAttempted ? 'not-completed' : 'failed', ...(sequencingAttempted ? {uncertain:true} : {}), error:safe(err)});
    }
    emit('PROGRESS', results.at(-1));
  }
} catch (err) {
  console.error(err);
  const error = safe(err);
  emit('ERROR', {error, beforeSequence:!attempted});
  for (const did of dids.slice(results.length)) results.push({did, status:attempted ? 'not-completed' : 'failed', ...(attempted ? {uncertain:true} : {}), error});
} finally {
  arm(); enter('cleanup');
  try { if (ctx) await ctx.destroy(); } catch (err) {
    console.error(err);
    const error = safe(err);
    emit('ERROR', {error, beforeSequence:!attempted});
    for (let i=0; i<results.length; i++) if (results[i].status === 'queued') results[i] = {did:results[i].did, status:'not-completed', uncertain:true, error};
  }
  clearTimeout(timer);
}
emit('RESULT', results);
await new Promise(resolve => process.stdout.write('', resolve));
process.exit(results.every(r => r.status === 'queued') ? 0 : 1);
`
}

type Child = {
  stdin?: WritableStream<Uint8Array>
  stderr?: ReadableStream<Uint8Array>
  stdout: ReadableStream<Uint8Array>
  status: Promise<Deno.CommandStatus>
  kill(signal?: Deno.Signal): void
}
type Spawn = (executable: string, options: Deno.CommandOptions) => Child

export async function publishCommand(
  executable: string,
  args: string[],
  dids: string[],
  timeoutMs = 20_000 + dids.length * 11_000,
  spawn: Spawn = (executable, options) =>
    new Deno.Command(executable, options).spawn(),
  signal?: AbortSignal,
  progress: (did: string, status: string) => void = () => {},
  runtimeOutput: (
    channel: 'stdout' | 'stderr',
    bytes: Uint8Array,
    stage: Diagnostic['stage'],
  ) => void = () => {},
  payload?: string,
): Promise<IdentityResult[]> {
  let settled = false
  const bounded = async <T>(promise: Promise<T>): Promise<T | undefined> => {
    let timeout: ReturnType<typeof setTimeout> | undefined
    try {
      return await Promise.race([
        promise,
        new Promise<undefined>((resolve) => {
          timeout = setTimeout(() => resolve(undefined), 250)
        }),
      ])
    } finally {
      clearTimeout(timeout)
    }
  }
  let child: Child | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  let rejectAbort: () => void = () => {}
  const abort = () => rejectAbort()
  let failure: Diagnostic | undefined
  let stderrFailure: Diagnostic | undefined
  let commandStatus: Deno.CommandStatus | undefined
  let remoteBeforeSequence = false
  let seenSequence = false
  let remoteStarted = false
  let remoteStage: Diagnostic['stage'] = 'transport'
  let stderrDone: Promise<void> = Promise.resolve()
  const stored = { stdout: 0, stderr: 0 }
  const raw = (channel: 'stdout' | 'stderr', bytes: Uint8Array) => {
    if (settled) return
    const remaining = Math.max(0, 1_000_000 - stored[channel])
    if (remaining)
      runtimeOutput(channel, bytes.subarray(0, remaining), remoteStage)
    if (bytes.length > remaining && stored[channel] <= 1_000_000)
      progress(
        'runtime',
        `${channel} raw output truncated after 1000000 bytes; continuing to drain`,
      )
    stored[channel] += bytes.length
  }
  let prefix: number[] = []
  let stdoutProtocol: boolean | undefined
  const markers = ['STAGE', 'ERROR', 'PROGRESS', 'RESULT'].map((kind) =>
    new TextEncoder().encode(`EPDS_IDENTITY_${kind}:`),
  )
  const rawStdout = (chunk: Uint8Array) => {
    const parts: Uint8Array[] = []
    let start = 0
    for (let i = 0; i < chunk.length; i++) {
      const byte = chunk[i]
      if (stdoutProtocol === undefined) {
        prefix.push(byte)
        const possible = markers.filter((marker) =>
          prefix.every((b, n) => marker[n] === b),
        )
        if (!possible.length) {
          stdoutProtocol = false
          parts.push(new Uint8Array(prefix))
          prefix = []
          start = i + 1
        } else if (possible.some((marker) => marker.length === prefix.length)) {
          stdoutProtocol = true
          prefix = []
        }
      }
      if (byte === 10) {
        if (stdoutProtocol === false && start <= i)
          parts.push(chunk.subarray(start, i + 1))
        stdoutProtocol = undefined
        start = i + 1
      }
    }
    if (stdoutProtocol === false && start < chunk.length)
      parts.push(chunk.subarray(start))
    const bytes = new Uint8Array(parts.reduce((n, part) => n + part.length, 0))
    let offset = 0
    for (const part of parts) {
      bytes.set(part, offset)
      offset += part.length
    }
    if (bytes.length) raw('stdout', bytes)
  }
  const incomplete = (): IdentityResult[] =>
    dids.map((did) => ({
      did,
      status: child && !remoteBeforeSequence ? 'not-completed' : 'failed',
      ...(child && !remoteBeforeSequence ? { uncertain: true } : {}),
      ...(failure ? { error: failure } : {}),
    }))
  try {
    if (signal?.aborted) {
      return dids.map((did) => ({
        did,
        status: 'not-completed',
        error: { stage: 'transport', code: 'interrupted' },
      }))
    }
    child = spawn(executable, {
      args,
      stdin: payload === undefined ? 'null' : 'piped',
      stdout: 'piped',
      stderr: 'piped',
    })
    const process = child
    stderrDone = (async () => {
      let buffer = ''
      const decoder = new TextDecoder()
      if (process.stderr)
        for await (const chunk of process.stderr) {
          raw('stderr', chunk)
          // Bounded overlapping windows, drained concurrently to avoid pipe deadlock.
          for (let i = 0; i < chunk.length; i += 4096) {
            buffer = (
              buffer +
              decoder.decode(chunk.subarray(i, i + 4096), { stream: true })
            ).slice(-8192)
            const code = stderrCode(buffer)
            if (code !== 'unknown' && !stderrFailure)
              stderrFailure = { stage: remoteStage, code }
          }
        }
    })()
    const send = async () => {
      if (payload === undefined) return
      if (!process.stdin) throw Error('invalid-transport')
      const writer = process.stdin.getWriter()
      try {
        await writer.write(new TextEncoder().encode(payload))
        await writer.close()
      } finally {
        writer.releaseLock()
      }
    }
    const collect = async () => {
      let linesRead = 0
      let size = 0
      let buffer = ''
      let final: IdentityResult[] | undefined
      let index = 0
      let started = false
      const provisional: IdentityResult[] = []
      const decoder = new TextDecoder()
      const line = (text: string) => {
        if (text.startsWith('EPDS_IDENTITY_STAGE:')) {
          remoteStarted = true
          const value = JSON.parse(text.slice(20))
          if (
            !value ||
            Object.keys(value).join() !== 'stage' ||
            !stages.includes(value.stage)
          )
            throw Error('protocol-mismatch')
          remoteStage = value.stage
          if (value.stage === 'sequence') seenSequence = true
          progress('remote', value.stage)
        } else if (text.startsWith('EPDS_IDENTITY_ERROR:')) {
          remoteStarted = true
          const value = JSON.parse(text.slice(20))
          if (
            !value ||
            Object.keys(value).sort().join() !== 'beforeSequence,error' ||
            !validDiagnostic(value.error) ||
            typeof value.beforeSequence !== 'boolean' ||
            (seenSequence && value.beforeSequence)
          )
            throw Error('protocol-mismatch')
          failure = value.error
          remoteBeforeSequence = value.beforeSequence
          progress('remote', JSON.stringify(failure))
        } else if (text.startsWith('EPDS_IDENTITY_PROGRESS:')) {
          remoteStarted = true
          const value = JSON.parse(text.slice(23))
          if (
            final ||
            !value ||
            ![
              'did,status',
              'did,status,uncertain',
              'did,error,status',
              'did,error,status,uncertain',
            ].includes(Object.keys(value).sort().join()) ||
            (value.uncertain !== undefined &&
              (value.uncertain !== true || value.status !== 'not-completed')) ||
            (value.error !== undefined && !validDiagnostic(value.error)) ||
            value.did !== dids[index]
          ) {
            throw Error('protocol')
          }
          if (!started && value.status === 'started') started = true
          else if (
            started &&
            (['queued', 'failed'].includes(value.status) ||
              (value.status === 'not-completed' && value.uncertain === true))
          ) {
            provisional.push(value)
            index++
            started = false
          } else throw Error('protocol')
          if (value.error) progress(value.did, JSON.stringify(value.error))
          progress(
            value.did,
            value.status === 'queued'
              ? 'stored; cleanup pending'
              : value.uncertain
                ? 'not-completed; remote outcome uncertain'
                : value.status,
          )
        } else if (text.startsWith('EPDS_IDENTITY_RESULT:')) {
          remoteStarted = true
          if (final) throw Error('duplicate')
          const value: unknown = JSON.parse(text.slice(21))
          if (
            !Array.isArray(value) ||
            value.length !== dids.length ||
            value.some(
              (r, i) =>
                !r ||
                ![
                  'did,status',
                  'did,status,uncertain',
                  'did,error,status',
                  'did,error,status,uncertain',
                ].includes(Object.keys(r).sort().join()) ||
                (r.uncertain !== undefined &&
                  (r.uncertain !== true || r.status !== 'not-completed')) ||
                (r.error !== undefined && !validDiagnostic(r.error)) ||
                r.did !== dids[i] ||
                (!['queued', 'failed'].includes(r.status) &&
                  !(r.status === 'not-completed' && r.uncertain === true)),
            )
          ) {
            throw Error('result')
          }
          if (
            (index || started) &&
            (index !== dids.length ||
              (JSON.stringify(value) !== JSON.stringify(provisional) &&
                !(
                  failure?.stage === 'cleanup' &&
                  value.every(
                    (r, i) =>
                      JSON.stringify(r) === JSON.stringify(provisional[i]) ||
                      (provisional[i]?.status === 'queued' &&
                        r.status === 'not-completed' &&
                        r.error?.stage === 'cleanup'),
                  )
                )))
          ) {
            throw Error('inconsistent-progress')
          }
          final = value
        }
      }
      for await (const chunk of process.stdout) {
        if (settled) return incomplete()
        if (signal?.aborted) throw Error('interrupted')
        rawStdout(chunk)
        size += chunk.length
        if (size > 32_000_000) throw Error('output-limit')
        buffer += decoder.decode(chunk, { stream: true })
        let end: number
        while ((end = buffer.indexOf('\n')) !== -1) {
          line(buffer.slice(0, end).replace(/\r$/, ''))
          buffer = buffer.slice(end + 1)
          if (++linesRead % 100 === 0) {
            await new Promise((resolve) => setTimeout(resolve, 0))
            if (settled || signal?.aborted) throw Error('interrupted')
          }
        }
      }
      if (prefix.length) raw('stdout', new Uint8Array(prefix))
      buffer += decoder.decode()
      if (buffer) line(buffer)
      const status = await process.status
      commandStatus = status
      await stderrDone
      progress(
        'runtime',
        `last stage=${remoteStage}; exit code=${status.code}; signal=${status.signal ?? 'none'}`,
      )
      if (
        !final ||
        status.signal ||
        status.code !== (final.every((r) => r.status === 'queued') ? 0 : 1) ||
        status.success !== final.every((r) => r.status === 'queued')
      ) {
        failure ??= stderrFailure
        failure ??= {
          stage: stored.stderr || stored.stdout ? remoteStage : 'protocol',
          code:
            !final && !stored.stderr && !stored.stdout
              ? 'missing-result'
              : 'exit-failure',
        }
        failure = {
          ...failure,
          exitCode: status.code,
          ...(status.signal ? { signal: status.signal } : {}),
        }
        if (
          !remoteStarted &&
          [
            'container-not-running',
            'container-unknown',
            'executable-absent',
            'authentication',
            'invalid-workdir',
          ].includes(failure.code)
        )
          remoteBeforeSequence = true
        throw Error('exit-failure')
      }
      return final
    }
    return await Promise.race([
      Promise.all([collect(), send()]).then(([results]) => results),
      new Promise<never>((_, reject) => {
        rejectAbort = () => reject(Error('interrupted'))
        signal?.addEventListener('abort', abort, { once: true })
        if (signal?.aborted) rejectAbort()
        timer = setTimeout(() => reject(Error('timeout')), timeoutMs)
      }),
    ])
  } catch (err) {
    if (!child)
      raw(
        'stderr',
        new TextEncoder().encode(
          err instanceof Error ? (err.stack ?? String(err)) : String(err),
        ),
      )
    failure = signal?.aborted
      ? { stage: remoteStage, code: 'interrupted' }
      : (failure ?? diagnostic(remoteStage, err))
    if (
      child &&
      ['unknown', 'protocol-mismatch', 'output-limit'].includes(failure.code)
    )
      failure.stage = 'protocol'
    if (failure.code === 'unknown' && child) failure.code = 'protocol-mismatch'
    if (child) {
      try {
        child.kill('SIGTERM')
      } catch (err) {
        raw('stderr', new TextEncoder().encode(String(err)))
      }
      commandStatus = await bounded(child.status.catch(() => undefined))
      if (!commandStatus) {
        try {
          child.kill('SIGKILL')
        } catch (err) {
          raw('stderr', new TextEncoder().encode(String(err)))
        }
        commandStatus = await bounded(child.status.catch(() => undefined))
      }
    }
    await bounded(stderrDone.catch(() => {}))
    if (commandStatus)
      failure = {
        ...failure,
        exitCode: commandStatus.code,
        ...(commandStatus.signal ? { signal: commandStatus.signal } : {}),
      }
    progress('failure', JSON.stringify(failure))
    return incomplete()
  } finally {
    settled = true
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

interface Report {
  version: number
  kind: string
  transport: string
  id: string
  startedAt: string
  finishedAt: string
  target: string[]
  apply: boolean
  inventory: string[]
  results: IdentityResult[]
  resumedFrom: string | null
  interrupted: boolean
}

export interface Interaction {
  terminal(): boolean
  prompt(message: string): string | null
  progress(line: string): void
}
const nativeInteraction: Interaction = {
  terminal: () => Deno.stdin.isTerminal() && Deno.stderr.isTerminal(),
  prompt: (message) => prompt(message),
  progress: (line) => console.error(line),
}

const transport = 'docker'
const validDid = (did: unknown): did is string =>
  typeof did === 'string' && /^did:plc:[a-z2-7]{24}$/.test(did)
const validId = (id: unknown): id is string =>
  typeof id === 'string' &&
  /^identity-(docker|railway)-[0-9T.Z:-]+-[a-f0-9-]{36}$/.test(id)
const timestamp = (value: unknown): value is string =>
  typeof value === 'string' &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value

export function validateReport(
  value: unknown,
  target: string[],
  apply: boolean,
  inventory: string[],
): Report {
  const r = value as Report
  if (
    !r ||
    Object.keys(r).sort().join() !==
      'apply,finishedAt,id,interrupted,inventory,kind,results,resumedFrom,startedAt,target,transport,version' ||
    r.version !== 1 ||
    r.kind !== 'identity-publishing' ||
    r.transport !== transport ||
    !validId(r.id) ||
    !r.id.startsWith(`identity-${transport}-`) ||
    !timestamp(r.startedAt) ||
    !timestamp(r.finishedAt) ||
    r.finishedAt < r.startedAt ||
    r.apply !== apply ||
    typeof r.interrupted !== 'boolean' ||
    (r.resumedFrom !== null &&
      (!validId(r.resumedFrom) ||
        !r.resumedFrom.startsWith(`identity-${transport}-`) ||
        r.resumedFrom === r.id)) ||
    JSON.stringify(r.target) !== JSON.stringify(target) ||
    !Array.isArray(r.inventory) ||
    !r.inventory.length ||
    r.inventory.length > 15000 ||
    new Set(r.inventory).size !== r.inventory.length ||
    r.inventory.some((d) => !validDid(d)) ||
    JSON.stringify(r.inventory) !== JSON.stringify(inventory) ||
    !Array.isArray(r.results) ||
    r.results.length !== r.inventory.length
  ) {
    throw Error('incompatible-report')
  }
  for (const [i, result] of r.results.entries()) {
    if (
      !result ||
      result.did !== r.inventory[i] ||
      (result.error !== undefined && !validDiagnostic(result.error)) ||
      Object.keys(result).some(
        (k) => !['did', 'status', 'uncertain', 'queuedIn', 'error'].includes(k),
      ) ||
      !['planned', 'queued', 'failed', 'not-completed', 'skipped'].includes(
        result.status,
      )
    ) {
      throw Error('invalid-result')
    }
    if (
      result.uncertain !== undefined &&
      (result.uncertain !== true ||
        result.status !== 'not-completed' ||
        !r.apply)
    ) {
      throw Error('invalid-uncertainty')
    }
    if (['queued', 'skipped'].includes(result.status)) {
      if (
        !r.apply ||
        !validId(result.queuedIn) ||
        !result.queuedIn.startsWith(`identity-${transport}-`) ||
        (result.status === 'queued' && result.queuedIn !== r.id) ||
        (result.status === 'skipped' &&
          (!r.resumedFrom || result.queuedIn === r.id))
      ) {
        throw Error('invalid-provenance')
      }
    } else if (
      result.queuedIn !== undefined ||
      (result.status === 'planned' && r.apply)
    ) {
      throw Error('invalid-status')
    }
  }
  return r
}

async function trustedDirectory(path: string): Promise<string> {
  const absolute = resolve(path)
  await Deno.mkdir(absolute, { recursive: true, mode: 0o700 })
  const info = await Deno.lstat(absolute)
  if (
    !info.isDirectory ||
    info.isSymlink ||
    (await Deno.realPath(absolute)) !== absolute ||
    info.uid !== Deno.uid() ||
    (info.mode! & 0o022) !== 0
  ) {
    throw Error('untrusted-directory')
  }
  return absolute
}

async function readReport(
  path: string,
  target: string[],
  apply: boolean,
  dids: string[],
): Promise<Report> {
  const info = await Deno.lstat(path)
  if (
    !info.isFile ||
    info.isSymlink ||
    info.size > 8_000_000 ||
    info.uid !== Deno.uid() ||
    (info.mode! & 0o077) !== 0
  ) {
    throw Error('unsafe-report')
  }
  return validateReport(
    JSON.parse(await Deno.readTextFile(path)),
    target,
    apply,
    dids,
  )
}

export async function runDockerIdentityCli(
  args: string[],
  output: (line: string) => void,
  publish: typeof publishCommand = publishCommand,
  interaction: Interaction = nativeInteraction,
): Promise<number> {
  let log: Deno.FsFile | undefined
  let report: Report | undefined
  let jsonPath = ''
  let logPath = ''
  let tempPath = ''
  const controller = new AbortController()
  const interrupt = () => controller.abort()
  let listening = false
  let runFailed = false
  let publishing = false
  const writeLog = (message: string) => {
    const line = `[${new Date().toISOString()}] ${message}\n`
    if (log) {
      const bytes = new TextEncoder().encode(line)
      let offset = 0
      while (offset < bytes.length) {
        offset += log.writeSync(bytes.subarray(offset))
      }
      log.syncSync()
    }
    interaction.progress(line.trimEnd())
  }
  const writeRaw = (
    channel: 'stdout' | 'stderr',
    bytes: Uint8Array,
    stage: Diagnostic['stage'],
  ) => {
    if (!log || !bytes.length) return
    const header = new TextEncoder().encode(
      `\n[${new Date().toISOString()}] RAW ${channel} stage=${stage} bytes=${bytes.length}\n`,
    )
    for (const block of [header, bytes]) {
      let offset = 0
      while (offset < block.length)
        offset += log.writeSync(block.subarray(offset))
    }
    log.syncSync()
  }
  try {
    const { values } = parseArgs({
      args,
      options: {
        help: { type: 'boolean' },
        apply: { type: 'boolean', default: false },
        container: { type: 'string' },
        user: { type: 'string' },
        workdir: { type: 'string', default: '/app/packages/pds-core' },
        did: { type: 'string', multiple: true },
        'did-file': { type: 'string' },
        'report-dir': { type: 'string', default: './reports' },
        'resume-report': { type: 'string' },
        'no-resume': { type: 'boolean', default: false },
      },
    })
    if (values.help) {
      output(
        'publish-identity-docker --container NAME_OR_ID (--did DID ... | --did-file PATH) [--user USER[:GROUP]] [--workdir /app/packages/pds-core] [--report-dir PATH] [--apply] [--resume-report PATH | --no-resume]. Offline preview by default. Uses Docker configured user unless --user is supplied. Every run requires terminal confirmation (type yes). Reports and timestamped logs are private and flat. Resume only compatible inventory/target/mode, preserving queued provenance. Ctrl+C/SIGTERM saves unfinished work and exits 130. Local client termination cannot stop remote work: inspect runtime before retrying uncertain results. No PLC writes, secret copying, or PDS stop. At most 15000 DIDs.',
      )
      return 0
    }
    if (
      !values.container ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(values.container) ||
      (values.user !== undefined &&
        !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63})?$/.test(
          values.user,
        )) ||
      !/^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+$/.test(values.workdir)
    ) {
      throw Error('invalid-target')
    }
    const target = [values.container, values.user ?? '', values.workdir]
    if (values['no-resume'] && values['resume-report']) {
      throw Error('conflicting-resume')
    }
    if (Boolean(values.did?.length) === Boolean(values['did-file'])) {
      throw Error('choose-one-source')
    }
    const dids = [
      ...new Set(
        values['did-file']
          ? (await Deno.readTextFile(values['did-file']))
              .split(/\s+/)
              .filter(Boolean)
          : values.did,
      ),
    ]
    if (
      !dids.length ||
      dids.length > 15000 ||
      dids.some((did) => !validDid(did))
    ) {
      throw Error('invalid-inventory')
    }
    const directory = await trustedDirectory(values['report-dir'])
    const id = `identity-${transport}-${new Date().toISOString()}-${crypto.randomUUID()}`
    jsonPath = join(directory, `${id}.json`)
    logPath = join(directory, `${id}.log`)
    tempPath = join(directory, `${id}.tmp`)
    log = await Deno.open(logPath, {
      write: true,
      createNew: true,
      mode: 0o600,
    })
    report = {
      version: 1,
      kind: 'identity-publishing',
      transport,
      id,
      startedAt: new Date().toISOString(),
      finishedAt: '',
      target,
      apply: values.apply,
      inventory: dids,
      results: dids.map((did) => ({ did, status: 'not-completed' })),
      resumedFrom: null,
      interrupted: false,
    }
    Deno.addSignalListener('SIGINT', interrupt)
    Deno.addSignalListener('SIGTERM', interrupt)
    listening = true
    writeLog(`JSON: ${jsonPath}`)
    writeLog(`Log: ${logPath}`)
    let selected = values['resume-report']
    if (!selected && !values['no-resume']) {
      const candidates: { name: string; report: Report }[] = []
      for await (const entry of Deno.readDir(directory)) {
        if (
          !entry.isFile ||
          !entry.name.startsWith(`identity-${transport}-`) ||
          !entry.name.endsWith('.json')
        ) {
          continue
        }
        try {
          candidates.push({
            name: entry.name,
            report: await readReport(
              join(directory, entry.name),
              target,
              values.apply,
              dids,
            ),
          })
        } catch {
          continue
        }
      }
      candidates.sort((a, b) => a.name.localeCompare(b.name))
      if (candidates.length) {
        output('0) New run')
        candidates.forEach((candidate, i) =>
          output(
            `${i + 1}) ${candidate.name} - ${new Date(
              candidate.report.startedAt,
            ).toUTCString()}`,
          ),
        )
        if (!interaction.terminal()) throw Error('terminal-required')
        const answer = interaction.prompt(
          'Select report number (0 for new run):',
        )
        if (
          answer === null ||
          !/^(0|[1-9][0-9]*)$/.test(answer) ||
          Number(answer) > candidates.length
        ) {
          throw Error('invalid-selection')
        }
        if (Number(answer)) {
          selected = join(directory, candidates[Number(answer) - 1].name)
        }
      }
    }
    if (selected) {
      const previous = await readReport(selected, target, values.apply, dids)
      report.resumedFrom = previous.id
      report.results = previous.results.map((r) =>
        ['queued', 'skipped'].includes(r.status)
          ? { did: r.did, status: 'skipped', queuedIn: r.queuedIn }
          : {
              did: r.did,
              status: 'not-completed',
              ...(r.uncertain ? { uncertain: true } : {}),
              ...(r.error ? { error: r.error } : {}),
            },
      )
    }
    const pending = report.results
      .filter((r) => r.status !== 'skipped')
      .map((r) => r.did)
    output(
      `Inventory: ${dids.length} | Process: ${pending.length} | Skip: ${
        dids.length - pending.length
      }`,
    )
    if (report.results.some((r) => r.uncertain)) {
      writeLog(
        'WARNING: Pending DIDs have uncertain remote outcomes. A prior remote job might still run. Inspect the runtime and wait for it to stop before retrying; duplicate notifications are possible.',
      )
    }
    if (controller.signal.aborted) throw Error('interrupted')
    if (
      !interaction.terminal() ||
      interaction.prompt('Type yes to proceed:') !== 'yes'
    ) {
      throw Error('confirmation-required')
    }
    if (controller.signal.aborted) throw Error('interrupted')
    writeLog(
      `${values.apply ? 'Apply' : 'Preview'} starting: ${pending.length} DIDs`,
    )
    if (values.apply && pending.length) {
      const priorUncertain = new Set(
        report.results.filter((r) => r.uncertain).map((r) => r.did),
      )
      publishing = true
      const results = await publish(
        'docker',
        [
          'exec',
          '-i',
          ...(values.user === undefined ? [] : ['--user', values.user]),
          '--workdir',
          values.workdir,
          values.container,
          'node',
          '--input-type=module',
          '-',
        ],
        pending,
        undefined,
        undefined,
        controller.signal,
        (did, status) => writeLog(`${did}: ${status}`),
        writeRaw,
        remotePayload(pending, values.workdir),
      )
      if (
        results.length !== pending.length ||
        results.some(
          (r, i) =>
            r.did !== pending[i] ||
            !['queued', 'failed', 'not-completed'].includes(r.status),
        )
      ) {
        throw Error('invalid-transport')
      }
      let resultIndex = 0
      report.results = report.results.map((r) => {
        if (r.status === 'skipped') return r
        const result = results[resultIndex++]
        return {
          ...result,
          ...(result.status === 'queued'
            ? { queuedIn: id }
            : priorUncertain.has(r.did)
              ? { status: 'not-completed' as const, uncertain: true }
              : {}),
        }
      })
      publishing = false
    } else if (!values.apply) {
      let planned = 0
      for (const r of report.results) {
        if (controller.signal.aborted) break
        r.status = 'planned'
        if (report.results.length <= 20) writeLog(`${r.did}: planned`)
        if (++planned % 100 === 0)
          await new Promise((resolve) => setTimeout(resolve, 0))
      }
    }
    const failed = report.results.filter((r) => r.error)
    if (failed.length)
      writeLog(
        `Batch outcomes: ${failed.length} errors; first=${JSON.stringify(failed[0].error)}; full outcomes in JSON`,
      )
    await new Promise((resolve) => setTimeout(resolve, 0))
    if (report.results.some((r) => r.uncertain)) {
      writeLog(
        'Remote completion uncertain; local client termination does not stop remote Node. Inspect runtime before retrying; duplicates possible.',
      )
    }
  } catch (err) {
    runFailed = true
    try {
      writeLog(
        controller.signal.aborted
          ? 'Interrupted; finalizing full inventory'
          : 'Failed: ' + JSON.stringify(diagnostic('input', err)),
      )
    } catch (err) {
      output(
        'Log write failed: ' + JSON.stringify(diagnostic('reporting', err)),
      )
    }
    if (report && publishing)
      report.results = report.results.map((r) =>
        r.status === 'skipped'
          ? r
          : {
              ...r,
              status: 'not-completed',
              uncertain: true,
              error: diagnostic('transport', err),
            },
      )
    if (!report) return controller.signal.aborted ? 130 : 1
  } finally {
    if (report) {
      report.interrupted = controller.signal.aborted
      report.finishedAt = new Date().toISOString()
      try {
        const file = await Deno.open(tempPath, {
          write: true,
          createNew: true,
          mode: 0o600,
        })
        try {
          const bytes = new TextEncoder().encode(
            JSON.stringify(report, null, 2) + '\n',
          )
          let offset = 0
          while (offset < bytes.length) {
            offset += await file.write(bytes.subarray(offset))
          }
          await file.sync()
        } finally {
          file.close()
        }
        await Deno.link(tempPath, jsonPath)
        await Deno.remove(tempPath)
        writeLog(
          `Final summary: ${JSON.stringify(Object.fromEntries(['queued', 'planned', 'failed', 'not-completed', 'skipped'].map((status) => [status, report!.results.filter((r) => r.status === status).length])))}`,
        )
        output('Outcome                       Count')
        for (const [label, status] of [
          ['Queued', 'queued'],
          ['Planned', 'planned'],
          ['Failed', 'failed'],
          ['Not completed', 'not-completed'],
          ['Skipped', 'skipped'],
        ]) {
          output(
            `${label.padEnd(29)} ${
              report.results.filter((r) => r.status === status).length
            }`,
          )
        }
        output(`Total                         ${report.inventory.length}`)
        output(`JSON: ${jsonPath}`)
        output(`Log: ${logPath}`)
      } catch (err) {
        output(
          'Report publication failed: ' +
            JSON.stringify(diagnostic('reporting', err)) +
            '; no success claimed.',
        )
        runFailed = true
        await Deno.remove(tempPath).catch((err) =>
          output(
            'Temporary report cleanup failed: ' +
              JSON.stringify(diagnostic('reporting', err)),
          ),
        )
      }
    }
    log?.close()
    if (listening) {
      Deno.removeSignalListener('SIGINT', interrupt)
      Deno.removeSignalListener('SIGTERM', interrupt)
    }
  }
  return controller.signal.aborted
    ? 130
    : runFailed ||
        report?.results.some((r) =>
          ['failed', 'not-completed'].includes(r.status),
        )
      ? 1
      : 0
}

if (import.meta.main) {
  Deno.exitCode = await runDockerIdentityCli(Deno.args, (line) =>
    console.log(line),
  )
}
