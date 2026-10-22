import { parseArgs } from 'node:util'

export interface IdentityResult {
  did: string
  status: 'planned' | 'queued' | 'failed'
}

export function remotePayload(dids: string[], workdir: string): string {
  return `
process.chdir(${JSON.stringify(workdir)});
const {createRequire} = await import("node:module");
const require = createRequire(process.cwd() + "/package.json");
const dids = ${JSON.stringify(dids)};
let ctx;
let timer;
let complete = false;
const results = [];
const arm = () => {
  clearTimeout(timer);
  timer = setTimeout(() => process.exit(1), 10000);
};
try {
  arm();
  const {AppContext} = await import(require.resolve('@atproto/pds'));
  ctx = await AppContext.fromEnv();
  for (const did of dids) {
    arm();
    try {
      if (!/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error();
      const account = await ctx.accountManager.getAccount(did, {
        includeDeactivated: true, includeTakenDown: true
      });
      if (!account || account.did !== did || !account.handle ||
          account.deactivatedAt || account.takedownRef) throw new Error();
      await ctx.sequencer.sequenceIdentity(did, account.handle);
      results.push({did, status: 'queued'});
    } catch {
      results.push({did, status: 'failed'});
    }
  }
  complete = true;
} catch {
  complete = false;
} finally {
  arm();
  try { await ctx?.destroy(); } catch { complete = false; }
  clearTimeout(timer);
}
if (complete) console.log('EPDS_IDENTITY_RESULT:' + JSON.stringify(results));
process.exit(complete && results.every(r => r.status === 'queued') ? 0 : 1);
`
}

function shellLiteral(value: string): string {
  return "'" + value.replaceAll("'", "'\\''") + "'"
}

export async function publishBatch(
  target: string[],
  dids: string[],
  workdir: string,
  timeoutMs = 20_000 + dids.length * 11_000,
): Promise<IdentityResult[]> {
  const failed = (): IdentityResult[] =>
    dids.map((did) => ({ did, status: 'failed' }))
  let child: Deno.ChildProcess | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const payload = remotePayload(dids, workdir)
    const command = `node --input-type=module -e ${shellLiteral(payload)}`
    child = new Deno.Command('railway', {
      args: ['ssh', ...target, '--', command],
      stdin: 'null',
      stdout: 'piped',
      stderr: 'null',
    }).spawn()
    const process = child
    const collect = async () => {
      const chunks: Uint8Array[] = []
      let size = 0
      for await (const chunk of process.stdout) {
        size += chunk.length
        if (size > 2_000_000) throw new Error()
        chunks.push(chunk)
      }
      const bytes = new Uint8Array(size)
      let offset = 0
      for (const chunk of chunks) {
        bytes.set(chunk, offset)
        offset += chunk.length
      }
      const status = await process.status
      const lines = new TextDecoder().decode(bytes).split(/\r?\n/)
      const reports = lines.filter((line) =>
        line.startsWith('EPDS_IDENTITY_RESULT:'),
      )
      if (reports.length !== 1) return failed()
      const results: unknown = JSON.parse(reports[0].slice(21))
      if (
        !Array.isArray(results) ||
        results.length !== dids.length ||
        results.some(
          (r, i) =>
            r?.did !== dids[i] || !['queued', 'failed'].includes(r?.status),
        ) ||
        status.success !== results.every((r) => r.status === 'queued')
      )
        return failed()
      return results.map((r) => ({
        did: r.did,
        status: r.status,
      })) as IdentityResult[]
    }
    return await Promise.race([
      collect(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error()), timeoutMs)
      }),
    ])
  } catch {
    if (child) {
      try {
        child.kill('SIGKILL')
      } catch {
        await child.status.catch(() => {})
      }
      await child.status.catch(() => {})
    }
    return failed()
  } finally {
    clearTimeout(timer)
  }
}

export async function runIdentityCli(
  args: string[],
  output: (line: string) => void,
): Promise<number> {
  try {
    const { values } = parseArgs({
      args,
      options: {
        help: { type: 'boolean' },
        apply: { type: 'boolean', default: false },
        project: { type: 'string' },
        environment: { type: 'string' },
        service: { type: 'string' },
        instance: { type: 'string' },
        workdir: { type: 'string', default: '/app/packages/pds-core' },
        did: { type: 'string', multiple: true },
        'did-file': { type: 'string' },
      },
    })
    if (values.help) {
      output(
        'publish-identity-railway --project ID --environment ID --service ID (--did DID ... | --did-file PATH) [--instance ID] [--workdir /app/packages/pds-core] [--apply]. Offline plan by default; apply queues identity on the hosting PDS via one railway ssh session. Verify PLC success and runtime/user/storage first. No PLC writes or local secret access. Failed/ambiguous batches exit 1; rerun independently, duplicates allowed.',
      )
      return 0
    }
    const target: string[] = []
    for (const name of ['project', 'environment', 'service'] as const) {
      const value = values[name]
      if (!value || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(value))
        throw new Error()
      target.push(`--${name}`, value)
    }
    if (values.instance) {
      if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(values.instance))
        throw new Error()
      target.push('--deployment-instance', values.instance)
    }
    if (!/^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+$/.test(values.workdir))
      throw new Error()
    if (Boolean(values.did?.length) === Boolean(values['did-file']))
      throw new Error()
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
      dids.length > 1000 ||
      dids.some((did) => !/^did:plc:[a-z2-7]{24}$/.test(did))
    )
      throw new Error()
    const results: IdentityResult[] = values.apply
      ? await publishBatch(target, dids, values.workdir)
      : dids.map((did) => ({ did, status: 'planned' }))
    output(JSON.stringify({ apply: values.apply, results }))
    return results.some((r) => r.status === 'failed') ? 1 : 0
  } catch {
    output(JSON.stringify({ error: 'invalid-input-or-permission; use --help' }))
    return 1
  }
}

if (import.meta.main) {
  Deno.exitCode = await runIdentityCli(Deno.args, (line) => console.log(line))
}
