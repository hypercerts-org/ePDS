#!/usr/bin/env node
/**
 * Start, stop, or inspect local ePDS services against a cloned standby release.
 *
 * This helper is for validation only. It starts pds-core and auth-service on
 * localhost ports using the release's normalized data directories.
 */
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'

const DEFAULT_PDS_HOSTNAME = 'epds1.test.certified.app'
const DEFAULT_AUTH_HOSTNAME = 'auth.localhost'

/** Print usage information for the local services helper. */
function printUsage() {
  console.log(`Usage: scripts/standby-local-services.mjs <start|stop|status> <release-dir> [options]

Starts/stops local pds-core and auth-service processes against a normalized
standby release. The services bind to localhost ports, keep normal auth rate
limits enabled, and write logs/pids into the release directory.

Options:
  --repo-dir <path>       ePDS repo directory [default: current working dir]
  --env-file <path>       Env file to load for secrets [default: <repo-dir>/.env]
  --pds-port <port>       Local pds-core port [default: 3100]
  --auth-port <port>      Local auth-service port [default: 3101]
  --pds-node <path>       Node binary for pds-core [default: auto]
  --auth-node <path>      Node binary for auth-service [default: current node]
  --pds-hostname <host>   PDS hostname for local env [default: ${DEFAULT_PDS_HOSTNAME}]
  --auth-hostname <host>  Auth hostname for local env [default: ${DEFAULT_AUTH_HOSTNAME}]
  --help                  Show this help text`)
}

/** Parse CLI flags for local service control. */
function parseArgs(argv) {
  const args = {
    action: null,
    releaseDir: null,
    repoDir: process.cwd(),
    envFile: null,
    pdsPort: 3100,
    authPort: 3101,
    pdsNode: findDefaultPdsNode(),
    authNode: process.execPath,
    pdsHostname: DEFAULT_PDS_HOSTNAME,
    authHostname: DEFAULT_AUTH_HOSTNAME,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--help' || arg === '-h') {
      printUsage()
      process.exit(0)
    }

    const valueOptions = new Map([
      ['--repo-dir', 'repoDir'],
      ['--env-file', 'envFile'],
      ['--pds-port', 'pdsPort'],
      ['--auth-port', 'authPort'],
      ['--pds-node', 'pdsNode'],
      ['--auth-node', 'authNode'],
      ['--pds-hostname', 'pdsHostname'],
      ['--auth-hostname', 'authHostname'],
    ])

    if (valueOptions.has(arg)) {
      const value = argv[index + 1]
      if (!value || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`)
      }
      const key = valueOptions.get(arg)
      args[key] =
        key === 'pdsPort' || key === 'authPort' ? Number(value) : value
      index += 1
      continue
    }

    if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`)
    }
    if (!args.action) {
      args.action = arg
      continue
    }
    if (!args.releaseDir) {
      args.releaseDir = arg
      continue
    }
    throw new Error(`Unexpected extra argument: ${arg}`)
  }

  if (!['start', 'stop', 'status'].includes(args.action)) {
    throw new Error('First argument must be one of: start, stop, status')
  }
  if (!args.releaseDir) {
    throw new Error('Missing required <release-dir>')
  }
  if (!Number.isInteger(args.pdsPort) || args.pdsPort <= 0) {
    throw new Error('--pds-port must be a positive integer')
  }
  if (!Number.isInteger(args.authPort) || args.authPort <= 0) {
    throw new Error('--auth-port must be a positive integer')
  }

  args.releaseDir = path.resolve(args.releaseDir)
  args.repoDir = path.resolve(args.repoDir)
  args.envFile = args.envFile
    ? path.resolve(args.envFile)
    : path.join(args.repoDir, '.env')

  return args
}

/** Find the Node 20 binary used locally for @atproto/pds's native sqlite build. */
function findDefaultPdsNode() {
  const candidates = [
    '/home/kzoeps/.nvm/versions/node/v20.18.3/bin/node',
    process.execPath,
  ]
  return (
    candidates.find((candidate) => fs.existsSync(candidate)) ?? process.execPath
  )
}

/** Parse a simple dotenv file without logging any values. */
function readEnvFile(envFile) {
  if (!fs.existsSync(envFile)) {
    return {}
  }

  const env = {}
  const lines = fs.readFileSync(envFile, 'utf8').split(/\r?\n/)
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) {
      continue
    }
    const equalsIndex = trimmed.indexOf('=')
    if (equalsIndex <= 0) {
      continue
    }
    const key = trimmed.slice(0, equalsIndex).trim()
    let value = trimmed.slice(equalsIndex + 1).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    env[key] = value
  }
  return env
}

/** Return the PID file path for a local service process. */
function pidFile(releaseDir, service) {
  return path.join(releaseDir, `${service}-local.pid`)
}

/** Return the log file path for a local service process. */
function logFile(releaseDir, service) {
  return path.join(releaseDir, `${service}-local.log`)
}

/** Read a PID file if present. */
function readPid(releaseDir, service) {
  const file = pidFile(releaseDir, service)
  if (!fs.existsSync(file)) {
    return null
  }
  const pid = Number(fs.readFileSync(file, 'utf8').trim())
  return Number.isInteger(pid) ? pid : null
}

/** Return whether a process is currently alive. */
function isAlive(pid) {
  if (!pid) {
    return false
  }
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/** Return the service entrypoint path this helper is allowed to manage. */
function serviceScriptPath(args, service) {
  if (service === 'pds-core') {
    return path.join(args.repoDir, 'packages', 'pds-core', 'dist', 'index.js')
  }
  if (service === 'auth-service') {
    return path.join(
      args.repoDir,
      'packages',
      'auth-service',
      'dist',
      'index.js',
    )
  }
  throw new Error(`Unknown local service: ${service}`)
}

/** Read a Linux process command line as argv entries, or null when unavailable. */
function readProcessCommandLine(pid) {
  const cmdlinePath = `/proc/${pid}/cmdline`
  if (!fs.existsSync(cmdlinePath)) {
    return null
  }
  return fs
    .readFileSync(cmdlinePath, 'utf8')
    .split('\0')
    .filter((part) => part.length > 0)
}

/** Verify a PID file still points at a process started by this helper. */
function isManagedServicePid(args, service, pid) {
  if (!isAlive(pid)) {
    return false
  }

  const commandLine = readProcessCommandLine(pid)
  if (commandLine === null) {
    return process.platform !== 'linux'
  }

  return commandLine.includes(serviceScriptPath(args, service))
}

/** Fetch a health endpoint and return a compact status object. */
async function health(url) {
  try {
    const response = await fetch(url)
    const body = await response.text()
    return { ok: response.ok, status: response.status, body }
  } catch (error) {
    return { ok: false, status: null, body: error.message }
  }
}

/** Wait until a health endpoint returns a successful response. */
async function waitForHealth(url, pid, service, logPath, timeoutMs) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    const result = await health(url)
    if (result.ok) {
      return result
    }
    if (!isAlive(pid)) {
      throw new Error(
        `${service} exited before becoming healthy; see ${logPath}`,
      )
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  throw new Error(
    `${service} did not become healthy within ${timeoutMs}ms; see ${logPath}`,
  )
}

/** Spawn one detached local service process and record its PID. */
async function spawnService({
  service,
  nodePath,
  scriptPath,
  env,
  repoDir,
  releaseDir,
}) {
  const stdoutFd = fs.openSync(logFile(releaseDir, service), 'a')
  const child = spawn(nodePath, [scriptPath], {
    cwd: repoDir,
    env,
    detached: true,
    stdio: ['ignore', stdoutFd, stdoutFd],
  })
  child.unref()
  fs.closeSync(stdoutFd)
  await fsp.writeFile(pidFile(releaseDir, service), `${child.pid}\n`, {
    mode: 0o600,
  })
  return child.pid
}

/** Build pds-core environment variables for local validation. */
function pdsEnv(args, baseEnv) {
  return {
    ...baseEnv,
    NODE_ENV: 'development',
    PDS_PORT: String(args.pdsPort),
    PORT: String(args.pdsPort),
    PDS_DATA_DIRECTORY: path.join(args.releaseDir, 'pds-core', 'normalized'),
    PDS_BLOBSTORE_DISK_LOCATION: path.join(
      args.releaseDir,
      'pds-core',
      'normalized',
      'blobs',
    ),
    PDS_HOSTNAME: args.pdsHostname,
    PDS_PUBLIC_URL: `http://localhost:${args.pdsPort}`,
    AUTH_HOSTNAME: args.authHostname,
    PDS_CRAWLERS: '',
  }
}

/** Build auth-service environment variables for local validation. */
function authEnv(args, baseEnv) {
  return {
    ...baseEnv,
    NODE_ENV: 'development',
    AUTH_PORT: String(args.authPort),
    PORT: String(args.authPort),
    DB_LOCATION: path.join(
      args.releaseDir,
      'auth-service',
      'normalized',
      'epds.sqlite',
    ),
    PDS_INTERNAL_URL: `http://localhost:${args.pdsPort}`,
    PDS_PUBLIC_URL: `http://localhost:${args.pdsPort}`,
    PDS_HOSTNAME: args.pdsHostname,
    AUTH_HOSTNAME: args.authHostname,
    EMAIL_PROVIDER: 'smtp',
    SMTP_HOST: baseEnv.SMTP_HOST || 'localhost',
    SMTP_PORT: baseEnv.SMTP_PORT || '1025',
  }
}

/** Start pds-core and auth-service against a release. */
async function start(args) {
  const pdsNormalized = path.join(args.releaseDir, 'pds-core', 'normalized')
  const authDb = path.join(
    args.releaseDir,
    'auth-service',
    'normalized',
    'epds.sqlite',
  )
  if (!fs.existsSync(pdsNormalized)) {
    throw new Error(`Missing normalized pds-core data: ${pdsNormalized}`)
  }
  if (!fs.existsSync(authDb)) {
    throw new Error(`Missing normalized auth DB: ${authDb}`)
  }

  for (const service of ['pds-core', 'auth-service']) {
    const existingPid = readPid(args.releaseDir, service)
    if (isManagedServicePid(args, service, existingPid)) {
      throw new Error(`${service} is already running with pid ${existingPid}`)
    }
    if (isAlive(existingPid)) {
      throw new Error(
        `${pidFile(args.releaseDir, service)} points to live pid ${existingPid}, but it does not look like this helper's ${service} process`,
      )
    }
  }

  const fileEnv = readEnvFile(args.envFile)
  const baseEnv = { ...process.env, ...fileEnv }

  const pdsPid = await spawnService({
    service: 'pds-core',
    nodePath: args.pdsNode,
    scriptPath: serviceScriptPath(args, 'pds-core'),
    env: pdsEnv(args, baseEnv),
    repoDir: args.repoDir,
    releaseDir: args.releaseDir,
  })
  await waitForHealth(
    `http://localhost:${args.pdsPort}/health`,
    pdsPid,
    'pds-core',
    logFile(args.releaseDir, 'pds-core'),
    80_000,
  )

  const authPid = await spawnService({
    service: 'auth-service',
    nodePath: args.authNode,
    scriptPath: serviceScriptPath(args, 'auth-service'),
    env: authEnv(args, baseEnv),
    repoDir: args.repoDir,
    releaseDir: args.releaseDir,
  })
  await waitForHealth(
    `http://localhost:${args.authPort}/health`,
    authPid,
    'auth-service',
    logFile(args.releaseDir, 'auth-service'),
    60_000,
  )

  console.log(`pds-core pid ${pdsPid}: http://localhost:${args.pdsPort}`)
  console.log(`auth-service pid ${authPid}: http://localhost:${args.authPort}`)
}

/** Stop local services for a release. */
async function stop(args) {
  for (const service of ['auth-service', 'pds-core']) {
    const pid = readPid(args.releaseDir, service)
    if (!pid || !isAlive(pid)) {
      console.log(`${service}: not running`)
      continue
    }
    if (!isManagedServicePid(args, service, pid)) {
      console.log(
        `${service}: pid file points to live pid ${pid}, but it does not look like this helper's process; not stopping`,
      )
      continue
    }
    console.log(`stopping ${service} pid ${pid}`)
    process.kill(pid, 'SIGTERM')
  }

  await new Promise((resolve) => setTimeout(resolve, 1000))

  for (const service of ['auth-service', 'pds-core']) {
    const pid = readPid(args.releaseDir, service)
    if (pid && isManagedServicePid(args, service, pid)) {
      console.log(`force stopping ${service} pid ${pid}`)
      process.kill(pid, 'SIGKILL')
    }
  }
}

/** Print local service PID and health status for a release. */
async function status(args) {
  const rows = []
  for (const [service, port] of [
    ['pds-core', args.pdsPort],
    ['auth-service', args.authPort],
  ]) {
    const pid = readPid(args.releaseDir, service)
    const alive = isAlive(pid)
    const managed = isManagedServicePid(args, service, pid)
    const healthResult = await health(`http://localhost:${port}/health`)
    rows.push({ service, pid, alive, managed, health: healthResult })
  }
  console.log(JSON.stringify(rows, null, 2))
}

/** Dispatch the requested local service action. */
async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.action === 'start') {
    await start(args)
  } else if (args.action === 'stop') {
    await stop(args)
  } else {
    await status(args)
  }
}

main().catch((error) => {
  console.error(`standby-local-services: ${error.message}`)
  process.exit(1)
})
