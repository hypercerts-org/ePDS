#!/usr/bin/env node
/**
 * Create a one-off cold standby copy from the Railway test ePDS volumes.
 *
 * This script intentionally uses Railway only for read-only volume downloads.
 * It passes explicit project, environment, and volume IDs every time and refuses
 * to target anything other than the built-in test ePDS profile unless the caller
 * opts into a custom target.
 */
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const TEST_EPDS = {
  name: 'test-epds',
  projectId: '17980f2b-0913-439f-a53e-472969130b6d',
  environmentId: '23b4bc8e-faa1-4777-8e5f-436c6f626a2d',
  pdsVolumeId: '9039f826-8b9b-4fb4-8ef2-5a9a22655e59',
  authVolumeId: 'c3fa8de2-971a-4aff-99ef-f8183f29e6f5',
  sourceUrl: 'https://epds1.test.certified.app',
}

/** Print usage information for the standby clone script. */
function printUsage() {
  console.log(`Usage: ALLOW_RAILWAY_DOWNLOAD=1 scripts/standby-clone.mjs [options]

Downloads the test ePDS pds-core and auth-service Railway volumes, normalizes
SQLite files, and updates <output-dir>/current after a successful clone.

Defaults are pinned to the known test ePDS Railway IDs. The script refuses
custom IDs unless --allow-custom-target is set.

Options:
  --output-dir <path>        Standby root directory [default: /tmp/epds-standby]
  --timestamp <stamp>        Release timestamp [default: current UTC time]
  --project-id <id>          Railway project ID [default: test ePDS]
  --environment-id <id>      Railway environment ID [default: test]
  --pds-volume-id <id>       pds-core volume ID [default: test pds-core volume]
  --auth-volume-id <id>      auth-service volume ID [default: test auth volume]
  --source-url <url>         Source PDS URL used in manifest [default: test URL]
  --allow-custom-target      Allow IDs that do not match the built-in test ePDS profile
  --skip-normalize           Download only; do not create normalized SQLite copy
  --force                    Replace an existing release directory with the same timestamp
  --dry-run                  Print planned commands without calling Railway
  --help                     Show this help text`)
}

/** Parse command-line flags for standby clone creation. */
function parseArgs(argv) {
  const args = {
    outputDir: '/tmp/epds-standby',
    timestamp: utcTimestamp(new Date()),
    projectId: TEST_EPDS.projectId,
    environmentId: TEST_EPDS.environmentId,
    pdsVolumeId: TEST_EPDS.pdsVolumeId,
    authVolumeId: TEST_EPDS.authVolumeId,
    sourceUrl: TEST_EPDS.sourceUrl,
    allowCustomTarget: false,
    skipNormalize: false,
    force: false,
    dryRun: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--help' || arg === '-h') {
      printUsage()
      process.exit(0)
    }
    if (arg === '--allow-custom-target') {
      args.allowCustomTarget = true
      continue
    }
    if (arg === '--skip-normalize') {
      args.skipNormalize = true
      continue
    }
    if (arg === '--force') {
      args.force = true
      continue
    }
    if (arg === '--dry-run') {
      args.dryRun = true
      continue
    }

    const valueOptions = new Map([
      ['--output-dir', 'outputDir'],
      ['--timestamp', 'timestamp'],
      ['--project-id', 'projectId'],
      ['--environment-id', 'environmentId'],
      ['--pds-volume-id', 'pdsVolumeId'],
      ['--auth-volume-id', 'authVolumeId'],
      ['--source-url', 'sourceUrl'],
    ])

    if (valueOptions.has(arg)) {
      const value = argv[index + 1]
      if (!value || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`)
      }
      args[valueOptions.get(arg)] = value
      index += 1
      continue
    }

    throw new Error(`Unknown option: ${arg}`)
  }

  return args
}

/** Format a UTC timestamp suitable for release directory names. */
function utcTimestamp(date) {
  return date
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z')
}

/** Ensure a release timestamp cannot escape the releases directory. */
function validateTimestamp(timestamp) {
  if (!/^\d{8}T\d{6}Z$/.test(timestamp)) {
    throw new Error(
      `Invalid --timestamp ${timestamp}; expected UTC format YYYYMMDDTHHMMSSZ`,
    )
  }
}

/** Resolve and verify the release directory stays under <output>/releases. */
function resolveReleaseDir(outputDir, timestamp) {
  validateTimestamp(timestamp)
  const releasesDir = path.resolve(outputDir, 'releases')
  const releaseDir = path.resolve(releasesDir, timestamp)
  const relative = path.relative(releasesDir, releaseDir)

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Resolved release directory escapes ${releasesDir}`)
  }

  return releaseDir
}

/** Return true when a command is available on PATH. */
function commandExists(command) {
  const result = spawnSync('command', ['-v', command], {
    shell: true,
    stdio: 'ignore',
  })
  return result.status === 0
}

/** Run a child process with bounded output and useful failure messages. */
function runCommand(command, args, opts = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 50,
    ...opts,
  })

  if (result.error) {
    throw result.error
  }

  if (result.status !== 0) {
    const rendered = [command, ...args].join(' ')
    throw new Error(
      `${rendered} failed with exit ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    )
  }

  return result.stdout
}

/** Refuse accidental non-test Railway targets unless explicitly allowed. */
function verifyTarget(args) {
  const matchesTest =
    args.projectId === TEST_EPDS.projectId &&
    args.environmentId === TEST_EPDS.environmentId &&
    args.pdsVolumeId === TEST_EPDS.pdsVolumeId &&
    args.authVolumeId === TEST_EPDS.authVolumeId &&
    args.sourceUrl === TEST_EPDS.sourceUrl

  if (!matchesTest && !args.allowCustomTarget) {
    throw new Error(
      'Refusing to target non-test ePDS IDs. Use --allow-custom-target only after verifying the project/environment/volume IDs.',
    )
  }

  return matchesTest ? TEST_EPDS.name : 'custom-target'
}

/** Render the Railway download command for one volume. */
function railwayDownloadCommand({
  projectId,
  environmentId,
  volumeId,
  destination,
}) {
  return [
    'volume',
    '-p',
    projectId,
    '-e',
    environmentId,
    'files',
    '--volume',
    volumeId,
    'download',
    '/',
    destination,
    '--json',
  ]
}

/** Download one Railway volume into a release directory. */
async function downloadVolume({
  args,
  service,
  volumeId,
  releaseDir,
  manifest,
}) {
  const destination = path.join(releaseDir, service, 'raw')
  await fsp.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 })

  const commandArgs = railwayDownloadCommand({
    projectId: args.projectId,
    environmentId: args.environmentId,
    volumeId,
    destination,
  })

  const commandRecord = {
    service,
    volumeId,
    destination,
    command: ['railway', ...commandArgs],
    startedAt: new Date().toISOString(),
  }

  manifest.downloads.push(commandRecord)

  if (args.dryRun) {
    console.log(commandRecord.command.join(' '))
    commandRecord.dryRun = true
    commandRecord.finishedAt = new Date().toISOString()
    return
  }

  const stdout = runCommand('railway', commandArgs)
  commandRecord.finishedAt = new Date().toISOString()
  commandRecord.stdout = stdout.trim()

  await fsp.writeFile(
    path.join(releaseDir, `${service}-download.log`),
    stdout.endsWith('\n') ? stdout : `${stdout}\n`,
  )

  const jsonStart = stdout.indexOf('{')
  if (jsonStart >= 0) {
    const parsed = JSON.parse(stdout.slice(jsonStart))
    commandRecord.result = parsed
    await fsp.writeFile(
      path.join(releaseDir, `${service}-download.json`),
      `${JSON.stringify(parsed, null, 2)}\n`,
    )
  }
}

/** Calculate a small size summary for a directory tree. */
async function directorySummary(rootDir) {
  let fileCount = 0
  let totalBytes = 0

  async function walk(currentDir) {
    const entries = await fsp.readdir(currentDir, { withFileTypes: true })
    for (const entry of entries) {
      const entryPath = path.join(currentDir, entry.name)
      if (entry.isDirectory()) {
        await walk(entryPath)
      } else if (entry.isFile()) {
        fileCount += 1
        totalBytes += (await fsp.stat(entryPath)).size
      }
    }
  }

  await walk(rootDir)
  return { fileCount, totalBytes }
}

/** Update the current symlink only after a release has succeeded. */
async function updateCurrentSymlink(outputDir, releaseDir) {
  const currentPath = path.join(outputDir, 'current')
  const nextPath = path.join(outputDir, `.current.next-${process.pid}`)
  const target = path.relative(outputDir, releaseDir)

  await fsp.rm(nextPath, { force: true })
  await fsp.symlink(target, nextPath)

  try {
    const stat = await fsp.lstat(currentPath)
    if (!stat.isSymbolicLink()) {
      throw new Error(`${currentPath} exists and is not a symlink`)
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error
    }
  }

  await fsp.rename(nextPath, currentPath)
}

/** Write the release manifest atomically enough for a one-shot local script. */
async function writeManifest(releaseDir, manifest) {
  await fsp.writeFile(
    path.join(releaseDir, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
  )
}

/** Run the SQLite normalization helper for a completed release. */
function runNormalization(releaseDir) {
  const normalizeScript = path.join(__dirname, 'standby-normalize-sqlite.mjs')
  runCommand(process.execPath, [normalizeScript, releaseDir, '--force'], {
    stdio: 'inherit',
  })
}

/** Create a cold standby release from the configured Railway test volumes. */
async function main() {
  process.umask(0o077)
  const args = parseArgs(process.argv.slice(2))
  const verifiedTarget = verifyTarget(args)
  const outputDir = path.resolve(args.outputDir)
  const releaseDir = resolveReleaseDir(outputDir, args.timestamp)

  if (!args.dryRun && process.env.ALLOW_RAILWAY_DOWNLOAD !== '1') {
    throw new Error(
      'Refusing to call Railway. Set ALLOW_RAILWAY_DOWNLOAD=1 to confirm read-only volume download.',
    )
  }

  if (!args.dryRun && !commandExists('railway')) {
    throw new Error('railway CLI is required but was not found on PATH')
  }

  if (!args.skipNormalize && !commandExists('sqlite3')) {
    throw new Error(
      'sqlite3 CLI is required for normalization but was not found on PATH',
    )
  }

  if (fs.existsSync(releaseDir)) {
    if (!args.force) {
      throw new Error(`Release already exists: ${releaseDir}; use --force`)
    }
    await fsp.rm(releaseDir, { recursive: true, force: true })
  }

  await fsp.mkdir(releaseDir, { recursive: true, mode: 0o700 })

  const manifest = {
    version: 1,
    script: 'standby-clone.mjs',
    startedAt: new Date().toISOString(),
    outputDir,
    releaseDir,
    targetVerifiedAs: verifiedTarget,
    railway: {
      projectId: args.projectId,
      environmentId: args.environmentId,
      pdsVolumeId: args.pdsVolumeId,
      authVolumeId: args.authVolumeId,
    },
    sourceUrl: args.sourceUrl,
    safety: {
      railwayUse: 'read-only volume files download only',
      railwaySsh: false,
      railwayMutations: false,
      customTargetAllowed: args.allowCustomTarget,
    },
    downloads: [],
    summaries: {},
  }

  console.log(`Target verification: ${verifiedTarget}`)
  console.log(`Release directory: ${releaseDir}`)

  await writeManifest(releaseDir, manifest)

  await downloadVolume({
    args,
    service: 'pds-core',
    volumeId: args.pdsVolumeId,
    releaseDir,
    manifest,
  })
  await writeManifest(releaseDir, manifest)

  await downloadVolume({
    args,
    service: 'auth-service',
    volumeId: args.authVolumeId,
    releaseDir,
    manifest,
  })
  await writeManifest(releaseDir, manifest)

  if (!args.dryRun) {
    manifest.summaries.raw = {
      pdsCore: await directorySummary(path.join(releaseDir, 'pds-core', 'raw')),
      authService: await directorySummary(
        path.join(releaseDir, 'auth-service', 'raw'),
      ),
    }
  }

  if (!args.skipNormalize && !args.dryRun) {
    runNormalization(releaseDir)
    manifest.summaries.normalized = {
      pdsCore: await directorySummary(
        path.join(releaseDir, 'pds-core', 'normalized'),
      ),
      authService: await directorySummary(
        path.join(releaseDir, 'auth-service', 'normalized'),
      ),
    }
  }

  manifest.finishedAt = new Date().toISOString()
  manifest.status = 'ok'
  await writeManifest(releaseDir, manifest)

  if (!args.dryRun) {
    await updateCurrentSymlink(outputDir, releaseDir)
  }

  console.log(`standby clone complete: ${releaseDir}`)
  if (!args.dryRun) {
    console.log(`current -> ${releaseDir}`)
  }
}

main().catch((error) => {
  console.error(`standby-clone: ${error.message}`)
  process.exit(1)
})
