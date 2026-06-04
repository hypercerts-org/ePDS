#!/usr/bin/env node
/**
 * Normalize a downloaded ePDS standby release and verify SQLite integrity.
 *
 * The raw Railway volume download is preserved. This script creates a separate
 * `normalized` copy, folds committed WAL frames into standalone SQLite files,
 * and writes both JSON and Markdown integrity reports into the release folder.
 */
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'

const SERVICES = ['pds-core', 'auth-service']

/** Print usage information for the SQLite normalization script. */
function printUsage() {
  console.log(`Usage: scripts/standby-normalize-sqlite.mjs <release-dir> [--force]

Creates <release-dir>/{pds-core,auth-service}/normalized from raw downloads,
folds WAL files into standalone .sqlite files, and writes integrity reports.

Options:
  --force    Replace existing normalized directories
  --help     Show this help text`)
}

/** Parse CLI flags for the SQLite normalization script. */
function parseArgs(argv) {
  const args = {
    releaseDir: null,
    force: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--help' || arg === '-h') {
      printUsage()
      process.exit(0)
    }
    if (arg === '--force') {
      args.force = true
      continue
    }
    if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`)
    }
    if (args.releaseDir !== null) {
      throw new Error(`Unexpected extra argument: ${arg}`)
    }
    args.releaseDir = arg
  }

  if (!args.releaseDir) {
    throw new Error('Missing required <release-dir> argument')
  }

  return args
}

/** Run a command and return stdout, or throw with useful diagnostics. */
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

/** Return true when a command is available on PATH. */
function commandExists(command) {
  const result = spawnSync('command', ['-v', command], {
    shell: true,
    stdio: 'ignore',
  })
  return result.status === 0
}

/** Quote a SQLite identifier such as a table name. */
function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`
}

/** Quote a SQLite string literal such as a path passed to VACUUM INTO. */
function quoteString(value) {
  return `'${value.replaceAll("'", "''")}'`
}

/** Run a read-only SQLite query and parse JSON output. */
function sqliteJson(databasePath, sql) {
  const stdout = runCommand('sqlite3', [
    '-batch',
    '-readonly',
    '-json',
    databasePath,
    sql,
  ])
  const trimmed = stdout.trim()
  return trimmed ? JSON.parse(trimmed) : []
}

/** Run a read-write SQLite command. */
function sqliteExec(databasePath, sql) {
  runCommand('sqlite3', ['-batch', databasePath, sql])
}

/** Recursively list SQLite database files below a directory. */
async function listSqliteFiles(rootDir) {
  const files = []

  async function walk(currentDir) {
    const entries = await fsp.readdir(currentDir, { withFileTypes: true })
    for (const entry of entries) {
      const entryPath = path.join(currentDir, entry.name)
      if (entry.isDirectory()) {
        await walk(entryPath)
      } else if (entry.isFile() && entry.name.endsWith('.sqlite')) {
        files.push(entryPath)
      }
    }
  }

  await walk(rootDir)
  files.sort()
  return files
}

/** Run PRAGMA integrity_check and per-table row counts for one SQLite DB. */
function checkIntegrity(databasePath, releaseDir) {
  const result = {
    path: path.relative(releaseDir, databasePath),
    ok: false,
    error: null,
    integrityRows: [],
    issueCount: null,
    tables: {},
    tableCountError: null,
  }

  try {
    const rows = sqliteJson(databasePath, 'PRAGMA integrity_check;')
    const values = rows.map((row) => Object.values(row)[0])
    result.integrityRows = values
    result.ok = values.length === 1 && values[0] === 'ok'
    result.issueCount = result.ok ? 0 : values.length

    try {
      const tables = sqliteJson(
        databasePath,
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;",
      ).map((row) => row.name)

      for (const table of tables) {
        try {
          const countRows = sqliteJson(
            databasePath,
            `SELECT COUNT(*) AS count FROM ${quoteIdentifier(table)};`,
          )
          result.tables[table] = countRows[0]?.count ?? null
        } catch (error) {
          result.tables[table] = { error: error.message }
        }
      }
    } catch (error) {
      result.tableCountError = error.message
    }
  } catch (error) {
    result.error = error.message
    result.integrityRows = [error.message]
    result.issueCount = 1
  }

  return result
}

/** Fold WAL frames into a standalone SQLite DB and remove local sidecars. */
function normalizeDatabase(databasePath, releaseDir) {
  const cleanPath = `${databasePath}.clean`
  fs.rmSync(cleanPath, { force: true })

  const result = {
    path: path.relative(releaseDir, databasePath),
    ok: false,
    error: null,
  }

  try {
    sqliteExec(
      databasePath,
      `PRAGMA wal_checkpoint(TRUNCATE); VACUUM INTO ${quoteString(cleanPath)};`,
    )
    fs.renameSync(cleanPath, databasePath)
    fs.rmSync(`${databasePath}-wal`, { force: true })
    fs.rmSync(`${databasePath}-shm`, { force: true })
    result.ok = true
  } catch (error) {
    result.error = error.message
    fs.rmSync(cleanPath, { force: true })
  }

  return result
}

/** Compare table counts before and after normalization. */
function compareTableCounts(rawResult, normalizedResult) {
  const diffs = {}
  const rawTables = rawResult.tables ?? {}
  const normalizedTables = normalizedResult.tables ?? {}
  const tableNames = new Set([
    ...Object.keys(rawTables),
    ...Object.keys(normalizedTables),
  ])

  for (const tableName of [...tableNames].sort()) {
    if (
      JSON.stringify(rawTables[tableName]) !==
      JSON.stringify(normalizedTables[tableName])
    ) {
      diffs[tableName] = {
        raw: rawTables[tableName],
        normalized: normalizedTables[tableName],
      }
    }
  }

  return diffs
}

/** Normalize one service directory within a release. */
async function normalizeService(service, releaseDir, force) {
  const rawDir = path.join(releaseDir, service, 'raw')
  const normalizedDir = path.join(releaseDir, service, 'normalized')

  if (!fs.existsSync(rawDir)) {
    throw new Error(`Missing raw directory: ${rawDir}`)
  }

  if (fs.existsSync(normalizedDir)) {
    if (!force) {
      throw new Error(
        `Normalized directory already exists: ${normalizedDir}; use --force`,
      )
    }
    await fsp.rm(normalizedDir, { recursive: true, force: true })
  }

  await fsp.cp(rawDir, normalizedDir, { recursive: true, dereference: false })

  const rawResults = {}
  for (const databasePath of await listSqliteFiles(rawDir)) {
    rawResults[path.relative(rawDir, databasePath)] = checkIntegrity(
      databasePath,
      releaseDir,
    )
  }

  const normalizeResults = {}
  for (const databasePath of await listSqliteFiles(normalizedDir)) {
    normalizeResults[path.relative(normalizedDir, databasePath)] =
      normalizeDatabase(databasePath, releaseDir)
  }

  const normalizedResults = {}
  for (const databasePath of await listSqliteFiles(normalizedDir)) {
    normalizedResults[path.relative(normalizedDir, databasePath)] =
      checkIntegrity(databasePath, releaseDir)
  }

  const dbs = {}
  const relativePaths = new Set([
    ...Object.keys(rawResults),
    ...Object.keys(normalizedResults),
  ])

  for (const relativePath of [...relativePaths].sort()) {
    const raw = rawResults[relativePath] ?? {}
    const normalized = normalizedResults[relativePath] ?? {}
    const tableCountDiffs = compareTableCounts(raw, normalized)

    dbs[relativePath] = {
      rawOk: raw.ok ?? false,
      rawIssueCount: raw.issueCount ?? 1,
      normalizedOk: normalized.ok ?? false,
      normalizedIssueCount: normalized.issueCount ?? 1,
      integrityChanged:
        JSON.stringify(raw.integrityRows ?? []) !==
        JSON.stringify(normalized.integrityRows ?? []),
      tableCountDiffCount: Object.keys(tableCountDiffs).length,
      tableCountDiffs,
      normalizeOk: normalizeResults[relativePath]?.ok ?? false,
      normalizeError: normalizeResults[relativePath]?.error ?? null,
      rawError: raw.error ?? null,
      normalizedError: normalized.error ?? null,
      rawTables: raw.tables ?? {},
      normalizedTables: normalized.tables ?? {},
    }
  }

  return {
    rawDir,
    normalizedDir,
    dbCount: Object.keys(dbs).length,
    dbs,
  }
}

/** Build an aggregate integrity summary for all checked databases. */
function buildSummary(report) {
  const allDbs = []
  for (const [service, serviceReport] of Object.entries(report.services)) {
    for (const [databasePath, database] of Object.entries(serviceReport.dbs)) {
      allDbs.push({ service, databasePath, database })
    }
  }

  const problemDbs = allDbs
    .filter(
      ({ database }) =>
        !database.rawOk || !database.normalizedOk || !database.normalizeOk,
    )
    .map(({ service, databasePath, database }) => ({
      service,
      database: databasePath,
      rawOk: database.rawOk,
      normalizedOk: database.normalizedOk,
      normalizeError: database.normalizeError,
    }))

  return {
    dbCount: allDbs.length,
    rawOkCount: allDbs.filter(({ database }) => database.rawOk).length,
    rawProblemCount: allDbs.filter(({ database }) => !database.rawOk).length,
    normalizedOkCount: allDbs.filter(({ database }) => database.normalizedOk)
      .length,
    normalizedProblemCount: allDbs.filter(
      ({ database }) => !database.normalizedOk,
    ).length,
    integrityChangedCount: allDbs.filter(
      ({ database }) => database.integrityChanged,
    ).length,
    tableCountChangedDbCount: allDbs.filter(
      ({ database }) => database.tableCountDiffCount > 0,
    ).length,
    normalizationFailedCount: allDbs.filter(
      ({ database }) => !database.normalizeOk,
    ).length,
    problemDbs,
    changedIntegrityDbs: allDbs
      .filter(({ database }) => database.integrityChanged)
      .map(({ service, databasePath, database }) => ({
        service,
        database: databasePath,
        rawIssueCount: database.rawIssueCount,
        normalizedIssueCount: database.normalizedIssueCount,
      })),
    changedTableCountDbs: allDbs
      .filter(({ database }) => database.tableCountDiffCount > 0)
      .map(({ service, databasePath, database }) => ({
        service,
        database: databasePath,
        diffCount: database.tableCountDiffCount,
      })),
  }
}

/** Write a concise Markdown summary for humans. */
async function writeMarkdownSummary(report, summaryPath) {
  const summary = report.summary
  const lines = [
    '# SQLite integrity summary\n\n',
    `Release: \`${report.releaseDir}\`\n\n`,
    `DBs checked: ${summary.dbCount}\n\n`,
    `Raw integrity OK: ${summary.rawOkCount} / ${summary.dbCount}\n\n`,
    `Normalized integrity OK: ${summary.normalizedOkCount} / ${summary.dbCount}\n\n`,
    `Integrity result changed after normalization: ${summary.integrityChangedCount} DBs\n\n`,
    `Table counts changed after normalization: ${summary.tableCountChangedDbCount} DBs\n\n`,
    `Normalization failures: ${summary.normalizationFailedCount} DBs\n`,
  ]

  if (summary.problemDbs.length > 0) {
    lines.push('\n## Problem DBs\n')
    for (const item of summary.problemDbs) {
      lines.push(
        `- ${item.service}/${item.database}: rawOk=${item.rawOk} normalizedOk=${item.normalizedOk} normalizeError=${item.normalizeError}\n`,
      )
    }
  }

  if (summary.changedIntegrityDbs.length > 0) {
    lines.push('\n## Integrity changes\n')
    for (const item of summary.changedIntegrityDbs) {
      lines.push(
        `- ${item.service}/${item.database}: raw issues=${item.rawIssueCount} normalized issues=${item.normalizedIssueCount}\n`,
      )
    }
  }

  if (summary.changedTableCountDbs.length > 0) {
    lines.push('\n## Table-count changes\n')
    for (const item of summary.changedTableCountDbs) {
      lines.push(
        `- ${item.service}/${item.database}: ${item.diffCount} table(s) changed\n`,
      )
    }
  }

  await fsp.writeFile(summaryPath, lines.join(''))
}

/** Run normalization and reporting. */
async function main() {
  const args = parseArgs(process.argv.slice(2))
  const releaseDir = path.resolve(args.releaseDir)

  if (!commandExists('sqlite3')) {
    throw new Error('sqlite3 CLI is required but was not found on PATH')
  }

  const report = {
    releaseDir,
    startedAt: new Date().toISOString(),
    services: {},
  }

  for (const service of SERVICES) {
    report.services[service] = await normalizeService(
      service,
      releaseDir,
      args.force,
    )
  }

  report.summary = buildSummary(report)

  const reportPath = path.join(releaseDir, 'sqlite-integrity-report.json')
  const summaryPath = path.join(releaseDir, 'sqlite-integrity-summary.md')
  await fsp.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`)
  await writeMarkdownSummary(report, summaryPath)

  console.log(JSON.stringify(report.summary, null, 2))
  console.log(`report=${reportPath}`)
  console.log(`summary=${summaryPath}`)

  if (report.summary.problemDbs.length > 0) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(`standby-normalize-sqlite: ${error.message}`)
  process.exit(1)
})
