#!/usr/bin/env node
/**
 * Compare a source ePDS and a local/standby ePDS over public XRPC endpoints.
 *
 * This validates that a restored standby can actually serve AT Protocol repo
 * data, not just that SQLite files can be opened.
 */
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash } from 'node:crypto'

const DEFAULT_SOURCE_URL = 'https://epds1.test.certified.app'

/** Print usage information for the XRPC validation script. */
function printUsage() {
  console.log(`Usage: scripts/standby-validate-xrpc.mjs --release-dir <dir> --target-url <url> [options]

Compares source and target PDS XRPC responses and writes reports under
<release-dir>/xrpc.

Options:
  --release-dir <dir>       Release directory to store reports
  --source-url <url>        Source PDS URL [default: ${DEFAULT_SOURCE_URL}]
  --target-url <url>        Target/local PDS URL, e.g. http://localhost:3100
  --limit <n>               listRepos limit [default: 1000]
  --sample-count <n>        Number of sample repos for deeper checks [default: 3]
  --record <at-uri|path>    Compare a specific record; can be repeated
                            formats: at://did/collection/rkey or did/collection/rkey
  --describe-repo <did>     Compare describeRepo for a DID; can be repeated
  --skip-car                Skip byte-for-byte com.atproto.sync.getRepo checks
  --help                    Show this help text`)
}

/** Parse command-line flags for XRPC validation. */
function parseArgs(argv) {
  const args = {
    releaseDir: null,
    sourceUrl: DEFAULT_SOURCE_URL,
    targetUrl: null,
    limit: 1000,
    sampleCount: 3,
    records: [],
    describeRepos: [],
    skipCar: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--help' || arg === '-h') {
      printUsage()
      process.exit(0)
    }
    if (arg === '--skip-car') {
      args.skipCar = true
      continue
    }

    const repeatedOptions = new Map([
      ['--record', 'records'],
      ['--describe-repo', 'describeRepos'],
    ])
    if (repeatedOptions.has(arg)) {
      const value = argv[index + 1]
      if (!value || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`)
      }
      args[repeatedOptions.get(arg)].push(value)
      index += 1
      continue
    }

    const valueOptions = new Map([
      ['--release-dir', 'releaseDir'],
      ['--source-url', 'sourceUrl'],
      ['--target-url', 'targetUrl'],
      ['--limit', 'limit'],
      ['--sample-count', 'sampleCount'],
    ])
    if (valueOptions.has(arg)) {
      const value = argv[index + 1]
      if (!value || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`)
      }
      const key = valueOptions.get(arg)
      args[key] =
        key === 'limit' || key === 'sampleCount' ? Number(value) : value
      index += 1
      continue
    }

    throw new Error(`Unknown option: ${arg}`)
  }

  if (!args.releaseDir) {
    throw new Error('Missing required --release-dir')
  }
  if (!args.targetUrl) {
    throw new Error('Missing required --target-url')
  }
  if (!Number.isInteger(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive integer')
  }
  if (!Number.isInteger(args.sampleCount) || args.sampleCount < 0) {
    throw new Error('--sample-count must be a non-negative integer')
  }

  return args
}

/** Return a base URL without trailing slashes. */
function cleanBaseUrl(url) {
  return url.replace(/\/+$/, '')
}

/** Return a SHA-256 hex digest for a Buffer. */
function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

/** Build an XRPC URL with query parameters. */
function xrpcUrl(baseUrl, nsid, params) {
  const url = new URL(`${cleanBaseUrl(baseUrl)}/xrpc/${nsid}`)
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, String(value))
  }
  return url
}

/** Fetch an XRPC endpoint as bytes, failing on non-2xx responses. */
async function fetchBytes(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': 'epds-standby-validate/1' },
  })
  const body = Buffer.from(await response.arrayBuffer())
  if (!response.ok) {
    throw new Error(
      `${url} returned ${response.status}: ${body.toString('utf8')}`,
    )
  }
  return body
}

/** Fetch an XRPC endpoint as JSON plus its raw bytes. */
async function fetchJson(url) {
  const body = await fetchBytes(url)
  return { body, json: JSON.parse(body.toString('utf8')) }
}

/** Parse a record argument into repo, collection, and rkey. */
function parseRecordSpec(spec) {
  const withoutScheme = spec.startsWith('at://')
    ? spec.slice('at://'.length)
    : spec
  const firstSlash = withoutScheme.indexOf('/')
  const lastSlash = withoutScheme.lastIndexOf('/')

  if (firstSlash <= 0 || lastSlash <= firstSlash) {
    throw new Error(
      `Invalid record spec ${spec}; expected at://did/collection/rkey or did/collection/rkey`,
    )
  }

  return {
    repo: withoutScheme.slice(0, firstSlash),
    collection: withoutScheme.slice(firstSlash + 1, lastSlash),
    rkey: withoutScheme.slice(lastSlash + 1),
  }
}

/** Pick deterministic sample DIDs from a sorted DID list. */
function chooseSampleDids(dids, sampleCount) {
  if (sampleCount === 0 || dids.length === 0) {
    return []
  }

  if (sampleCount >= dids.length) {
    return dids
  }

  const sample = []
  for (let index = 0; index < sampleCount; index += 1) {
    const position = Math.round(
      (index * (dids.length - 1)) / (sampleCount - 1 || 1),
    )
    const did = dids[position]
    if (!sample.includes(did)) {
      sample.push(did)
    }
  }
  return sample
}

/** Compare listRepos responses at repo head/rev/status level. */
function compareListRepos(sourceList, targetList) {
  const sourceRepos = new Map(sourceList.repos.map((repo) => [repo.did, repo]))
  const targetRepos = new Map(targetList.repos.map((repo) => [repo.did, repo]))
  const missingTarget = [...sourceRepos.keys()]
    .filter((did) => !targetRepos.has(did))
    .sort()
  const extraTarget = [...targetRepos.keys()]
    .filter((did) => !sourceRepos.has(did))
    .sort()
  const fieldDiffs = []
  const fields = ['head', 'rev', 'active', 'status']

  for (const did of [...sourceRepos.keys()].sort()) {
    if (!targetRepos.has(did)) {
      continue
    }
    const source = sourceRepos.get(did)
    const target = targetRepos.get(did)
    const diffs = {}
    for (const field of fields) {
      if (source[field] !== target[field]) {
        diffs[field] = { source: source[field], target: target[field] }
      }
    }
    if (Object.keys(diffs).length > 0) {
      fieldDiffs.push({ did, diffs })
    }
  }

  return { sourceRepos, targetRepos, missingTarget, extraTarget, fieldDiffs }
}

/** Compare a JSON endpoint on source and target. */
async function compareJsonEndpoint({ sourceUrl, targetUrl, nsid, params }) {
  const source = await fetchJson(xrpcUrl(sourceUrl, nsid, params))
  const target = await fetchJson(xrpcUrl(targetUrl, nsid, params))
  return {
    match: JSON.stringify(source.json) === JSON.stringify(target.json),
    sourceSha256: sha256(source.body),
    targetSha256: sha256(target.body),
    source: source.json,
    target: target.json,
  }
}

/** Compare a byte endpoint on source and target. */
async function compareByteEndpoint({ sourceUrl, targetUrl, nsid, params }) {
  const source = await fetchBytes(xrpcUrl(sourceUrl, nsid, params))
  const target = await fetchBytes(xrpcUrl(targetUrl, nsid, params))
  return {
    match: source.equals(target),
    sourceSize: source.length,
    targetSize: target.length,
    sourceSha256: sha256(source),
    targetSha256: sha256(target),
  }
}

/** Write a Markdown summary for the XRPC comparison report. */
async function writeMarkdownSummary(report, summaryPath) {
  const lines = [
    '# XRPC comparison summary\n\n',
    `Source: \`${report.sourceUrl}\`\n\n`,
    `Target: \`${report.targetUrl}\`\n\n`,
    `Repos source/target: ${report.repoCountSource} / ${report.repoCountTarget}\n\n`,
    `Cursor source/target: \`${report.cursorSource}\` / \`${report.cursorTarget}\`\n\n`,
    `Missing on target: ${report.missingTargetCount}\n\n`,
    `Extra on target: ${report.extraTargetCount}\n\n`,
    `Head/rev/status diffs: ${report.fieldDiffCount}\n\n`,
    `Sample repos checked: ${report.sampleResults.length}\n\n`,
    `Record checks: ${report.recordResults.length}\n\n`,
    `describeRepo checks: ${report.describeRepoResults.length}\n\n`,
    `Overall match: ${report.overallMatch}\n`,
  ]

  for (const sample of report.sampleResults) {
    lines.push(`\n## Sample ${sample.did}\n`)
    for (const [endpoint, result] of Object.entries(sample.endpoints)) {
      lines.push(`- ${endpoint}: match=${result.match}`)
      if (result.sourceSha256) {
        lines.push(
          ` sourceSha256=${result.sourceSha256} targetSha256=${result.targetSha256}`,
        )
      }
      lines.push('\n')
    }
  }

  for (const record of report.recordResults) {
    lines.push(`\n## Record ${record.spec}\n`)
    lines.push(
      `- match=${record.result.match} sourceSha256=${record.result.sourceSha256} targetSha256=${record.result.targetSha256}\n`,
    )
  }

  for (const describe of report.describeRepoResults) {
    lines.push(`\n## describeRepo ${describe.did}\n`)
    lines.push(
      `- match=${describe.result.match} sourceSha256=${describe.result.sourceSha256} targetSha256=${describe.result.targetSha256}\n`,
    )
  }

  await fs.writeFile(summaryPath, lines.join(''))
}

/** Compare source and target PDS instances over XRPC. */
async function main() {
  const args = parseArgs(process.argv.slice(2))
  const releaseDir = path.resolve(args.releaseDir)
  const xrpcDir = path.join(releaseDir, 'xrpc')
  await fs.mkdir(xrpcDir, { recursive: true })

  const sourceUrl = cleanBaseUrl(args.sourceUrl)
  const targetUrl = cleanBaseUrl(args.targetUrl)

  const sourceListResult = await fetchJson(
    xrpcUrl(sourceUrl, 'com.atproto.sync.listRepos', { limit: args.limit }),
  )
  const targetListResult = await fetchJson(
    xrpcUrl(targetUrl, 'com.atproto.sync.listRepos', { limit: args.limit }),
  )

  await fs.writeFile(
    path.join(xrpcDir, 'source-listRepos.json'),
    `${JSON.stringify(sourceListResult.json, null, 2)}\n`,
  )
  await fs.writeFile(
    path.join(xrpcDir, 'target-listRepos.json'),
    `${JSON.stringify(targetListResult.json, null, 2)}\n`,
  )

  const comparison = compareListRepos(
    sourceListResult.json,
    targetListResult.json,
  )
  const sampleDids = chooseSampleDids(
    [...comparison.sourceRepos.keys()].sort(),
    args.sampleCount,
  )

  const sampleResults = []
  for (const did of sampleDids) {
    const endpoints = {
      'com.atproto.sync.getRepoStatus': await compareJsonEndpoint({
        sourceUrl,
        targetUrl,
        nsid: 'com.atproto.sync.getRepoStatus',
        params: { did },
      }),
      'com.atproto.sync.getLatestCommit': await compareJsonEndpoint({
        sourceUrl,
        targetUrl,
        nsid: 'com.atproto.sync.getLatestCommit',
        params: { did },
      }),
    }

    if (!args.skipCar) {
      endpoints['com.atproto.sync.getRepo'] = await compareByteEndpoint({
        sourceUrl,
        targetUrl,
        nsid: 'com.atproto.sync.getRepo',
        params: { did },
      })
    }

    sampleResults.push({ did, endpoints })
  }

  const recordResults = []
  for (const spec of args.records) {
    const record = parseRecordSpec(spec)
    recordResults.push({
      spec,
      record,
      result: await compareJsonEndpoint({
        sourceUrl,
        targetUrl,
        nsid: 'com.atproto.repo.getRecord',
        params: record,
      }),
    })
  }

  const describeRepoResults = []
  for (const did of args.describeRepos) {
    describeRepoResults.push({
      did,
      result: await compareJsonEndpoint({
        sourceUrl,
        targetUrl,
        nsid: 'com.atproto.repo.describeRepo',
        params: { repo: did },
      }),
    })
  }

  const sampleMismatches = sampleResults.flatMap((sample) =>
    Object.entries(sample.endpoints)
      .filter(([, result]) => !result.match)
      .map(([endpoint]) => ({ did: sample.did, endpoint })),
  )
  const recordMismatches = recordResults.filter(
    (record) => !record.result.match,
  )
  const describeMismatches = describeRepoResults.filter(
    (describe) => !describe.result.match,
  )

  const report = {
    sourceUrl,
    targetUrl,
    repoCountSource: sourceListResult.json.repos?.length ?? 0,
    repoCountTarget: targetListResult.json.repos?.length ?? 0,
    cursorSource: sourceListResult.json.cursor ?? null,
    cursorTarget: targetListResult.json.cursor ?? null,
    missingTargetCount: comparison.missingTarget.length,
    extraTargetCount: comparison.extraTarget.length,
    fieldDiffCount: comparison.fieldDiffs.length,
    missingTarget: comparison.missingTarget,
    extraTarget: comparison.extraTarget,
    fieldDiffs: comparison.fieldDiffs,
    sampleDids,
    sampleResults,
    recordResults,
    describeRepoResults,
    sampleMismatches,
    recordMismatches,
    describeMismatches,
  }

  report.overallMatch =
    report.repoCountSource === report.repoCountTarget &&
    report.cursorSource === report.cursorTarget &&
    report.missingTargetCount === 0 &&
    report.extraTargetCount === 0 &&
    report.fieldDiffCount === 0 &&
    sampleMismatches.length === 0 &&
    recordMismatches.length === 0 &&
    describeMismatches.length === 0

  const reportPath = path.join(xrpcDir, 'xrpc-compare-report.json')
  const summaryPath = path.join(xrpcDir, 'xrpc-compare-summary.md')
  await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`)
  await writeMarkdownSummary(report, summaryPath)

  console.log(
    JSON.stringify(
      {
        overallMatch: report.overallMatch,
        repoCountSource: report.repoCountSource,
        repoCountTarget: report.repoCountTarget,
        cursorMatch: report.cursorSource === report.cursorTarget,
        missingTargetCount: report.missingTargetCount,
        extraTargetCount: report.extraTargetCount,
        fieldDiffCount: report.fieldDiffCount,
        sampleCount: report.sampleResults.length,
        sampleMismatchCount: sampleMismatches.length,
        recordMismatchCount: recordMismatches.length,
        describeRepoMismatchCount: describeMismatches.length,
        report: reportPath,
        summary: summaryPath,
      },
      null,
      2,
    ),
  )

  if (!report.overallMatch) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(`standby-validate-xrpc: ${error.message}`)
  process.exit(1)
})
