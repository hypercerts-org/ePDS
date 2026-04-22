import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// packages/shared/{src,dist}/ → repo root is always three levels up
const ROOT = join(__dirname, '..', '..', '..')

/**
 * Resolve the ePDS version string.
 *
 * Precedence:
 *   1. `EPDS_VERSION` env var (operator override, e.g. `0.2.2+abcdef01`)
 *   2. `.epds-version` file written at Docker build time
 *   3. `version` field from the root `package.json` (dev / non-Docker)
 *
 * Throws if none of the above can be resolved — this indicates a broken
 * build or missing repo root, not a condition to silently degrade from.
 */
export function getEpdsVersion(): string {
  if (process.env.EPDS_VERSION) {
    return process.env.EPDS_VERSION
  }

  try {
    const v = readFileSync(join(ROOT, '.epds-version'), 'utf8').trim()
    if (v) return v
  } catch {
    // .epds-version not present — fall through to package.json
  }

  const pkgPath = join(ROOT, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
  return pkg.version
}
