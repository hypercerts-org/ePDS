import type { NextConfig } from 'next'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

function resolveVersion(): string {
  if (process.env.NEXT_PUBLIC_EPDS_VERSION) {
    return process.env.NEXT_PUBLIC_EPDS_VERSION
  }
  // In dev: read from root package.json
  const root = join(import.meta.dirname, '..', '..')
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  return pkg.version
}

const nextConfig: NextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_EPDS_VERSION: resolveVersion(),
  },
}

export default nextConfig
