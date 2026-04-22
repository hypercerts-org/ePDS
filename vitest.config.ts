import { defineConfig } from 'vitest/config'
import * as path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@/': path.resolve(__dirname, 'packages/demo/src') + '/',
    },
  },
  test: {
    include: ['packages/*/src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: './coverage',
      include: ['packages/*/src/**/*.ts'],
      exclude: [
        'packages/*/src/__tests__/**',
        '**/*.test.ts',
        '**/*.d.ts',
        'packages/shared/src/version.ts',
      ],
      // Ratchet thresholds — update these whenever coverage increases.
      // See AGENTS.md for the ratcheting policy.
      thresholds: {
        statements: 37,
        branches: 33,
        functions: 54,
        lines: 36,
      },
    },
  },
})
