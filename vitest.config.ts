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
      exclude: ['packages/*/src/__tests__/**', '**/*.test.ts', '**/*.d.ts'],
      // Baseline thresholds — ratchet these up as coverage improves
      thresholds: {
        statements: 20,
        branches: 13,
        functions: 34,
        lines: 20,
      },
    },
  },
})
