/**
 * Tests for applyPdsPortFallback().
 *
 * Verifies the PORT → PDS_PORT fallback logic without mutating process.env
 * directly — the helper accepts an env object for testability.
 */
import { describe, it, expect } from 'vitest'
import { applyPdsPortFallback } from '../lib/resolve-port.js'

describe('applyPdsPortFallback', () => {
  it('copies PORT to PDS_PORT when PDS_PORT is unset', () => {
    const env: NodeJS.ProcessEnv = { PORT: '8080' }
    applyPdsPortFallback(env)
    expect(env.PDS_PORT).toBe('8080')
  })

  it('does not overwrite PDS_PORT when it is already set', () => {
    const env: NodeJS.ProcessEnv = { PDS_PORT: '3000', PORT: '8080' }
    applyPdsPortFallback(env)
    expect(env.PDS_PORT).toBe('3000')
  })

  it('does nothing when neither PDS_PORT nor PORT is set', () => {
    const env: NodeJS.ProcessEnv = {}
    applyPdsPortFallback(env)
    expect(env.PDS_PORT).toBeUndefined()
  })

  it('does nothing when PORT is unset even if PDS_PORT is unset', () => {
    const env: NodeJS.ProcessEnv = { OTHER: 'value' }
    applyPdsPortFallback(env)
    expect(env.PDS_PORT).toBeUndefined()
  })
})
