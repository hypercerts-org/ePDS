import { describe, it, expect, afterEach } from 'vitest'
import { requireEnv } from '../require-env.js'

describe('requireEnv', () => {
  const ORIGINAL_ENV = process.env

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV }
  })

  function setEnv(vars: Record<string, string | undefined>) {
    process.env = { ...ORIGINAL_ENV, ...vars }
  }

  it('returns the value when the variable is set', () => {
    setEnv({ AUTH_SESSION_SECRET: 's3cret' })
    expect(requireEnv('AUTH_SESSION_SECRET')).toBe('s3cret')
  })

  it('throws when the variable is unset', () => {
    setEnv({ AUTH_SESSION_SECRET: undefined })
    expect(() => requireEnv('AUTH_SESSION_SECRET')).toThrow(
      'Missing required environment variable: AUTH_SESSION_SECRET',
    )
  })

  // An empty value is as dangerous as an absent one — it would silently
  // produce unsigned cookies rather than failing loudly.
  it('throws when the variable is set but empty', () => {
    setEnv({ EPDS_CALLBACK_SECRET: '' })
    expect(() => requireEnv('EPDS_CALLBACK_SECRET')).toThrow(
      'Missing required environment variable: EPDS_CALLBACK_SECRET',
    )
  })

  // Whitespace-only is effectively empty for a secret: it would boot with an
  // unusable value rather than failing loudly, so trim before checking.
  it('throws when the variable is set but whitespace-only', () => {
    setEnv({ EPDS_CALLBACK_SECRET: '   ' })
    expect(() => requireEnv('EPDS_CALLBACK_SECRET')).toThrow(
      'Missing required environment variable: EPDS_CALLBACK_SECRET',
    )
  })

  it('names the offending variable and how to generate one', () => {
    setEnv({ EPDS_CALLBACK_SECRET: undefined })
    expect(() => requireEnv('EPDS_CALLBACK_SECRET')).toThrow(
      'Missing required environment variable: EPDS_CALLBACK_SECRET. Generate a value with: openssl rand -hex 32',
    )
  })
})
