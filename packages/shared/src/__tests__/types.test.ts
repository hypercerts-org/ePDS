import { describe, it, expect } from 'vitest'
import { DEFAULT_RATE_LIMITS } from '../types.js'
import type {
  RateLimitConfig,
  EpdsLinkConfig,
  EmailConfig,
  AuthConfig,
} from '../types.js'

describe('DEFAULT_RATE_LIMITS', () => {
  it('has expected default values', () => {
    expect(DEFAULT_RATE_LIMITS.emailPer15Min).toBe(3)
    expect(DEFAULT_RATE_LIMITS.emailPerHour).toBe(5)
    expect(DEFAULT_RATE_LIMITS.ipPer15Min).toBe(10)
    expect(DEFAULT_RATE_LIMITS.globalPerMinute).toBe(30)
  })

  it('satisfies the RateLimitConfig interface', () => {
    const config: RateLimitConfig = DEFAULT_RATE_LIMITS
    expect(config).toBeDefined()
    expect(typeof config.emailPer15Min).toBe('number')
    expect(typeof config.emailPerHour).toBe('number')
    expect(typeof config.ipPer15Min).toBe('number')
    expect(typeof config.globalPerMinute).toBe('number')
  })
})

describe('Type interfaces (compile-time checks)', () => {
  it('EpdsLinkConfig has expected shape', () => {
    const config: EpdsLinkConfig = {
      expiryMinutes: 10,
      maxAttemptsPerToken: 5,
    }
    expect(config.expiryMinutes).toBe(10)
    expect(config.maxAttemptsPerToken).toBe(5)
  })

  it('EmailConfig has expected shape', () => {
    const config: EmailConfig = {
      provider: 'smtp',
      from: 'noreply@test.com',
      fromName: 'Test',
    }
    expect(config.provider).toBe('smtp')
    expect(config.from).toBe('noreply@test.com')
  })

  it('AuthConfig has expected shape', () => {
    const config: AuthConfig = {
      hostname: 'auth.example.com',
      port: 3001,
      sessionSecret: 'secret',
      csrfSecret: 'csrf-secret',
      pdsHostname: 'pds.example.com',
      pdsPublicUrl: 'https://pds.example.com',
      verificationLink: { expiryMinutes: 10, maxAttemptsPerToken: 5 },
      email: {
        provider: 'smtp',
        from: 'noreply@test.com',
        fromName: 'Test',
      },
      dbLocation: ':memory:',
    }
    expect(config.hostname).toBe('auth.example.com')
  })
})
