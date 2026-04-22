import { describe, it, expect } from 'vitest'
import { createLogger } from '../logger.js'

describe('createLogger', () => {
  it('returns a pino logger instance with the given name', () => {
    const logger = createLogger('test-logger')
    expect(logger).toBeDefined()
    // pino loggers have standard level methods
    expect(typeof logger.info).toBe('function')
    expect(typeof logger.error).toBe('function')
    expect(typeof logger.warn).toBe('function')
    expect(typeof logger.debug).toBe('function')
    expect(typeof logger.trace).toBe('function')
    expect(typeof logger.fatal).toBe('function')
  })

  it('creates loggers with different names', () => {
    const logger1 = createLogger('service-a')
    const logger2 = createLogger('service-b')
    expect(logger1).not.toBe(logger2)
  })

  it('logger has a child method', () => {
    const logger = createLogger('parent')
    expect(typeof logger.child).toBe('function')
  })
})
