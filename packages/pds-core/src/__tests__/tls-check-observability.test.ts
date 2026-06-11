/**
 * Unit tests for `/tls-check` observability helpers.
 *
 * The route itself is integration-level glue, so these tests keep coverage on
 * the extracted classifier and observer that generate future incident logs.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  TlsCheckObserver,
  classifyTlsCheckDomain,
  type TlsCheckClassifierOptions,
  type TlsCheckLogger,
} from '../lib/tls-check-observability.js'

const classifier: TlsCheckClassifierOptions = {
  pdsHostname: 'climateai.org',
  authHostname: 'auth.climateai.org',
  serviceHandleDomains: ['.climateai.org'],
}

describe('classifyTlsCheckDomain', () => {
  it('classifies apex, auth, hosted handles, nested names, unsupported names, and missing domains', () => {
    expect(classifyTlsCheckDomain(undefined, classifier)).toBe('missing')
    expect(classifyTlsCheckDomain('climateai.org', classifier)).toBe('apex')
    expect(classifyTlsCheckDomain('auth.climateai.org', classifier)).toBe(
      'auth',
    )
    expect(classifyTlsCheckDomain('alice.climateai.org', classifier)).toBe(
      'oneLabel',
    )
    expect(classifyTlsCheckDomain('a.b.climateai.org', classifier)).toBe(
      'nested',
    )
    expect(classifyTlsCheckDomain('example.com', classifier)).toBe(
      'unsupported',
    )
  })
})

describe('TlsCheckObserver', () => {
  it('logs slow requests and aggregate summaries', () => {
    let nowMs = 1_000
    const logger = mockLogger()
    const observer = new TlsCheckObserver({
      logger,
      classifier,
      enableEventLoopMonitor: false,
      summaryIntervalMs: 0,
      slowRequestMs: 1_000,
      nowMs: () => nowMs,
    })

    const scope = observer.begin('a.b.climateai.org')
    nowMs += 200
    scope.recordAccountLookup(200)
    nowMs += 1_050
    scope.complete(400)
    observer.flush()
    observer.stop()

    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        domain: 'a.b.climateai.org',
        domainClass: 'nested',
        durationMs: 1_250,
        statusCode: 400,
        inflight: 0,
      }),
      'tls-check slow',
    )
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        window: {
          started: 1,
          completed: 1,
          aborted: 0,
          failed: 0,
          inflight: 0,
          maxInflight: 1,
        },
        status: { '400': 1 },
        domainClass: { nested: 1 },
        durationMs: {
          count: 1,
          min: 1_250,
          p50: 1_250,
          p95: 1_250,
          p99: 1_250,
          max: 1_250,
        },
        accountLookupMs: {
          count: 1,
          min: 200,
          p50: 200,
          p95: 200,
          p99: 200,
          max: 200,
        },
        eventLoopLagMs: undefined,
      }),
      'tls-check summary',
    )
  })

  it('suppresses individual warning logs after the per-window limit', () => {
    let nowMs = 0
    const logger = mockLogger()
    const observer = new TlsCheckObserver({
      logger,
      classifier,
      enableEventLoopMonitor: false,
      individualLogLimitPerWindow: 1,
      summaryIntervalMs: 0,
      slowRequestMs: 100,
      nowMs: () => nowMs,
    })

    const first = observer.begin('a.b.climateai.org')
    nowMs = 150
    first.complete(400)
    const second = observer.begin('c.d.climateai.org')
    nowMs = 300
    second.complete(400)
    observer.flush()
    observer.stop()

    expect(logger.warn).toHaveBeenCalledOnce()
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        individualLogSuppressed: { slow: 1 },
      }),
      'tls-check summary',
    )
  })

  it('logs aborted requests and keeps inflight counts across summary windows', () => {
    let nowMs = 0
    const logger = mockLogger()
    const observer = new TlsCheckObserver({
      logger,
      classifier,
      enableEventLoopMonitor: false,
      summaryIntervalMs: 0,
      nowMs: () => nowMs,
    })

    const scope = observer.begin('alice.climateai.org')
    observer.flush()
    nowMs = 750
    scope.abort()
    scope.recordAccountLookup(500)
    observer.flush()
    observer.stop()

    expect(logger.info).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        window: expect.objectContaining({
          started: 1,
          completed: 0,
          aborted: 0,
          inflight: 1,
          maxInflight: 1,
        }),
        domainClass: { oneLabel: 1 },
      }),
      'tls-check summary',
    )
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        domain: 'alice.climateai.org',
        domainClass: 'oneLabel',
        durationMs: 750,
        inflight: 0,
      }),
      'tls-check aborted',
    )
    expect(logger.info).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        window: expect.objectContaining({
          started: 0,
          completed: 0,
          aborted: 1,
          inflight: 0,
          maxInflight: 1,
        }),
        accountLookupMs: { count: 0 },
      }),
      'tls-check summary',
    )
  })
})

function mockLogger(): TlsCheckLogger & {
  info: ReturnType<typeof vi.fn<TlsCheckLogger['info']>>
  warn: ReturnType<typeof vi.fn<TlsCheckLogger['warn']>>
} {
  return {
    info: vi.fn<TlsCheckLogger['info']>(),
    warn: vi.fn<TlsCheckLogger['warn']>(),
  }
}
