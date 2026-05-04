/**
 * Shared test helpers for the /preview/chooser and /preview/consent
 * route tests. Both suites need a captured-response stub and a logger
 * mock with the same shape; pulling them in here keeps Sonar happy
 * about new-code duplication and gives the suites a single place to
 * grow the mock when the handler signature changes.
 */
import { vi } from 'vitest'

export function mockLogger() {
  return { info: vi.fn(), warn: vi.fn(), debug: vi.fn() }
}

export type CapturedRes = {
  headers: Record<string, string>
  body: string | null
  setHeader: (name: string, value: string) => void
  send: (body: string) => void
}

export function mockRes(): CapturedRes {
  const res: CapturedRes = {
    headers: {},
    body: null,
    setHeader(name, value) {
      this.headers[name] = value
    },
    send(body) {
      this.body = body
    },
  }
  return res
}
