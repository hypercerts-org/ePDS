/**
 * The login page router (GET /oauth/authorize) on an ephemeral 127.0.0.1
 * port, backed by a temporary SQLite file, for route-level tests. The
 * client metadata for https://app.example.com is seeded so rendering makes
 * no outbound fetch.
 */
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import type { AddressInfo } from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import cookieParser from 'cookie-parser'
import express from 'express'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import { AuthServiceContext, type AuthServiceConfig } from '../../context.js'
import { csrfProtection } from '../../middleware/csrf.js'
import { createLoginPageRouter } from '../../routes/login-page.js'

function makeConfig(dbPath: string): AuthServiceConfig {
  return {
    hostname: 'auth.test.local',
    port: 0,
    sessionSecret: 'test-session-secret',
    epdsCallbackSecret: 'test-callback-secret',
    pdsHostname: 'test.local',
    pdsPublicUrl: 'https://test.local',
    email: {
      provider: 'smtp',
      smtpHost: 'localhost',
      smtpPort: 1025,
      from: 'noreply@test.local',
      fromName: 'ePDS Test',
    },
    dbLocation: dbPath,
    otpLength: 6,
    otpCharset: 'numeric',
    trustedClients: [],
  }
}

export interface LoginPageApp {
  baseUrl: string
  /** Stop the server, close the database and delete its files. */
  close: () => Promise<void>
}

export async function startLoginPageApp(
  dbPrefix: string,
): Promise<LoginPageApp> {
  const dbPath = path.join(
    os.tmpdir(),
    `${dbPrefix}-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
  )
  _seedClientMetadataCacheForTest('https://app.example.com', {
    client_name: 'Test App',
  })
  // AuthServiceContext opens its own EpdsDb against config.dbLocation, so
  // there is exactly one open SQLite handle; ctx.destroy() closes it and
  // releases the WAL/SHM companion files for the unlink to remove.
  const ctx = new AuthServiceContext(makeConfig(dbPath))
  const app = express()
  // An in-process test server on 127.0.0.1; disabling the header keeps
  // Sonar's framework-disclosure hotspot quiet.
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(csrfProtection())
  app.use(createLoginPageRouter(ctx))
  const server = app.listen(0)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      })
      ctx.destroy()
      for (const suffix of ['', '-wal', '-shm']) {
        fs.rmSync(dbPath + suffix, { force: true })
      }
    },
  }
}
