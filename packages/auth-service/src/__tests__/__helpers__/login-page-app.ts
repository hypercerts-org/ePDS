/**
 * The login page router (GET /oauth/authorize) on an ephemeral 127.0.0.1
 * port, backed by a temporary SQLite file, for route-level tests. The
 * client metadata for https://app.example.com is seeded so rendering makes
 * no outbound fetch. better-auth is a stand-in: tests that start a social
 * sign-in pass their own.
 */
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import type { AddressInfo } from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import cookieParser from 'cookie-parser'
import express from 'express'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import type { BetterAuthInstance } from '../../better-auth.js'
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
  /** The router's context, for assertions against its database. */
  ctx: AuthServiceContext
  /** Stop the server, close the database and delete its files. */
  close: () => Promise<void>
}

/** The part of better-auth the login page router uses. */
export type LoginPageAuth = Pick<BetterAuthInstance, 'api'>

/** A better-auth stand-in for tests that never start a social sign-in. */
const NO_SOCIAL_START = {
  api: {
    signInSocial: () => {
      throw new Error('unexpected social sign-in start')
    },
  },
} as unknown as LoginPageAuth

export async function startLoginPageApp(
  dbPrefix: string,
  auth: LoginPageAuth = NO_SOCIAL_START,
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
  app.use(createLoginPageRouter(ctx, auth))
  const server = app.listen(0, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    ctx,
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
