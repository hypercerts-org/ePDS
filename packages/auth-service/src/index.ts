import { createLogger } from '@certified-app/shared'
import express from 'express'
import cookieParser from 'cookie-parser'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))
import { toNodeHandler } from 'better-auth/node'
import { AuthServiceContext, type AuthServiceConfig } from './context.js'
import { createBetterAuth, runBetterAuthMigrations } from './better-auth.js'
import { csrfProtection } from './middleware/csrf.js'
import { requestRateLimit } from './middleware/rate-limit.js'
import { createLoginPageRouter } from './routes/login-page.js'
import { createRecoveryRouter } from './routes/recovery.js'
import { createAccountLoginRouter } from './routes/account-login.js'
import { createAccountSettingsRouter } from './routes/account-settings.js'
import { createCompleteRouter } from './routes/complete.js'
import { createChooseHandleRouter } from './routes/choose-handle.js'
import { resolveAuthPort } from './lib/resolve-port.js'
import { createSecurityHeadersMiddleware } from './lib/security-headers.js'
import {
  validateOtpCharset,
  validateOtpLength,
} from './lib/otp-config-validation.js'

const logger = createLogger('auth-service')

export function createAuthService(config: AuthServiceConfig): {
  app: express.Express
  ctx: AuthServiceContext
} {
  const ctx = new AuthServiceContext(config)
  const app = express()

  // Mount better-auth BEFORE express.json() so it can parse its own request bodies.
  // All better-auth endpoints live under /api/auth/*.
  const betterAuthInstance = createBetterAuth(
    ctx.emailSender,
    ctx.db,
    config.otpLength,
    config.otpCharset,
  )
  app.all('/api/auth/*', toNodeHandler(betterAuthInstance))

  // Middleware
  app.set('trust proxy', 1)
  app.use(express.urlencoded({ extended: true }))
  app.use(express.json())
  app.use(cookieParser())
  app.use('/static', express.static(path.resolve(__dirname, '..', 'public')))
  app.use(csrfProtection(config.csrfSecret))
  app.use(requestRateLimit({ windowMs: 60_000, maxRequests: 60 }))

  // Security headers (X-Frame-Options, CSP, HSTS, etc.). The CSP's
  // img-src is dynamically widened to allow the requesting OAuth
  // client's origin so client-branded login pages can render their
  // logo. See packages/auth-service/src/lib/security-headers.ts.
  app.use(createSecurityHeadersMiddleware())

  // Routes
  app.use(createLoginPageRouter(ctx))
  app.use(createRecoveryRouter(ctx, betterAuthInstance))
  app.use(createAccountLoginRouter(betterAuthInstance, ctx))
  app.use(createAccountSettingsRouter(ctx, betterAuthInstance))
  app.use(createCompleteRouter(ctx, betterAuthInstance))
  app.use(createChooseHandleRouter(ctx, betterAuthInstance))

  // Metrics endpoint (protect with admin auth in production)
  app.get('/metrics', (req, res) => {
    const adminPassword = process.env.PDS_ADMIN_PASSWORD
    if (adminPassword) {
      const authHeader = req.headers.authorization
      if (
        !authHeader ||
        authHeader !==
          'Basic ' + Buffer.from('admin:' + adminPassword).toString('base64')
      ) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
    }
    const metrics = ctx.db.getMetrics()
    res.json({
      ...metrics,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage().rss,
      timestamp: Date.now(),
    })
  })

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'auth' })
  })

  return { app, ctx }
}

// Entry point when run directly
async function main() {
  const config: AuthServiceConfig = {
    hostname: process.env.AUTH_HOSTNAME || 'auth.localhost',
    port: resolveAuthPort(),
    sessionSecret:
      process.env.AUTH_SESSION_SECRET || 'dev-session-secret-change-me',
    csrfSecret: process.env.AUTH_CSRF_SECRET || 'dev-csrf-secret-change-me',
    epdsCallbackSecret:
      process.env.EPDS_CALLBACK_SECRET || 'dev-callback-secret-change-me',
    pdsHostname: process.env.PDS_HOSTNAME || 'localhost',
    pdsPublicUrl: process.env.PDS_PUBLIC_URL || 'http://localhost:3000',
    email: {
      provider: (process.env.EMAIL_PROVIDER || 'smtp') as 'smtp',
      smtpHost: process.env.SMTP_HOST || 'localhost',
      smtpPort: parseInt(process.env.SMTP_PORT || '1025', 10),
      smtpUser: process.env.SMTP_USER || undefined,
      smtpPass: process.env.SMTP_PASS || undefined,
      from: process.env.SMTP_FROM || 'noreply@localhost',
      fromName: process.env.SMTP_FROM_NAME || 'ePDS',
    },
    dbLocation: process.env.DB_LOCATION || './data/epds.sqlite',
    otpLength: Number(process.env.OTP_LENGTH ?? '8'),
    otpCharset: (process.env.OTP_CHARSET || 'numeric') as
      | 'numeric'
      | 'alphanumeric',
    trustedClients: (process.env.PDS_OAUTH_TRUSTED_CLIENTS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  }

  validateOtpLength(config.otpLength, process.env.OTP_LENGTH)
  config.otpCharset = validateOtpCharset(config.otpCharset)

  await runBetterAuthMigrations(
    config.dbLocation,
    config.hostname,
    config.otpLength,
    config.otpCharset,
  )

  const { app, ctx } = createAuthService(config)

  const server = app.listen(config.port, () => {
    logger.info(
      { port: config.port, hostname: config.hostname },
      'Auth service running',
    )
  })

  const shutdown = () => {
    logger.info('Auth service shutting down')
    server.close()
    ctx.destroy()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

void main()
