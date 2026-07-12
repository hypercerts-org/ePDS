import { Router, type Request, type Response } from 'express'
import Database from 'better-sqlite3'
import { createLogger, verifyInternalSecret } from '@certified-app/shared'

const logger = createLogger('auth:test-hooks')

const ALLOWED_OTP_TYPES = new Set(['sign-in', 'email-verification'])

/**
 * Test-only router. Mounted only when EPDS_TEST_HOOKS=1, and rejected
 * outright when NODE_ENV=production. Used by the e2e suite to backdate
 * better-auth verification rows and auth_flow rows so the "session expired
 * after 10 minutes" scenario can run in seconds rather than wall-clock
 * minutes.
 *
 * Security model:
 *  - Defence-in-depth: the router itself is not registered unless the
 *    EPDS_TEST_HOOKS gate flag is set.
 *  - Authentication: x-internal-secret header, timing-safe equality vs
 *    EPDS_INTERNAL_SECRET.
 *  - Blast radius: the only mutations are UPDATE ... SET expiresAt /
 *    expires_at on the verification or auth_flow rows; the hooks cannot
 *    mint sessions or forge OTPs.
 */
export function createTestHooksRouter(dbLocation: string): Router {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'EPDS_TEST_HOOKS=1 is set but NODE_ENV=production — refusing to mount test-only endpoints',
    )
  }

  logger.warn(
    { dbLocation },
    'Test hooks ENABLED — /_internal/test/* routes are live (EPDS_TEST_HOOKS=1)',
  )

  const router = Router()

  router.post(
    '/_internal/test/expire-auth-flow',
    (req: Request, res: Response) => {
      if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      // Prefer targeting by request_uri so parallel e2e workers do not
      // expire each other's in-flight auth_flow rows. The {email} body
      // field is still required so callers stay symmetric with
      // /expire-otp and so server logs record which scenario triggered
      // the backdate. If request_uri is omitted, keep the legacy
      // test-only behaviour of backdating all live rows.
      const email = ((req.body?.email as string) || '').trim().toLowerCase()
      const requestUri = ((req.body?.request_uri as string) || '').trim()
      if (!email) {
        res.status(400).json({ error: 'Missing email' })
        return
      }

      const db = new Database(dbLocation)
      try {
        const past = Date.now() - 60 * 60 * 1000
        const now = Date.now()
        const result = requestUri
          ? db
              .prepare(
                'UPDATE auth_flow SET expires_at = ? WHERE request_uri = ? AND expires_at > ?',
              )
              .run(past, requestUri, now)
          : db
              .prepare(
                'UPDATE auth_flow SET expires_at = ? WHERE expires_at > ?',
              )
              .run(past, now)
        logger.warn(
          {
            email,
            requestUri: requestUri ? requestUri.slice(0, 60) : null,
            updated: result.changes,
          },
          'Backdated auth_flow.expires_at',
        )
        res.json({ updated: result.changes })
      } catch (err) {
        logger.error({ err, email }, 'Failed to backdate auth_flow row')
        res.status(500).json({ error: 'Internal server error' })
      } finally {
        db.close()
      }
    },
  )

  router.post('/_internal/test/expire-otp', (req: Request, res: Response) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const email = ((req.body?.email as string) || '').trim().toLowerCase()
    const type = ((req.body?.type as string) || 'sign-in').trim()

    if (!email) {
      res.status(400).json({ error: 'Missing email' })
      return
    }
    if (!ALLOWED_OTP_TYPES.has(type)) {
      res.status(400).json({
        error: `Unknown type "${type}"; expected one of sign-in, email-verification`,
      })
      return
    }

    const identifier = `${type}-otp-${email}`
    const db = new Database(dbLocation)
    try {
      const past = new Date(Date.now() - 60 * 60 * 1000).toISOString()
      const result = db
        .prepare('UPDATE verification SET expiresAt = ? WHERE identifier = ?')
        .run(past, identifier)
      logger.warn(
        { identifier, updated: result.changes },
        'Backdated verification.expiresAt',
      )
      res.json({ updated: result.changes })
    } catch (err) {
      logger.error({ err, identifier }, 'Failed to backdate verification row')
      res.status(500).json({ error: 'Internal server error' })
    } finally {
      db.close()
    }
  })

  return router
}
