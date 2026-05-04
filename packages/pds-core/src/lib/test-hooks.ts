/**
 * E2E test-only hooks. Mounted only when EPDS_TEST_HOOKS=1 and refused
 * outright when NODE_ENV=production. Mirrors auth-service's /_internal/test/*
 * pattern: narrow UPDATEs / DELETEs that mutate one row to reproduce
 * time-dependent behaviour without waiting out the wall-clock TTL.
 *
 * Currently exposes:
 *   POST /_internal/test/expire-device-account
 *     Body: {did, deviceId?}
 *     Backdates `account_device.updatedAt` 8 days into the past for the
 *     matching row(s). Used by the e2e suite to age bindings past
 *     upstream's authenticationMaxAge (7d) so checkLoginRequired returns
 *     true for the targeted binding(s).
 *
 *   POST /_internal/test/delete-par
 *     Body: {request_uri}
 *     Deletes the matching `authorization_request` row. Used by the
 *     @par-callback-error scenario to reproduce the production failure
 *     where /oauth/epds-callback hits an expired/missing PAR — the
 *     fix in the same commit responds with a friendly OAuth-spec
 *     redirect (or styled HTML) instead of leaking
 *     `{"error": "Authentication failed"}` JSON.
 */
import express, { type Application } from 'express'
import type { PDS } from '@atproto/pds'
import { verifyInternalSecret } from '@certified-app/shared'
import type { Logger } from 'pino'

const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'

/**
 * Validate the prefix AND attempt the URL-decode in one step, so a
 * malformed `%`-escape (e.g. `req-%`) is treated as malformed input
 * (400) rather than crashing the catch block and being reported as
 * a 500 server error. Returns the decoded request id when valid,
 * otherwise null. The caller logs the rejection so a malformed
 * payload still leaves a breadcrumb.
 */
function decodeAndValidateRequestUri(value: string): string | null {
  if (!value.startsWith(`${REQUEST_URI_PREFIX}req-`)) return null
  try {
    return decodeURIComponent(value.slice(REQUEST_URI_PREFIX.length))
  } catch (err) {
    if (err instanceof URIError) return null
    throw err
  }
}

export function installTestHooks(opts: {
  pds: PDS
  app: Application
  logger: Pick<Logger, 'warn' | 'error'>
}): void {
  const { pds, app, logger } = opts
  if (process.env.EPDS_TEST_HOOKS !== '1') return
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'EPDS_TEST_HOOKS=1 is set but NODE_ENV=production — refusing to mount test-only endpoints',
    )
  }
  logger.warn(
    'Test hooks ENABLED — /_internal/test/* routes are live (EPDS_TEST_HOOKS=1)',
  )

  app.post(
    '/_internal/test/expire-device-account',
    express.json(),
    async (req, res) => {
      if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const rawDid: unknown = req.body?.did
      const did = typeof rawDid === 'string' ? rawDid.trim() : ''
      const deviceId =
        typeof req.body?.deviceId === 'string'
          ? req.body.deviceId.trim()
          : undefined
      if (!did) {
        res.status(400).json({ error: 'Missing did' })
        return
      }
      // 8 days ago — comfortably past upstream's 7-day authenticationMaxAge
      // so checkLoginRequired returns true on every backdated row.
      const past = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString()
      try {
        // Reuse the PDS accountManager's own Kysely instance — same handle
        // PDS uses for upsertDeviceAccount, so there are no two-connection
        // WAL-visibility surprises.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- account_device shape not exported by @atproto/pds
        const db = pds.ctx.accountManager.db.db as any
        let q = db
          .updateTable('account_device')
          .set({ updatedAt: past })
          .where('did', '=', did)
        if (deviceId) {
          q = q.where('deviceId', '=', deviceId)
        }
        const result = await q.executeTakeFirst()
        const updated = Number(result?.numUpdatedRows ?? 0)
        logger.warn(
          { did, deviceId, updated, past },
          'Backdated account_device.updatedAt',
        )
        res.json({ updated })
      } catch (err) {
        logger.error(
          { err, did, deviceId },
          'Failed to backdate account_device.updatedAt',
        )
        res.status(500).json({ error: 'Internal server error' })
      }
    },
  )

  app.post('/_internal/test/delete-par', express.json(), async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const rawRequestUri: unknown = req.body?.request_uri
    const requestUri =
      typeof rawRequestUri === 'string' ? rawRequestUri.trim() : ''
    const requestId = requestUri
      ? decodeAndValidateRequestUri(requestUri)
      : null
    if (!requestId) {
      res.status(400).json({ error: 'Missing or malformed request_uri' })
      return
    }
    try {
      // Same Kysely instance as expire-device-account above. The
      // authorization_request table is owned by @atproto/pds — see
      // its account-manager/db/schema/authorization-request.ts. We
      // narrow the cast to a single column lookup so the absence
      // of a typed schema here doesn't propagate.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- authorization_request shape not exported by @atproto/pds
      const db = pds.ctx.accountManager.db.db as any
      const result = await db
        .deleteFrom('authorization_request')
        .where('id', '=', requestId)
        .executeTakeFirst()
      const deleted = Number(result?.numDeletedRows ?? 0)
      logger.warn(
        { requestUri, deleted },
        'Deleted PAR row — /oauth/epds-callback will treat this as expired',
      )
      res.json({ deleted })
    } catch (err) {
      logger.error({ err, requestUri }, 'Failed to delete PAR row')
      res.status(500).json({ error: 'Internal server error' })
    }
  })
}
