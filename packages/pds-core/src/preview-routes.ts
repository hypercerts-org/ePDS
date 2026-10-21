/**
 * Preview route registration for the branding and OAuth UI development pages.
 * The installer is shared by pds-core startup and route-level tests so the
 * tests exercise the same Express paths that deployments serve.
 */
import type { Application, Request, Response } from 'express'
import {
  getClientMetadataCacheStatus,
  validateClientMetadataForPreview,
} from '@certified-app/shared'
import type { createPreviewChooserHandler } from './lib/preview-chooser.js'
import type { createPreviewConsentHandler } from './lib/preview-consent.js'
import { renderPreviewIndex } from './lib/preview-consent.js'
type PreviewRouteLogger = {
  info: (message: string) => void
}

export type PreviewRouteOptions = {
  previewConsentHandler: NonNullable<
    ReturnType<typeof createPreviewConsentHandler>
  >
  previewChooserHandler: NonNullable<
    ReturnType<typeof createPreviewChooserHandler>
  >
  authHostname: string
  pdsPublicUrl: string
  trustedClients: string[]
  logger: PreviewRouteLogger
}

/**
 * Register the preview routes when preview handlers have been enabled.
 *
 * The upstream PDS app is passed in so these routes share the same Express
 * instance and middleware ordering as the running service.
 */
export function installPreviewRoutes(
  app: Application,
  opts: PreviewRouteOptions,
): void {
  // auth-service runs on auth.<PDS_HOSTNAME>; pds-core is pdsPublicUrl.
  // Use https for real hostnames, http for localhost (see setup.sh and
  // Caddyfile — same rule applied in auth-service's preview router).
  const authScheme =
    opts.authHostname === 'localhost' ||
    opts.authHostname.endsWith('.localhost')
      ? 'http'
      : 'https'
  const authPublicUrl = `${authScheme}://${opts.authHostname}`
  app.get('/preview', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.send(
      renderPreviewIndex({ authPublicUrl, pdsPublicUrl: opts.pdsPublicUrl }),
    )
  })
  app.get('/preview/consent', opts.previewConsentHandler)
  app.get('/preview/chooser', opts.previewChooserHandler)
  app.get('/preview/cache-status', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store')
    res.json({ now: Date.now(), entries: getClientMetadataCacheStatus() })
  })
  app.get('/preview/validate', async (req: Request, res: Response) => {
    const url =
      typeof req.query.client_id === 'string' ? req.query.client_id : ''
    res.setHeader('Cache-Control', 'no-store')
    if (!url) {
      res.json({ url: '', fetched: false, checks: [] })
      return
    }
    const result = await validateClientMetadataForPreview(
      url,
      opts.trustedClients,
    )
    res.json(result)
  })
  opts.logger.info(
    'Preview routes installed (PDS_PREVIEW_ROUTES=1): /preview, /preview/consent, /preview/chooser, /preview/cache-status, /preview/validate',
  )
}
