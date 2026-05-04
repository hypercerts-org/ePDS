import type express from 'express'
import { createLogger } from '@certified-app/shared'
import { renderError } from './render-error.js'

const logger = createLogger('auth:error-middleware')

/**
 * Trailing 404 handler. Returns JSON for Accept: * / * (fetch/curl default)
 * and styled HTML only when the client explicitly prefers text/html.
 */
export function notFoundHandler(
  req: express.Request,
  res: express.Response,
): void {
  res.vary('Accept')
  if (req.accepts(['json', 'html']) === 'html') {
    res
      .status(404)
      .type('html')
      .send(
        renderError(
          "The page you're looking for doesn't exist.",
          'Page not found',
        ),
      )
  } else {
    res.status(404).json({ error: 'not_found' })
  }
}

/**
 * Express error handler. Logs the cause, keeps the user-facing message
 * generic, and delegates to Express's default handler when headers have
 * already been sent so partial responses are not clobbered.
 */
export function errorHandler(
  err: unknown,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  logger.error({ err, path: req.path }, 'Unhandled error in auth-service')
  if (res.headersSent) {
    next(err)
    return
  }
  res.vary('Accept')
  if (req.accepts(['json', 'html']) === 'html') {
    res
      .status(500)
      .type('html')
      .send(renderError('Something went wrong. Please try again.'))
  } else {
    res.status(500).json({ error: 'internal_error' })
  }
}
