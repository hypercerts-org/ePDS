import { Router } from 'express'
import type { NextFunction, Request, RequestHandler, Response } from 'express'

/**
 * Express 4 ignores promises returned by route handlers, so a throw inside
 * an `async` handler becomes an unhandled rejection and Node exits the
 * process. Wrapping each handler forwards the rejection to `next()`, which
 * reaches `errorHandler` and becomes a 500 response.
 */
export function forwardAsyncErrors(handler: RequestHandler): RequestHandler {
  // Error-handling middleware (arity 4) must keep its signature.
  if (handler.length >= 4) return handler
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Express types handlers as void-returning; async ones return a promise.
      const call = handler as (...a: Parameters<RequestHandler>) => unknown
      Promise.resolve(call(req, res, next)).catch(next)
    } catch (err) {
      next(err)
    }
  }
}

const ROUTE_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'all'] as const

function wrapAll(args: unknown[]): unknown[] {
  return args.map((arg) => {
    if (typeof arg === 'function') {
      return forwardAsyncErrors(arg as RequestHandler)
    }
    if (Array.isArray(arg)) return wrapAll(arg)
    return arg // path string / RegExp
  })
}

/**
 * Drop-in replacement for `Router()` whose route handlers (get, post, put,
 * patch, delete, all) forward async errors to `next()`.
 */
export function createAsyncRouter(): Router {
  const router = Router()
  // Express exposes overloaded registration methods. Forward the original
  // path and argument shape, replacing only handler functions, and patch
  // just these methods on this instance so other router APIs stay untouched.
  for (const method of ROUTE_METHODS) {
    const original = router[method].bind(router) as (...a: unknown[]) => Router
    ;(router as unknown as Record<string, unknown>)[method] = (
      ...args: unknown[]
    ) => original(...wrapAll(args))
  }
  return router
}
