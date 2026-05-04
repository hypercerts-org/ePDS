import { Router } from 'express'

/**
 * Router for the site root (`/`). Redirects unconditionally to
 * `/account`, which in turn requires auth and will bounce the visitor
 * to `/account/login` when unauthenticated. 303 See Other matches the
 * redirect status the rest of the auth service uses.
 */
export function createRootRouter(): Router {
  const router = Router()

  router.get('/', (_req, res) => {
    res.redirect(303, '/account')
  })

  return router
}
