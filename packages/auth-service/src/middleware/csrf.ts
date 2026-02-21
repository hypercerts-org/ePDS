import type { Request, Response, NextFunction } from 'express'
import * as crypto from 'node:crypto'

const CSRF_COOKIE = 'magic_csrf'
const CSRF_HEADER = 'x-csrf-token'

export function csrfProtection(_secret: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // GET requests: set CSRF cookie if not present
    if (req.method === 'GET') {
      if (!req.cookies[CSRF_COOKIE]) {
        const token = crypto.randomBytes(32).toString('hex')
        res.cookie(CSRF_COOKIE, token, {
          httpOnly: true,
          secure: process.env.NODE_ENV !== 'development',
          sameSite: 'lax',
          maxAge: 30 * 60 * 1000, // 30 minutes
        })
        res.locals.csrfToken = token
      } else {
        res.locals.csrfToken = req.cookies[CSRF_COOKIE]
      }
      next()
      return
    }

    // POST requests: validate CSRF
    if (req.method === 'POST') {
      const cookieToken = req.cookies[CSRF_COOKIE]
      const headerToken = req.headers[CSRF_HEADER] as string | undefined
      const bodyToken = req.body?.csrf as string | undefined
      const submittedToken = headerToken || bodyToken

      if (!cookieToken || !submittedToken) {
        res.status(403).json({ error: 'CSRF validation failed' })
        return
      }

      if (cookieToken.length !== submittedToken.length) {
        res.status(403).json({ error: 'CSRF validation failed' })
        return
      }

      const valid = crypto.timingSafeEqual(
        Buffer.from(cookieToken),
        Buffer.from(submittedToken),
      )

      if (!valid) {
        res.status(403).json({ error: 'CSRF validation failed' })
        return
      }

      res.locals.csrfToken = cookieToken
    }

    next()
  }
}

export function getCsrfToken(res: Response): string {
  return res.locals.csrfToken as string
}
