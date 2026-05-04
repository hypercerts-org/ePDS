import type { Request, Response, NextFunction } from 'express'

const requestCounts = new Map<string, { count: number; resetAt: number }>()

// Cleanup expired entries every 5 minutes to prevent memory leaks
setInterval(
  () => {
    const now = Date.now()
    for (const [key, entry] of requestCounts) {
      if (entry.resetAt < now) requestCounts.delete(key)
    }
  },
  5 * 60 * 1000,
).unref()

/**
 * In-memory request rate limiter (per IP).
 * Suitable for single-instance deployments. For multi-instance,
 * use a Redis-backed rate limiter (e.g. express-rate-limit + rate-limit-redis).
 *
 * Honours `EPDS_DISABLE_RATE_LIMIT=true` as a no-op opt-out for
 * docker-compose / e2e stacks where a single source IP fires hundreds of
 * requests per scenario. Production deployments leave the env var unset
 * and the limiter applies normally.
 */
export function requestRateLimit(opts: {
  windowMs: number
  maxRequests: number
}) {
  const disabled = process.env.EPDS_DISABLE_RATE_LIMIT === 'true'
  return (req: Request, res: Response, next: NextFunction): void => {
    if (disabled) {
      next()
      return
    }
    const ip = req.ip || req.socket.remoteAddress || 'unknown'
    const now = Date.now()

    let entry = requestCounts.get(ip)
    if (!entry || entry.resetAt < now) {
      entry = { count: 0, resetAt: now + opts.windowMs }
      requestCounts.set(ip, entry)
    }

    entry.count++
    if (entry.count > opts.maxRequests) {
      res
        .status(429)
        .json({ error: 'Too many requests. Please try again later.' })
      return
    }

    next()
  }
}
