/**
 * Resolve the authenticated user's DID from a request, using the stock
 * PDS AuthVerifier (supports both legacy access JWTs and DPoP-bound
 * OAuth tokens).
 *
 * Used ONLY by the wallet enrollment/info routes — i.e. to answer
 * "which account is asking". It is deliberately NOT used to authorize
 * wallet *signatures*: those require a user-signed envelope verified
 * inside the signer, because a bearer/DPoP token is host-forwardable
 * and must never be sufficient to move funds (see threat model in
 * docs/design/tee-signer.md).
 */
import type { Request, Response } from 'express'

interface LoggerLike {
  debug: (obj: unknown, msg?: string) => void
}

export type UserDidVerifier = (
  req: Request,
  res: Response,
) => Promise<string | null>

export function createUserDidVerifier(
  pds: { ctx: { authVerifier: unknown } },
  logger: LoggerLike,
): UserDidVerifier {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- AuthVerifier's method verifiers aren't exported from @atproto/pds; we call the xrpc-style verifier directly with a minimal MethodAuthContext.
  const verifier = (pds.ctx.authVerifier as any).authorization({
    // No extra permission checks — we only need the caller's identity.
    authorize: () => {},
  })

  return async (req, res) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- MethodAuthContext shape from @atproto/xrpc-server, not exported through @atproto/pds
      const output: any = await verifier({ params: {}, req, res })
      const did: unknown = output?.credentials?.did
      return typeof did === 'string' ? did : null
    } catch (err) {
      logger.debug({ err }, 'wallet route auth failed')
      return null
    }
  }
}
