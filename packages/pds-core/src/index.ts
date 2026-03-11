/**
 * ePDS Core
 *
 * Wraps the stock @atproto/pds with:
 * - OAuth /epds-callback endpoint that issues authorization codes directly
 * - Modified AS metadata pointing authorization_endpoint to auth subdomain
 * - Account creation for new users (via PLC + repo init)
 *
 * Flow:
 *   1. Client -> PAR -> PDS (stock)
 *   2. PDS redirects to auth.pds.example/oauth/authorize (via AS metadata)
 *   3. User enters email, receives verification code, verifies
 *   4. Auth service redirects to pds.example/oauth/epds-callback
 *   5. ePDS callback: creates account if needed, issues code, redirects to client
 */
import * as dotenv from 'dotenv'
dotenv.config()

import type * as http from 'node:http'
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto'
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import {
  generateRandomHandle,
  createLogger,
  verifyCallback,
} from '@certified-app/shared'

const logger = createLogger('pds-core')

async function main() {
  const env = readEnv()
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const authHostname = process.env.AUTH_HOSTNAME || 'auth.localhost'
  const handleDomain = process.env.PDS_HOSTNAME || 'localhost'
  const pdsUrl = cfg.service.publicUrl || `https://${handleDomain}`

  const pds = await PDS.create(cfg, secrets)
  const ctx = pds.ctx
  const provider = ctx.oauthProvider

  if (!provider) {
    logger.warn(
      'OAuth provider not configured, starting without ePDS callback integration',
    )
  } else {
    logger.info('OAuth provider active, setting up ePDS callback integration')
  }

  // =========================================================================
  // EPDS CALLBACK - The core integration endpoint
  // =========================================================================
  //
  // Called by the auth service after OTP verification + user consent.
  // Steps: load device -> resolve account -> issue code -> redirect to client

  const epdsCallbackSecret =
    process.env.EPDS_CALLBACK_SECRET || 'dev-callback-secret-change-me'

  pds.app.get('/oauth/epds-callback', async (req, res) => {
    // We use `as any` casts for branded OAuth types (RequestUri, Code, etc.)
    // since these internal types aren't cleanly exported from @atproto/oauth-provider.

    const requestUri = req.query.request_uri as string
    const email = ((req.query.email as string) || '').toLowerCase()
    const approved = req.query.approved === '1'
    const _isNewAccount = req.query.new_account === '1'
    const ts = req.query.ts as string
    const sig = req.query.sig as string

    if (!requestUri || !email || !approved) {
      res.status(400).json({ error: 'Missing required parameters' })
      return
    }

    // Verify HMAC-SHA256 signature before performing any account operations.
    // This prevents an attacker with a valid request_uri from forging a callback
    // with an arbitrary victim email.
    if (!ts || !sig) {
      res.status(403).json({ error: 'Missing signature' })
      return
    }

    const approvedStr = req.query.approved as string
    const newAccountStr = req.query.new_account as string
    const callbackVerification = verifyCallback(
      {
        request_uri: requestUri,
        email,
        approved: approvedStr,
        new_account: newAccountStr,
      },
      ts,
      sig,
      epdsCallbackSecret,
    )

    if (!callbackVerification.valid) {
      // Distinguish expired from invalid to help with clock-skew debugging
      const tsNum = parseInt(ts, 10)
      const age = Math.floor(Date.now() / 1000) - tsNum
      if (!isNaN(tsNum) && age > 5 * 60) {
        res.status(400).json({ error: 'Callback signature expired' })
      } else {
        res.status(403).json({ error: 'Invalid callback signature' })
      }
      return
    }

    if (!provider) {
      res.status(500).json({ error: 'OAuth provider not configured' })
      return
    }

    try {
      // Step 1: Load or create device session
      const deviceInfo = await provider.deviceManager.load(
        req as unknown as http.IncomingMessage,
        res as unknown as http.ServerResponse,
      )
      const { deviceId, deviceMetadata } = deviceInfo

      // Step 2: Get the pending authorization request
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
      const requestData = await (provider.requestManager as any).get(
        requestUri,
        deviceId,
      )
      const { clientId, parameters } = requestData

      // Step 3: Get the client
      const client = await provider.clientManager.getClient(clientId)

      // Step 4: Resolve or create the account.
      // Use the PDS accountManager directly — account.sqlite is the single source of truth.
      // Backup email lookup (recovery flow) is handled by the auth-service before issuing
      // the HMAC-signed callback; by the time we reach here, email is the verified primary.
      const existingAccount =
        await pds.ctx.accountManager.getAccountByEmail(email)
      let did: string | undefined = existingAccount?.did

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider Account type not exported
      let account: any

      if (did) {
        // Existing account
        const accountData = await provider.accountManager.getAccount(did)
        account = accountData.account
      } else {
        // New account - create via the OAuthProvider's sign-up mechanism
        // Retry up to 3 times in case of handle collision
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            const handle = generateRandomHandle(handleDomain)
            account = await provider.accountManager.createAccount(
              deviceId,
              deviceMetadata,
              {
                locale: 'en',
                handle,
                email,
                // Use a random unguessable password so the PDS creates a proper account
                // row (registerAccount requires a password). The password is never
                // returned or stored anywhere accessible, so the account is effectively
                // passwordless — login is only possible via the magic OTP flow.
                password: randomBytes(32).toString('hex'),
                // Invite code is required when PDS_INVITE_REQUIRED is true (the default).
                // EPDS_INVITE_CODE should be a high-useCount code generated via the admin API.
                inviteCode: process.env.EPDS_INVITE_CODE,
              },
            )
            did = account.sub
            logger.info({ did, email, handle }, 'Created account')
            break
          } catch (createErr: unknown) {
            if (attempt === 2) throw createErr
            logger.warn(
              { err: createErr, attempt },
              'Account creation attempt failed, retrying',
            )
          }
        }
      }

      // Step 5: Bind account to device session (for future SSO)
      await provider.accountManager.upsertDeviceAccount(deviceId, account.sub)

      // Step 6: Issue authorization code
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
      const code = await (provider.requestManager as any).setAuthorized(
        requestUri,
        client,
        account,
        deviceId,
        deviceMetadata,
      )

      // Step 7: Update authorized clients (consent tracking)
      const { authorizedClients } = await provider.accountManager.getAccount(
        account.sub,
      )
      const clientData = authorizedClients.get(clientId)
      if (provider.checkConsentRequired(parameters, clientData)) {
        const scopes = new Set(clientData?.authorizedScopes)
        for (const s of parameters.scope?.split(' ') ?? []) scopes.add(s)
        await provider.accountManager.setAuthorizedClient(account, client, {
          ...clientData,
          authorizedScopes: [...scopes],
        })
      }

      // Step 8: Build redirect URL and send user back to client
      const redirectUri = parameters.redirect_uri
      if (!redirectUri) {
        res
          .status(400)
          .json({ error: 'No redirect_uri in authorization request' })
        return
      }

      const redirectUrl = new URL(redirectUri)
      const responseMode = parameters.response_mode || 'query'

      const redirectParams: [string, string][] = [
        ['iss', pdsUrl],
        ['code', code],
      ]
      if (parameters.state) {
        redirectParams.push(['state', parameters.state])
      }

      if (responseMode === 'fragment') {
        const fragmentParams = new URLSearchParams()
        for (const [k, v] of redirectParams) fragmentParams.set(k, v)
        redirectUrl.hash = fragmentParams.toString()
      } else {
        for (const [k, v] of redirectParams) redirectUrl.searchParams.set(k, v)
      }

      res.setHeader('Cache-Control', 'no-store')
      res.redirect(303, redirectUrl.toString())

      logger.info({ did, redirectUri }, 'Auth code issued')
    } catch (err) {
      logger.error({ err }, 'ePDS callback error')

      // Try to redirect error back to client
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
        const requestData = await (provider.requestManager as any).get(
          requestUri,
        )
        const redirectUri = requestData?.parameters?.redirect_uri
        if (redirectUri) {
          const errorUrl = new URL(redirectUri)
          errorUrl.searchParams.set('error', 'server_error')
          errorUrl.searchParams.set(
            'error_description',
            'Authentication failed',
          )
          errorUrl.searchParams.set('iss', pdsUrl)
          if (requestData.parameters.state) {
            errorUrl.searchParams.set('state', requestData.parameters.state)
          }
          res.redirect(303, errorUrl.toString())
          return
        }
      } catch {
        // Fall through
      }

      if (!res.headersSent) {
        res.status(500).json({ error: 'Authentication failed' })
      }
    }
  })

  // =========================================================================
  // Override AS metadata - point authorization_endpoint to auth subdomain
  // =========================================================================
  //
  // The stock OAuth provider pre-serializes metadata into a buffer at init time
  // via staticJsonMiddleware, mounted as middleware (app.use) before any routes.
  // We can't override it with app.get() since middleware runs first.
  //
  // Solution: inject our own middleware at the very front of the Express stack
  // so it intercepts the request before the stock OAuth middleware.

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express middleware injected into raw stack
  const asMetadataOverride = (req: any, res: any, next: any) => {
    if (
      req.method === 'GET' &&
      req.path === '/.well-known/oauth-authorization-server'
    ) {
      const authUrl = `https://${authHostname}`
      res.setHeader('Access-Control-Allow-Origin', '*')
      res.setHeader('Cache-Control', 'public, max-age=300')
      res.setHeader('Content-Type', 'application/json')
      res.json({
        ...provider!.metadata,
        authorization_endpoint: `${authUrl}/oauth/authorize`,
      })
      return
    }
    next()
  }

  // Insert at position 0 in the Express middleware stack so it runs before
  // the stock authRoutes middleware that serves the pre-serialized metadata.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- accessing Express internal _router stack
  const stack = (pds.app as any)._router?.stack
  if (stack) {
    // Create a Layer-like entry by temporarily registering and then moving it
    pds.app.use(asMetadataOverride)
    const layer = stack.pop()
    // Insert after query (0) and expressInit (1) so req.path is available,
    // but before the authRoutes router that serves stock OAuth metadata.
    // Find expressInit and insert right after it.
    let insertIdx = 0
    for (let i = 0; i < stack.length; i++) {
      if (stack[i].name === 'expressInit') {
        insertIdx = i + 1
        break
      }
    }
    stack.splice(insertIdx, 0, layer)
    logger.info('AS metadata override installed')
  }

  // =========================================================================
  // Internal endpoints
  // =========================================================================

  /** Timing-safe check of the x-internal-secret header. Returns false if the
   *  env var is unset or the header is missing/mismatched.
   *  Both values are hashed to SHA-256 so timingSafeEqual always receives
   *  equal-length buffers, avoiding length-leak timing side-channels and
   *  ERR_INVALID_ARG_VALUE throws from multibyte string length mismatches. */
  function verifyInternalSecret(
    header: string | string[] | undefined,
  ): boolean {
    const secret = process.env.EPDS_INTERNAL_SECRET
    if (!secret || typeof header !== 'string') return false
    const hash = (v: string) => createHash('sha256').update(v).digest()
    return timingSafeEqual(hash(header), hash(secret))
  }

  // Protected internal endpoint for auth service to look up an account by email.
  // Replaces the old unauthenticated /_magic/check-email to prevent email enumeration.
  // Queries account.sqlite directly via the PDS accountManager — no mirror table needed.
  pds.app.get('/_internal/account-by-email', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const email = ((req.query.email as string) || '').trim().toLowerCase()
    if (!email) {
      res.status(400).json({ error: 'Missing email' })
      return
    }
    try {
      const account = await pds.ctx.accountManager.getAccountByEmail(email)
      res.json({ did: account?.did ?? null })
    } catch (err) {
      logger.error({ err }, 'Failed to look up account by email')
      res.status(500).json({ error: 'Internal server error' })
    }
  })

  // Protected internal endpoint for auth service to look up an account by handle or DID.
  // Used to resolve AT Protocol login_hints (handles or DIDs) to email addresses so the
  // auth service can skip the email form and go straight to OTP.
  // accountManager.getAccount() accepts both handles and DIDs.
  pds.app.get('/_internal/account-by-handle', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const handle = ((req.query.handle as string) || '').trim()
    if (!handle) {
      res.status(400).json({ error: 'Missing handle' })
      return
    }
    try {
      const account = await pds.ctx.accountManager.getAccount(handle)
      res.json({ email: account?.email ?? null })
    } catch (err) {
      logger.error({ err }, 'Failed to look up account by handle')
      res.status(500).json({ error: 'Internal server error' })
    }
  })

  // Protected internal endpoint for auth service to retrieve the login_hint
  // stored in a PAR request. Third-party apps put the handle/DID in the PAR body
  // but don't duplicate it on the authorization redirect URL. The auth service
  // needs to retrieve it to resolve the user's email for OTP.
  pds.app.get('/_internal/par-login-hint', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const requestUri = ((req.query.request_uri as string) || '').trim()
    if (!requestUri) {
      res.status(400).json({ error: 'Missing request_uri' })
      return
    }
    try {
      const oauthProvider = pds.ctx.oauthProvider
      if (!oauthProvider) {
        res.status(503).json({ error: 'OAuth provider not available' })
        return
      }
      // Cast to the branded RequestUri type expected by requestManager.get()
      const request = await oauthProvider.requestManager.get(
        requestUri as `urn:ietf:params:oauth:request_uri:req-${string}`,
      )
      res.json({ login_hint: request.parameters.login_hint ?? null })
    } catch (err) {
      logger.debug({ err, requestUri }, 'Failed to read PAR login_hint')
      // Not found or expired — not an error, just no hint available
      res.json({ login_hint: null })
    }
  })

  // =========================================================================
  // TLS check - used by Caddy on-demand TLS to verify handle ownership
  // =========================================================================

  pds.app.get('/tls-check', async (req, res) => {
    await checkHandleRoute(pds, authHostname, req, res)
  })

  // =========================================================================
  // TLS check - used by Caddy on-demand TLS to verify handle ownership
  // =========================================================================

  pds.app.get('/tls-check', async (req, res) => {
    await checkHandleRoute(pds, authHostname, req, res)
  })

  pds.app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'epds' })
  })

  await pds.start()
  logger.info({ port: cfg.service.port, pdsUrl, authHostname }, 'ePDS running')

  const shutdown = async () => {
    logger.info('ePDS shutting down')
    await pds.destroy()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

/** Caddy on-demand TLS ask handler.
 *  Returns 200 if the domain is the PDS hostname, the auth subdomain, or a
 *  valid hosted handle, so Caddy knows it should provision a certificate for it. */
async function checkHandleRoute(
  pds: PDS,
  authHostname: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express types not directly available in this package
  req: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express types not directly available in this package
  res: any,
) {
  try {
    const { domain } = req.query
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({
        error: 'InvalidRequest',
        message: 'bad or missing domain query param',
      })
    }
    // Allow the PDS hostname and the auth subdomain through unconditionally
    if (domain === pds.ctx.cfg.service.hostname || domain === authHostname) {
      return res.json({ success: true })
    }
    const isHostedHandle = pds.ctx.cfg.identity.serviceHandleDomains.find(
      (avail: string) => domain.endsWith(avail),
    )
    if (!isHostedHandle) {
      return res.status(400).json({
        error: 'InvalidRequest',
        message: 'handles are not provided on this domain',
      })
    }
    const account = await pds.ctx.accountManager.getAccount(domain)
    if (!account) {
      return res.status(404).json({
        error: 'NotFound',
        message: 'handle not found for this domain',
      })
    }
    return res.json({ success: true })
  } catch (err) {
    logger.error({ err }, 'check handle failed')
    return res
      .status(500)
      .json({ error: 'InternalServerError', message: 'Internal Server Error' })
  }
}

main().catch((err: unknown) => {
  logger.fatal({ err }, 'Failed to start ePDS')
  process.exit(1)
})
