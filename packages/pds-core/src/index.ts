/**
 * Magic PDS Core
 *
 * Wraps the stock @atproto/pds with:
 * - OAuth /magic-callback endpoint that issues authorization codes directly
 * - Modified AS metadata pointing authorization_endpoint to auth subdomain
 * - Account creation for new users (via PLC + repo init)
 *
 * Flow:
 *   1. Client -> PAR -> PDS (stock)
 *   2. PDS redirects to auth.pds.example/oauth/authorize (via AS metadata)
 *   3. User enters email, receives magic link, verifies
 *   4. Auth service redirects to pds.example/oauth/magic-callback
 *   5. Magic callback: creates account if needed, issues code, redirects to client
 */
import * as dotenv from 'dotenv'
dotenv.config()

import * as crypto from 'node:crypto'
import * as http from 'node:http'
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import { MagicPdsDb, generateRandomHandle, createLogger, verifyCallback } from '@magic-pds/shared'

const logger = createLogger('pds-core')

async function main() {
  const env = readEnv()
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const dbLocation = process.env.DB_LOCATION || './data/magic-pds.sqlite'
  const magicDb = new MagicPdsDb(dbLocation)

  const authHostname = process.env.AUTH_HOSTNAME || 'auth.localhost'
  const handleDomain = process.env.PDS_HOSTNAME || 'localhost'
  const pdsUrl = cfg.service.publicUrl || `https://${handleDomain}`

  const pds = await PDS.create(cfg, secrets)
  const ctx = pds.ctx
  const provider = ctx.oauthProvider

  if (!provider) {
    logger.warn('OAuth provider not configured, starting without magic link integration')
  } else {
    logger.info('OAuth provider active, setting up magic link integration')
  }

  // =========================================================================
  // MAGIC CALLBACK - The core integration endpoint
  // =========================================================================
  //
  // Called by the auth service after magic link verification + user consent.
  // Steps: load device -> resolve account -> issue code -> redirect to client

  const magicCallbackSecret = process.env.MAGIC_CALLBACK_SECRET || 'dev-callback-secret-change-me'

  pds.app.get('/oauth/magic-callback', async (req, res) => {
    // We use `as any` casts for branded OAuth types (RequestUri, Code, etc.)
    // since these internal types aren't cleanly exported from @atproto/oauth-provider.

    const requestUri = req.query.request_uri as string
    const email = (req.query.email as string || '').toLowerCase()
    const approved = req.query.approved === '1'
    const isNewAccount = req.query.new_account === '1'
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
    const signatureValid = verifyCallback(
      { request_uri: requestUri, email, approved: approvedStr, new_account: newAccountStr },
      ts,
      sig,
      magicCallbackSecret,
    )

    if (!signatureValid) {
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
      const requestData = await (provider.requestManager as any).get(
        requestUri,
        deviceId,
      )
      const { clientId, parameters } = requestData

      // Step 3: Get the client
      const client = await provider.clientManager.getClient(clientId)

      // Step 4: Resolve or create the account
      let did = magicDb.getDidByEmail(email)
      if (!did) {
        // Check if this is a backup email (recovery flow)
        did = magicDb.getDidByBackupEmail(email)
      }
      if (!did) {
        // Check if account exists in PDS but not yet tracked in magic-pds DB
        // (e.g. accounts created before tracking, or via auto-provision)
        did = magicDb.getDidFromPdsAccount(email) || undefined
        if (did) {
          magicDb.setAccountEmail(email, did)
          logger.info({ did, email }, 'Synced existing PDS account to magic-pds DB')
        }
      }
      let account: any // Account type from @atproto/oauth-provider-api

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
                // Password required by schema but never used for login
                password: crypto.randomBytes(64).toString('hex'),
              },
            )
            magicDb.setAccountEmail(email, account.sub)
            did = account.sub
            logger.info({ did, email, handle }, 'Created account')
            break
          } catch (createErr: any) {
            if (attempt === 2) throw createErr
            logger.warn({ err: createErr, attempt }, 'Account creation attempt failed, retrying')
          }
        }
      }

      // Step 5: Bind account to device session (for future SSO)
      await provider.accountManager.upsertDeviceAccount(deviceId, account.sub)

      // Step 6: Issue authorization code
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
        res.status(400).json({ error: 'No redirect_uri in authorization request' })
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
      logger.error({ err }, 'Magic callback error')

      // Try to redirect error back to client
      try {
        const requestData = await (provider!.requestManager as any).get(requestUri)
        const redirectUri = requestData?.parameters?.redirect_uri
        if (redirectUri) {
          const errorUrl = new URL(redirectUri)
          errorUrl.searchParams.set('error', 'server_error')
          errorUrl.searchParams.set('error_description', 'Authentication failed')
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

  const asMetadataOverride = (req: any, res: any, next: any) => {
    if (req.method === 'GET' && req.path === '/.well-known/oauth-authorization-server') {
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
      if (stack[i].name === 'expressInit') { insertIdx = i + 1; break }
    }
    stack.splice(insertIdx, 0, layer)
    logger.info('AS metadata override installed')
  }

  // =========================================================================
  // Health check
  // =========================================================================

  // Internal endpoint for auth service to check if an email has an existing account
  pds.app.get('/_magic/check-email', (req, res) => {
    const email = (req.query.email as string || '').trim().toLowerCase()
    if (!email) {
      res.status(400).json({ error: 'email required' })
      return
    }
    let did = magicDb.getDidByEmail(email)
    if (!did) did = magicDb.getDidByBackupEmail(email)
    res.json({ exists: !!did, did: did || undefined })
  })

  pds.app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'magic-pds' })
  })

  await pds.start()
  logger.info({ port: cfg.service.port, pdsUrl, authHostname }, 'Magic PDS running')

  const shutdown = async () => {
    logger.info('Magic PDS shutting down')
    await pds.destroy()
    magicDb.close()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

main().catch((err) => {
  logger.fatal({ err }, 'Failed to start Magic PDS')
  process.exit(1)
})
