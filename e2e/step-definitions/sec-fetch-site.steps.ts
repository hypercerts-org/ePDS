/**
 * Step definitions for the same-site deployment topology scenario.
 *
 * See the comment block in features/security.feature for full context.
 *
 * TL;DR: ePDS puts the auth service on a subdomain of the PDS (e.g.
 * auth.pds.example / pds.example). When the browser follows the redirect
 * chain auth → pds /oauth/epds-callback → pds /oauth/authorize, it sends
 * sec-fetch-site: same-site. The upstream @atproto/oauth-provider rejects
 * that value. On Railway CI, this is masked because up.railway.app is a
 * public suffix (so cross-service requests are cross-site, not same-site).
 *
 * These steps send a direct HTTP request with sec-fetch-site: same-site to
 * verify the PDS doesn't reject it — catching the bug regardless of the
 * CI domain topology.
 */

import { When, Then } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'

When(
  String.raw`a GET request is sent to the PDS \/oauth\/authorize with sec-fetch-site {string}`,
  async function (this: EpdsWorld, secFetchSiteValue: string) {
    // We need a valid request_uri to avoid a different error (missing
    // request_uri) masking the sec-fetch-site rejection. Try PAR first;
    // if it requires DPoP (which we can't easily provide here), fall back
    // to a dummy URI — the sec-fetch-site check runs before request_uri
    // validation, so the 400 about sec-fetch-site will still surface.
    const clientMetaUrl = `${testEnv.demoUrl}/client-metadata.json`

    const parBody = new URLSearchParams({
      client_id: clientMetaUrl,
      redirect_uri: `${testEnv.demoUrl}/api/oauth/callback`,
      response_type: 'code',
      scope: 'atproto transition:generic',
      state: 'test-state',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    })

    const parRes = await fetch(`${testEnv.pdsUrl}/oauth/par`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: parBody.toString(),
      redirect: 'manual',
    })

    let requestUri: string
    if (parRes.ok) {
      const parData = (await parRes.json()) as { request_uri: string }
      requestUri = parData.request_uri
    } else {
      requestUri = 'urn:ietf:params:oauth:request_uri:req-test-dummy'
    }

    // Send GET /oauth/authorize with the sec-fetch-site header that a real
    // browser would send on a same-site deployment (e.g. *.certified.app).
    const authorizeUrl = new URL('/oauth/authorize', testEnv.pdsUrl)
    authorizeUrl.searchParams.set('request_uri', requestUri)
    authorizeUrl.searchParams.set('client_id', clientMetaUrl)

    const res = await fetch(authorizeUrl.toString(), {
      method: 'GET',
      headers: {
        'sec-fetch-site': secFetchSiteValue,
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
      },
      redirect: 'manual',
    })

    this.lastHttpStatus = res.status
    const text = await res.text()
    try {
      this.lastHttpJson = JSON.parse(text) as Record<string, unknown>
    } catch {
      this.lastHttpJson = { body: text }
    }
  },
)

Then(
  'the response is not a 400 error about forbidden sec-fetch-site header',
  function (this: EpdsWorld) {
    const status = this.lastHttpStatus
    const body = this.lastHttpJson

    const bodyStr = JSON.stringify(body ?? {}).toLowerCase()
    const isSecFetchRejection =
      status === 400 &&
      bodyStr.includes('sec-fetch-site') &&
      bodyStr.includes('forbidden')

    if (isSecFetchRejection) {
      throw new Error(
        `PDS /oauth/authorize rejected sec-fetch-site header with 400.\n` +
          `This means the redirect chain from auth subdomain → PDS will fail ` +
          `on deployments where auth and PDS share the same registrable domain ` +
          `(e.g. *.certified.app). The upstream @atproto/oauth-provider rejects ` +
          `"same-site" but browsers send it when redirecting between subdomains ` +
          `of the same site.\n\n` +
          `Fix: add middleware in pds-core to rewrite sec-fetch-site: same-site ` +
          `→ same-origin for requests arriving from the trusted auth subdomain.`,
      )
    }
  },
)
