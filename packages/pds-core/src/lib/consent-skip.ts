/**
 * Consent-skip on sign-up for trusted clients.
 *
 * After the epds-callback creates a brand-new account for a trusted client
 * that opted in (`epds_skip_consent_on_signup`), the authorization code is
 * issued directly and the browser is sent straight back to the client,
 * bypassing /oauth/authorize.
 *
 * Extracted from the route so the redirect can be unit-tested with a fake
 * provider. The provider is typed structurally (not `any`) so tsc checks the
 * shape of `requestManager.setAuthorized`: oauth-provider 0.27 changed it from
 * returning the code to returning `{ code, parameters }`, and an untyped call
 * silently produced `code=[object Object]`.
 */
import type {
  Account,
  Client,
  DeviceId,
  RequestMetadata,
} from '@atproto/oauth-provider/hooks'

export interface ConsentSkipProvider {
  requestManager: {
    get(
      requestUri: string,
      deviceId: DeviceId,
    ): Promise<{ parameters: Readonly<Record<string, unknown>> }>
    setAuthorized(
      requestUri: string,
      client: Client,
      account: Account,
      deviceId: DeviceId,
      deviceMetadata: RequestMetadata,
    ): Promise<{ code: string }>
  }
  accountManager: {
    setAuthorizedClient(
      account: Account,
      client: Client,
      data: { authorizedScopes: string[] },
    ): Promise<void>
  }
}

export type ConsentSkipResult =
  | { kind: 'redirect'; url: URL }
  | { kind: 'missing-redirect-uri' }

export async function issueConsentSkipRedirect(
  provider: ConsentSkipProvider,
  args: {
    requestUri: string
    client: Client
    account: Account
    deviceId: DeviceId
    deviceMetadata: RequestMetadata
    pdsUrl: string
  },
): Promise<ConsentSkipResult> {
  const { requestUri, client, account, deviceId, deviceMetadata, pdsUrl } = args

  // Bind device to the PAR request so setAuthorized() can proceed
  const { parameters } = await provider.requestManager.get(requestUri, deviceId)

  // Checked before setAuthorized(): that call issues an authorization
  // code, and we must not issue one we cannot deliver.
  const redirectUri = parameters.redirect_uri
  if (typeof redirectUri !== 'string' || !redirectUri) {
    return { kind: 'missing-redirect-uri' }
  }

  const { code } = await provider.requestManager.setAuthorized(
    requestUri,
    client,
    account,
    deviceId,
    deviceMetadata,
  )

  // Record the client as authorized so future logins can auto-approve
  const scope = typeof parameters.scope === 'string' ? parameters.scope : ''
  await provider.accountManager.setAuthorizedClient(account, client, {
    authorizedScopes: scope ? scope.split(' ') : [],
  })

  const redirectParams: [string, string][] = [
    ['iss', pdsUrl],
    ['code', code],
  ]
  if (typeof parameters.state === 'string' && parameters.state) {
    redirectParams.push(['state', parameters.state])
  }

  const url = new URL(redirectUri)
  if (parameters.response_mode === 'fragment') {
    const fragment = new URLSearchParams()
    for (const [k, v] of redirectParams) fragment.set(k, v)
    url.hash = fragment.toString()
  } else {
    for (const [k, v] of redirectParams) url.searchParams.set(k, v)
  }
  return { kind: 'redirect', url }
}
