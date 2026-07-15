/**
 * Client for the ePDS TEE signer service.
 *
 * Used by pds-core for both flows — but the flows stay separate all the
 * way down: `signRepoDigest()` can only ever reach the signer's repo
 * route (`atproto/signing` key), while the `wallet*()` methods can only
 * reach the wallet routes (`wallet/*` keys, which additionally demand a
 * user-signed envelope the PDS cannot forge).
 *
 * Transport auth is the shared internal secret (`x-internal-secret`),
 * mirroring the auth-service -> pds-core internal API convention. In a
 * split-host deployment the connection must additionally be verified
 * via the signer's attestation (see `attestation()` and
 * docs/design/tee-signer.md — "Splitting across two hosts").
 */

export type SignerKeyPurpose = 'atproto/signing' | 'wallet/evm' | 'wallet/sol'

export interface SignerKeyInfo {
  keyId: string
  purpose: SignerKeyPurpose
  curve: 'secp256k1' | 'ed25519'
  publicKeyHex: string
  didKey?: string
  address?: string
}

/** Public JWK of the enclave's wallet-encryption key (P-256). */
export interface WalletEncryptionJwk {
  kty: string
  crv: string
  x: string
  y: string
}

export interface SignerAttestation {
  mode: 'dstack' | 'dev'
  reportData: string
  quote: string | null
  identityPublicKeyHex: string
  walletEncryptionPublicJwk?: WalletEncryptionJwk
  note?: string
}

export interface WalletChainInfo {
  address: string
  publicKeyHex: string
}

export interface WalletPublicInfo {
  did: string
  evm: WalletChainInfo
  sol: WalletChainInfo
  /** Incremented on every re-shard (recovery). */
  version: number
  createdAt: number
}

export interface WalletCreateResult {
  status: 'created'
  wallet: WalletPublicInfo
  /** Device share, JWE-encrypted to the user's enrolled request key. */
  deviceShareJwe: string
  /** Recovery share, same encryption — the client must re-protect it
   * under a user-controlled recovery factor. */
  recoveryShareJwe: string
}

export interface WalletInfoResult {
  enrolled: boolean
  wallet: WalletPublicInfo | null
  walletEncryptionPublicJwk: WalletEncryptionJwk
}

export interface WalletRecoverResult {
  status: 'recovered'
  version: number
  deviceShareJwe: string
  recoveryShareJwe: string
}

export interface WalletSignEnvelope {
  /** base64url(JSON payload bytes) — signed by the USER, opaque to the PDS */
  payload: string
  /** base64url(compact P-256 signature over SHA-256(payload bytes)) */
  sig: string
}

export interface WalletSignResult {
  signatureHex: string
  /** secp256k1 recovery bit — present for wallet/evm signatures */
  recovery?: number
}

export class SignerClientError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'SignerClientError'
  }
}

export interface SignerClientOptions {
  baseUrl: string
  secret: string
  /** Per-request timeout in milliseconds. Default: 10_000. */
  timeoutMs?: number
}

export class SignerClient {
  private readonly baseUrl: string
  private readonly secret: string
  private readonly timeoutMs: number

  constructor(opts: SignerClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.secret = opts.secret
    this.timeoutMs = opts.timeoutMs ?? 10_000
  }

  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        'x-internal-secret': this.secret,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(this.timeoutMs),
    })
    let json: unknown = null
    try {
      json = await res.json()
    } catch {
      // fall through — handled by the !res.ok branch or returned as null
    }
    if (!res.ok) {
      const errValue = (json as { error?: unknown } | null)?.error
      const message =
        typeof errValue === 'string'
          ? errValue
          : `signer request failed with status ${res.status}`
      throw new SignerClientError(res.status, message)
    }
    return json as T
  }

  async health(): Promise<{ status: string; service: string }> {
    return this.request('GET', '/health')
  }

  async attestation(): Promise<SignerAttestation> {
    return this.request('GET', '/v1/attestation')
  }

  /**
   * Repo signing key info only — wallet keys are per-wallet secrets
   * under the 2-of-3 share scheme and cannot be derived (the signer
   * rejects wallet purposes here; use `walletCreate` / `walletInfo`).
   */
  async deriveKey(
    did: string,
    purpose: 'atproto/signing',
  ): Promise<SignerKeyInfo> {
    return this.request('POST', '/v1/keys/derive', { did, purpose })
  }

  // ── REPO PATH ─────────────────────────────────────────────────────

  /** Sign a repo-commit SHA-256 digest. Returns the raw 64-byte low-S sig. */
  async signRepoDigest(did: string, digestHex: string): Promise<Uint8Array> {
    const { signatureHex } = await this.request<{ signatureHex: string }>(
      'POST',
      '/v1/sign/repo',
      { did, digestHex },
    )
    return Uint8Array.from(Buffer.from(signatureHex, 'hex'))
  }

  // ── WALLET PATH ───────────────────────────────────────────────────

  async walletEnroll(
    did: string,
    requestPublicKeyHex: string,
  ): Promise<{ status: 'created' | 'unchanged' }> {
    return this.request('POST', '/v1/wallet/enroll', {
      did,
      requestPublicKeyHex,
    })
  }

  async walletEnrollment(did: string): Promise<{ enrolled: boolean }> {
    return this.request(
      'GET',
      `/v1/wallet/enrollment/${encodeURIComponent(did)}`,
    )
  }

  /**
   * Create the user's wallet: entropy is generated in-enclave and
   * split 2-of-3. The returned share JWEs are opaque to us (encrypted
   * to the user's enrolled request key) — pass them through verbatim.
   */
  async walletCreate(did: string): Promise<WalletCreateResult> {
    return this.request('POST', '/v1/wallet/create', { did })
  }

  /** Public wallet material + enrollment + enclave encryption JWK. */
  async walletInfo(did: string): Promise<WalletInfoResult> {
    return this.request('GET', `/v1/wallet/info/${encodeURIComponent(did)}`)
  }

  /** Forward a user-signed envelope. The signer verifies the user; we don't. */
  async walletSign(envelope: WalletSignEnvelope): Promise<WalletSignResult> {
    return this.request('POST', '/v1/wallet/sign', envelope)
  }

  /**
   * Forward a user-signed export envelope. Returns the key material
   * encrypted to the user's request key — opaque to us and the PDS.
   */
  async walletExport(
    envelope: WalletSignEnvelope,
  ): Promise<{ exportJwe: string }> {
    return this.request('POST', '/v1/wallet/export', envelope)
  }

  /**
   * Forward a recovery request. Authorization is possession of the
   * recovery share (verified inside the enclave), not the caller.
   */
  async walletRecover(params: {
    did: string
    /** Recovery share, JWE-encrypted to the enclave's encryption key. */
    recoveryShareJwe: string
    /** Optional new request key to enroll (device replacement). */
    requestPublicKeyHex?: string
  }): Promise<WalletRecoverResult> {
    return this.request('POST', '/v1/wallet/recover', params)
  }
}
