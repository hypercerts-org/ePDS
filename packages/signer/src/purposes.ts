/**
 * Key purposes — the hard separation boundary between the two flows.
 *
 * Every key the signer derives is bound to (did, purpose). The repo path
 * and the wallet path use disjoint purposes and disjoint API routes:
 *
 *   - `atproto/signing` — signs repo commits. Only reachable through
 *     `POST /v1/sign/repo`, which trusts the PDS (its single caller,
 *     authenticated with the internal secret).
 *   - `wallet/evm`, `wallet/sol` — sign on-chain transactions. Only
 *     reachable through `POST /v1/wallet/sign`, which additionally
 *     requires an envelope signed by the *user's* enrolled request key.
 *
 * Normal ATProto reads/writes never touch wallet purposes; wallet
 * operations never touch the repo signing key. Keeping the purposes in
 * one module (and validating against these allowlists at every route)
 * is what enforces that separation.
 */

/** Purpose used by the repo-commit signing path. */
export const REPO_SIGNING_PURPOSE = 'atproto/signing' as const

/** Purposes usable by the wallet path. */
export const WALLET_PURPOSES = ['wallet/evm', 'wallet/sol'] as const

export type WalletPurpose = (typeof WALLET_PURPOSES)[number]
export type KeyPurpose = typeof REPO_SIGNING_PURPOSE | WalletPurpose

export function isWalletPurpose(value: unknown): value is WalletPurpose {
  return (
    typeof value === 'string' &&
    (WALLET_PURPOSES as readonly string[]).includes(value)
  )
}

export function isKeyPurpose(value: unknown): value is KeyPurpose {
  return value === REPO_SIGNING_PURPOSE || isWalletPurpose(value)
}

/** Basic DID shape check — enough to reject junk before deriving keys. */
export function isPlausibleDid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^did:(plc|web):[a-zA-Z0-9._:%-]{1,512}$/.test(value)
  )
}
