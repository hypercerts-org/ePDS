/**
 * Signer persistence — wallet enrollments and anti-replay nonces.
 *
 * Deliberately tiny: derivation is pure, so the only state the signer
 * keeps is (a) which user request-key is enrolled for each DID and
 * (b) the last accepted wallet nonce per DID (monotonic counter).
 *
 * Threat-model note (see docs/design/tee-signer.md): the host controls
 * this disk, so it can roll the file back. Rolling back the nonce table
 * re-opens a replay window for envelopes the user *already signed* —
 * it never lets the host forge a new one. A production deployment
 * should anchor freshness outside the host (monotonic counter service
 * or on-chain nonce checks); enrollment rows additionally carry the
 * request-key so a rollback can only restore an older key the user
 * once controlled, not substitute the host's own.
 */
import Database from 'better-sqlite3'

export interface EnrollmentRow {
  did: string
  requestPubkeyHex: string
  createdAt: number
}

export class SignerStore {
  private readonly db: Database.Database

  constructor(dbPath: string) {
    this.db = new Database(dbPath)
    this.db.pragma('journal_mode = WAL')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS wallet_enrollment (
        did TEXT PRIMARY KEY,
        request_pubkey_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wallet_nonce (
        did TEXT PRIMARY KEY,
        last_nonce INTEGER NOT NULL
      );
    `)
  }

  getEnrollment(did: string): EnrollmentRow | null {
    const row = this.db
      .prepare(
        'SELECT did, request_pubkey_hex AS requestPubkeyHex, created_at AS createdAt FROM wallet_enrollment WHERE did = ?',
      )
      .get(did) as EnrollmentRow | undefined
    return row ?? null
  }

  /**
   * Trust-on-first-use enrollment. Returns:
   *  - 'created'   — no key was enrolled; this one now is.
   *  - 'unchanged' — the same key was already enrolled (idempotent).
   *  - 'conflict'  — a different key is enrolled; caller must reject.
   *    Key rotation requires an envelope signed by the current key and
   *    is intentionally not implemented via plain re-enrollment.
   */
  enroll(
    did: string,
    requestPubkeyHex: string,
  ): 'created' | 'unchanged' | 'conflict' {
    const existing = this.getEnrollment(did)
    if (existing) {
      return existing.requestPubkeyHex === requestPubkeyHex
        ? 'unchanged'
        : 'conflict'
    }
    this.db
      .prepare(
        'INSERT INTO wallet_enrollment (did, request_pubkey_hex, created_at) VALUES (?, ?, ?)',
      )
      .run(did, requestPubkeyHex, Date.now())
    return 'created'
  }

  /**
   * Atomically accept `nonce` for `did` iff it is strictly greater than
   * the last accepted nonce. Returns false on replay/reorder.
   */
  consumeNonce(did: string, nonce: number): boolean {
    const tx = this.db.transaction((): boolean => {
      const row = this.db
        .prepare(
          'SELECT last_nonce AS lastNonce FROM wallet_nonce WHERE did = ?',
        )
        .get(did) as { lastNonce: number } | undefined
      if (row && nonce <= row.lastNonce) return false
      this.db
        .prepare(
          'INSERT INTO wallet_nonce (did, last_nonce) VALUES (?, ?) ON CONFLICT(did) DO UPDATE SET last_nonce = excluded.last_nonce',
        )
        .run(did, nonce)
      return true
    })
    return tx()
  }

  close(): void {
    this.db.close()
  }
}
