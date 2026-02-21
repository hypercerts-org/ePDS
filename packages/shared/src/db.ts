import Database from 'better-sqlite3'
import * as path from 'node:path'
import * as fs from 'node:fs'

export interface MagicLinkTokenRow {
  tokenHash: string
  email: string
  createdAt: number
  expiresAt: number
  used: number
  authRequestId: string
  clientId: string | null
  deviceInfo: string | null
  csrfToken: string
  codeHash: string | null
  attempts: number
}

export interface BackupEmailRow {
  id: number
  did: string
  email: string
  verified: number
  verificationTokenHash: string | null
  createdAt: number
}

export interface EmailRateLimitRow {
  email: string
  ipAddress: string | null
  sentAt: number
}

export interface AuthFlowRow {
  flowId: string
  requestUri: string
  clientId: string | null
  email: string | null
  createdAt: number
  expiresAt: number
}

export class EpdsDb {
  private db: Database.Database

  constructor(dbLocation: string) {
    const dir = path.dirname(dbLocation)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    this.db = new Database(dbLocation)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.migrate()
  }

  private migrate(): void {
    // Versioned migration system
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)',
    )
    const row = this.db.prepare('SELECT version FROM schema_version').get() as
      | { version: number }
      | undefined
    const currentVersion = row?.version ?? 0

    if (currentVersion === 0 && !row) {
      this.db.prepare('INSERT INTO schema_version (version) VALUES (0)').run()
    }

    const migrations: Array<() => void> = [
      // v1: Initial schema
      () => {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS magic_link_token (
            token_hash       TEXT PRIMARY KEY,
            email            TEXT NOT NULL,
            created_at       INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            used             INTEGER NOT NULL DEFAULT 0,
            auth_request_id  TEXT NOT NULL,
            client_id        TEXT,
            device_info      TEXT,
            csrf_token       TEXT NOT NULL,
            attempts         INTEGER NOT NULL DEFAULT 0
          );
          CREATE INDEX IF NOT EXISTS idx_mlt_email ON magic_link_token(email);
          CREATE INDEX IF NOT EXISTS idx_mlt_expires ON magic_link_token(expires_at);

          CREATE TABLE IF NOT EXISTS backup_email (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            did                     TEXT NOT NULL,
            email                   TEXT NOT NULL,
            verified                INTEGER NOT NULL DEFAULT 0,
            verification_token_hash TEXT,
            created_at              INTEGER NOT NULL,
            UNIQUE(did, email)
          );
          CREATE INDEX IF NOT EXISTS idx_be_did ON backup_email(did);

          CREATE TABLE IF NOT EXISTS account_session (
            session_id       TEXT PRIMARY KEY,
            did              TEXT NOT NULL,
            email            TEXT NOT NULL,
            created_at       INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            user_agent       TEXT,
            ip_address       TEXT
          );
          CREATE INDEX IF NOT EXISTS idx_as_did ON account_session(did);
          CREATE INDEX IF NOT EXISTS idx_as_expires ON account_session(expires_at);

          CREATE TABLE IF NOT EXISTS email_rate_limit (
            email            TEXT NOT NULL,
            ip_address       TEXT,
            sent_at          INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_erl_email_time ON email_rate_limit(email, sent_at);
          CREATE INDEX IF NOT EXISTS idx_erl_ip_time ON email_rate_limit(ip_address, sent_at);
        `)
      },

      // v2: Add code_hash column for OTP support
      () => {
        this.db.exec('ALTER TABLE magic_link_token ADD COLUMN code_hash TEXT')
      },

      // v3: Per-client login tracking for welcome vs sign-in emails
      () => {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS client_logins (
            email      TEXT NOT NULL,
            client_id  TEXT NOT NULL,
            first_login_at INTEGER NOT NULL,
            PRIMARY KEY (email, client_id)
          );
        `)
      },

      // v4: Per-email OTP failure tracking for brute-force lockout
      () => {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS otp_failed_attempts (
            email      TEXT NOT NULL,
            failed_at  INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_ofa_email_time ON otp_failed_attempts(email, failed_at);
        `)
      },

      // v5: Drop account_email mirror table — pds-core now queries account.sqlite via
      // accountManager.getAccountByEmail() directly; auth-service uses /_internal/account-by-email.
      () => {
        this.db.exec(`
          DROP TABLE IF EXISTS account_email;
        `)
      },

      // v6: Add auth_flow table for threading AT Protocol request_uri through better-auth flows.
      () => {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS auth_flow (
            flow_id      TEXT PRIMARY KEY,
            request_uri  TEXT NOT NULL,
            client_id    TEXT,
            email        TEXT,
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_af_expires ON auth_flow(expires_at);
        `)
      },

      // v7: Drop account_session table — session management is now handled by better-auth.
      () => {
        this.db.exec(`DROP TABLE IF EXISTS account_session;`)
      },
    ]

    for (let i = currentVersion; i < migrations.length; i++) {
      migrations[i]()
      this.db.prepare('UPDATE schema_version SET version = ?').run(i + 1)
    }
  }

  // ── Magic Link Token Operations ──

  createMagicLinkToken(data: {
    tokenHash: string
    email: string
    expiresAt: number
    authRequestId: string
    clientId: string | null
    deviceInfo: string | null
    csrfToken: string
    codeHash?: string | null
  }): void {
    const now = Date.now()
    this.db
      .prepare(
        `
      INSERT INTO magic_link_token (token_hash, email, created_at, expires_at, auth_request_id, client_id, device_info, csrf_token, code_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      )
      .run(
        data.tokenHash,
        data.email.toLowerCase(),
        now,
        data.expiresAt,
        data.authRequestId,
        data.clientId,
        data.deviceInfo,
        data.csrfToken,
        data.codeHash || null,
      )
  }

  getMagicLinkToken(tokenHash: string): MagicLinkTokenRow | undefined {
    return this.db
      .prepare(
        `
      SELECT
        token_hash as tokenHash, email, created_at as createdAt,
        expires_at as expiresAt, used, auth_request_id as authRequestId,
        client_id as clientId, device_info as deviceInfo, csrf_token as csrfToken, code_hash as codeHash, attempts
      FROM magic_link_token WHERE token_hash = ?
    `,
      )
      .get(tokenHash) as MagicLinkTokenRow | undefined
  }

  markMagicLinkTokenUsed(tokenHash: string): void {
    this.db
      .prepare(`UPDATE magic_link_token SET used = 1 WHERE token_hash = ?`)
      .run(tokenHash)
  }

  incrementTokenAttempts(tokenHash: string): number {
    this.db
      .prepare(
        `UPDATE magic_link_token SET attempts = attempts + 1 WHERE token_hash = ?`,
      )
      .run(tokenHash)
    const row = this.db
      .prepare(`SELECT attempts FROM magic_link_token WHERE token_hash = ?`)
      .get(tokenHash) as { attempts: number } | undefined
    return row?.attempts ?? 0
  }

  cleanupExpiredTokens(): number {
    const result = this.db
      .prepare(`DELETE FROM magic_link_token WHERE expires_at < ?`)
      .run(Date.now())
    return result.changes
  }

  // ── Backup Email Operations ──

  addBackupEmail(
    did: string,
    email: string,
    verificationTokenHash: string,
  ): void {
    this.db
      .prepare(
        `INSERT INTO backup_email (did, email, verification_token_hash, created_at) VALUES (?, ?, ?, ?)`,
      )
      .run(did, email.toLowerCase(), verificationTokenHash, Date.now())
  }

  verifyBackupEmail(verificationTokenHash: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE backup_email SET verified = 1, verification_token_hash = NULL
       WHERE verification_token_hash = ? AND verified = 0`,
      )
      .run(verificationTokenHash)
    return result.changes > 0
  }

  getBackupEmails(did: string): BackupEmailRow[] {
    return this.db
      .prepare(
        `SELECT id, did, email, verified, verification_token_hash as verificationTokenHash,
       created_at as createdAt FROM backup_email WHERE did = ?`,
      )
      .all(did) as BackupEmailRow[]
  }

  getDidByBackupEmail(email: string): string | undefined {
    const row = this.db
      .prepare(`SELECT did FROM backup_email WHERE email = ? AND verified = 1`)
      .get(email.toLowerCase()) as { did: string } | undefined
    return row?.did
  }

  removeBackupEmail(did: string, email: string): void {
    this.db
      .prepare(`DELETE FROM backup_email WHERE did = ? AND email = ?`)
      .run(did, email.toLowerCase())
  }

  // ── Rate Limiting ──

  recordEmailSend(email: string, ipAddress: string | null): void {
    this.db
      .prepare(
        `INSERT INTO email_rate_limit (email, ip_address, sent_at) VALUES (?, ?, ?)`,
      )
      .run(email.toLowerCase(), ipAddress, Date.now())
  }

  getEmailSendCount(email: string, sinceMs: number): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) as count FROM email_rate_limit WHERE email = ? AND sent_at > ?`,
      )
      .get(email.toLowerCase(), Date.now() - sinceMs) as { count: number }
    return row.count
  }

  getIpSendCount(ipAddress: string, sinceMs: number): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) as count FROM email_rate_limit WHERE ip_address = ? AND sent_at > ?`,
      )
      .get(ipAddress, Date.now() - sinceMs) as { count: number }
    return row.count
  }

  cleanupOldRateLimitEntries(): number {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000
    const result = this.db
      .prepare(`DELETE FROM email_rate_limit WHERE sent_at < ?`)
      .run(oneDayAgo)
    return result.changes
  }

  // ── Per-email OTP failure lockout ──

  /** Record a failed OTP verification attempt for an email. */
  recordOtpFailure(email: string): void {
    this.db
      .prepare(
        `INSERT INTO otp_failed_attempts (email, failed_at) VALUES (?, ?)`,
      )
      .run(email.toLowerCase(), Date.now())
  }

  /**
   * Count OTP failures for an email within the given time window (ms).
   * Used to enforce per-email lockout independent of per-token attempt limits.
   */
  getOtpFailureCount(email: string, sinceMs: number): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) as count FROM otp_failed_attempts WHERE email = ? AND failed_at > ?`,
      )
      .get(email.toLowerCase(), Date.now() - sinceMs) as { count: number }
    return row.count
  }

  /** Remove old OTP failure records (call during periodic cleanup). */
  cleanupOldOtpFailures(): number {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000
    const result = this.db
      .prepare(`DELETE FROM otp_failed_attempts WHERE failed_at < ?`)
      .run(oneDayAgo)
    return result.changes
  }

  // ── Magic Link Token by CSRF (for polling) ──

  getMagicLinkTokenByCsrf(csrfToken: string): MagicLinkTokenRow | undefined {
    return this.db
      .prepare(
        `
      SELECT
        token_hash as tokenHash, email, created_at as createdAt,
        expires_at as expiresAt, used, auth_request_id as authRequestId,
        client_id as clientId, device_info as deviceInfo, csrf_token as csrfToken, code_hash as codeHash, attempts
      FROM magic_link_token WHERE csrf_token = ? ORDER BY created_at DESC LIMIT 1
    `,
      )
      .get(csrfToken) as MagicLinkTokenRow | undefined
  }

  // Delete all data for a DID (account deletion / GDPR).
  // Note: email-specific cleanup (magic_link_token, email_rate_limit) is best-effort
  // since the primary email is now owned by the PDS (account.sqlite), not by us.
  deleteAccountData(did: string): void {
    this.db.prepare('DELETE FROM backup_email WHERE did = ?').run(did)
  }

  // ── Auth Flow Operations ──
  // Short-lived records that thread the AT Protocol request_uri through better-auth flows.

  createAuthFlow(data: {
    flowId: string
    requestUri: string
    clientId: string | null
    expiresAt: number
  }): void {
    this.db
      .prepare(
        `INSERT INTO auth_flow (flow_id, request_uri, client_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        data.flowId,
        data.requestUri,
        data.clientId,
        Date.now(),
        data.expiresAt,
      )
  }

  getAuthFlow(flowId: string): AuthFlowRow | undefined {
    return this.db
      .prepare(
        `SELECT flow_id as flowId, request_uri as requestUri, client_id as clientId,
       email, created_at as createdAt, expires_at as expiresAt
       FROM auth_flow WHERE flow_id = ? AND expires_at > ?`,
      )
      .get(flowId, Date.now()) as AuthFlowRow | undefined
  }

  /** Look up a non-expired auth_flow by request_uri (for idempotency on duplicate GETs). */
  getAuthFlowByRequestUri(requestUri: string): AuthFlowRow | undefined {
    return this.db
      .prepare(
        `SELECT flow_id as flowId, request_uri as requestUri, client_id as clientId,
       email, created_at as createdAt, expires_at as expiresAt
       FROM auth_flow WHERE request_uri = ? AND expires_at > ?
       ORDER BY created_at DESC LIMIT 1`,
      )
      .get(requestUri, Date.now()) as AuthFlowRow | undefined
  }

  deleteAuthFlow(flowId: string): void {
    this.db.prepare(`DELETE FROM auth_flow WHERE flow_id = ?`).run(flowId)
  }

  cleanupExpiredAuthFlows(): number {
    const result = this.db
      .prepare(`DELETE FROM auth_flow WHERE expires_at < ?`)
      .run(Date.now())
    return result.changes
  }

  // ── Metrics ──

  getMetrics(): {
    pendingTokens: number
    backupEmails: number
    rateLimitEntries: number
  } {
    const now = Date.now()
    const pendingTokens = (
      this.db
        .prepare(
          'SELECT COUNT(*) as c FROM magic_link_token WHERE used = 0 AND expires_at > ?',
        )
        .get(now) as { c: number }
    ).c
    const backupEmails = (
      this.db
        .prepare('SELECT COUNT(*) as c FROM backup_email WHERE verified = 1')
        .get() as { c: number }
    ).c
    const rateLimitEntries = (
      this.db.prepare('SELECT COUNT(*) as c FROM email_rate_limit').get() as {
        c: number
      }
    ).c
    return { pendingTokens, backupEmails, rateLimitEntries }
  }

  // ── Per-Client Login Tracking ──

  hasClientLogin(email: string, clientId: string): boolean {
    const row = this.db
      .prepare(`SELECT 1 FROM client_logins WHERE email = ? AND client_id = ?`)
      .get(email.toLowerCase(), clientId)
    return !!row
  }

  recordClientLogin(email: string, clientId: string): void {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO client_logins (email, client_id, first_login_at) VALUES (?, ?, ?)`,
      )
      .run(email.toLowerCase(), clientId, Date.now())
  }

  close(): void {
    this.db.close()
  }
}
