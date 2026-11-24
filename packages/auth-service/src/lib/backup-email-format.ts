// Keep the existing format rules. After the first domain character, stop at
// the first dot so the matcher never retries different domain/suffix splits.
const BACKUP_EMAIL_FORMAT = /^[^\s@]+@[^\s@][^.\s@]*\.[^\s@]+$/

export function hasBackupEmailFormat(email: string): boolean {
  return BACKUP_EMAIL_FORMAT.test(email)
}
