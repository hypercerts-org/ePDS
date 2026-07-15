/**
 * Minimal base58btc encoder — used for Solana address rendering only.
 * (Bitcoin/IPFS alphabet; no checksum. Solana addresses are the raw
 * base58 of the 32-byte ed25519 public key.)
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return ''

  // Count leading zero bytes — each maps to a literal '1'.
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++

  // Repeated division of the big-endian number by 58.
  const digits: number[] = []
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  while (value > 0n) {
    digits.push(Number(value % 58n))
    value /= 58n
  }

  return (
    '1'.repeat(zeros) +
    digits
      .reverse()
      .map((d) => ALPHABET[d])
      .join('')
  )
}
