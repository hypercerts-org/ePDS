/**
 * Attestation — proving the signer's key material lives inside a TEE.
 *
 * In production the signer runs as a dstack workload inside a
 * confidential VM (Intel TDX / AMD SEV-SNP). dstack exposes a guest
 * agent on a unix socket that returns a hardware quote over caller-
 * supplied report data. We bind the quote to this signer instance by
 * putting SHA-256(identity public key) into report_data — a verifier
 * can then check: genuine hardware, expected code measurement, and
 * that THIS public key (and therefore every key derived alongside it)
 * lives inside the measured code.
 *
 * Outside a TEE (dev), there is no quote: mode is 'dev' and callers
 * that require attestation (EPDS_SIGNER_REQUIRE_ATTESTATION=1) must
 * refuse to proceed.
 */
import * as fs from 'node:fs'
import * as http from 'node:http'

export interface AttestationResult {
  mode: 'dstack' | 'dev'
  /** hex SHA-256 of the signer identity public key, bound into the quote */
  reportData: string
  /** hex-encoded hardware quote, or null in dev mode */
  quote: string | null
  note?: string
}

const DEFAULT_DSTACK_SOCK = '/var/run/dstack.sock'

/** Fetch a quote from the dstack guest agent over its unix socket. */
function fetchDstackQuote(
  socketPath: string,
  reportDataHex: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path: `/GetQuote?report_data=${reportDataHex}`,
        method: 'GET',
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            if (typeof body.quote === 'string') resolve(body.quote)
            else reject(new Error('dstack response missing quote'))
          } catch (err) {
            reject(err instanceof Error ? err : new Error(String(err)))
          }
        })
      },
    )
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('dstack quote timeout')))
    req.end()
  })
}

export async function getAttestation(opts: {
  reportDataHex: string
  dstackSockPath?: string
}): Promise<AttestationResult> {
  const sockPath = opts.dstackSockPath ?? DEFAULT_DSTACK_SOCK
  if (fs.existsSync(sockPath)) {
    try {
      const quote = await fetchDstackQuote(sockPath, opts.reportDataHex)
      return { mode: 'dstack', reportData: opts.reportDataHex, quote }
    } catch (err) {
      return {
        mode: 'dev',
        reportData: opts.reportDataHex,
        quote: null,
        note: `dstack socket present but quote failed: ${err instanceof Error ? err.message : String(err)}`,
      }
    }
  }
  return {
    mode: 'dev',
    reportData: opts.reportDataHex,
    quote: null,
    note: 'no TEE guest agent found — running unattested (dev mode)',
  }
}
