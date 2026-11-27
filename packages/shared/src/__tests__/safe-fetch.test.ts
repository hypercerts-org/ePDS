import { describe, expect, it } from 'vitest'
import { makeSafeFetch } from '../safe-fetch.js'

/**
 * Both rejections happen before any connection is attempted, so no network
 * or local server is needed. Each test names the specific policy that must
 * reject, so removing that protection makes it fail.
 *
 * Redirect rejection (`redirect: 'error'`) is deliberately not unit-tested:
 * reaching a redirecting server requires a loopback http origin on a custom
 * port, which `makeSafeFetch` can only enable together with the protections
 * under test (it exposes no separate switches), and adding a seam just for a
 * test is not worth it. The e2e suite exercises the real client-metadata path.
 */
describe('makeSafeFetch', () => {
  it('rejects a loopback IP over https with the unicast (private IP) policy', async () => {
    const err: unknown = await makeSafeFetch()('https://127.0.0.1/').then(
      () => undefined,
      (e: unknown) => e,
    )

    expect((err as Error | undefined)?.cause).toMatchObject({
      message: expect.stringContaining('non-unicast') as unknown,
    })
  })

  it('rejects plain http with the protocol policy', async () => {
    await expect(makeSafeFetch()('http://127.0.0.1/')).rejects.toThrow(
      /Forbidden protocol "http:"/,
    )
  })
})
