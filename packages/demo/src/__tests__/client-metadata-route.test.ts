/**
 * The demo advertises its Atmosphere hand-off endpoint in client metadata.
 * The endpoint must be the verifying /api/oauth/handoff route: pointing it
 * at /api/oauth/login would silently skip the state and issuer checks.
 */
import { describe, it, expect } from 'vitest'
import { GET } from '../app/client-metadata.json/route.js'

describe('GET /client-metadata.json', () => {
  it('points epds_handle_login_url at the verifying hand-off route', async () => {
    const res = await GET()
    const metadata = (await res.json()) as { epds_handle_login_url: string }

    expect(metadata.epds_handle_login_url).toMatch(/\/api\/oauth\/handoff$/)
  })
})
