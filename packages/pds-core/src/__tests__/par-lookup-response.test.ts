import { describe, it, expect } from 'vitest'
import { buildParLookupResponse } from '../lib/par-lookup-response.js'

describe('buildParLookupResponse', () => {
  it('returns the stored PAR fields and the OAuth issuer', () => {
    expect(
      buildParLookupResponse(
        {
          login_hint: 'alice.test',
          state: 'st-1',
          client_id: 'https://app.example/m.json',
        },
        'http://pds.localhost:3000',
      ),
    ).toEqual({
      login_hint: 'alice.test',
      state: 'st-1',
      client_id: 'https://app.example/m.json',
      issuer: 'http://pds.localhost:3000',
    })
  })

  it('reports absent optional fields as null but keeps the issuer', () => {
    expect(
      buildParLookupResponse(
        { client_id: 'https://app.example/m.json' },
        'https://pds.example',
      ),
    ).toEqual({
      login_hint: null,
      state: null,
      client_id: 'https://app.example/m.json',
      issuer: 'https://pds.example',
    })
  })

  it('returns all nulls, issuer included, when the request is not found', () => {
    expect(buildParLookupResponse(null, 'https://pds.example')).toEqual({
      login_hint: null,
      state: null,
      client_id: null,
      issuer: null,
    })
  })
})
