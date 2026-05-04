import { describe, expect, it } from 'vitest'

import { DEFAULT_BRANDING_CSS } from '../lib/default-branding.js'

describe('DEFAULT_BRANDING_CSS', () => {
  it('stacks upstream FormCard action rows on mobile only', () => {
    const upstreamActionRowSelector =
      '.flex.flex-row-reverse.flex-wrap.items-center.justify-end.space-x-2.space-x-reverse'

    expect(DEFAULT_BRANDING_CSS).toContain('@media (max-width: 767.98px)')
    expect(DEFAULT_BRANDING_CSS).toContain(upstreamActionRowSelector)
    expect(DEFAULT_BRANDING_CSS).toContain(
      `${upstreamActionRowSelector} { flex-direction: column-reverse !important;`,
    )
    expect(DEFAULT_BRANDING_CSS).toContain(
      'align-items: stretch !important; gap: 0.5rem !important;',
    )
    expect(DEFAULT_BRANDING_CSS).toContain(
      `${upstreamActionRowSelector} > * { margin-left: 0 !important; margin-right: 0 !important; margin-inline-start: 0 !important; margin-inline-end: 0 !important; }`,
    )
    expect(DEFAULT_BRANDING_CSS).toContain(
      `${upstreamActionRowSelector} > .flex-auto { display: none !important; }`,
    )
  })
})
