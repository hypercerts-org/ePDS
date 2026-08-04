import { describe, expect, it } from 'vitest'
import { adaptOtpBrandingCss } from '../lib/otp-branding-compat.js'

const SLOT_ALIAS = ':where(#otp-boxes)>div:where(.otp-box)'
const ACTIVE_SLOT_ALIAS = `${SLOT_ALIAS}.active`
const INPUT_PLACEHOLDER_ALIAS = `${SLOT_ALIAS}>span:where(.otp-character.placeholder)`
const CLASS_SLOT_ALIAS = ':where(#otp-boxes)>div.otp-box'
const DATA_SLOT_ALIAS = ':where(#otp-boxes)>div[data-slot]:where(.otp-box)'
const OTP_PLACEHOLDER_ALIAS = '.otp-box>span:where(.otp-character.placeholder)'

describe('adaptOtpBrandingCss', () => {
  it('returns absent when the client has no branding CSS', () => {
    expect(adaptOtpBrandingCss(null)).toEqual({
      status: 'absent',
      css: null,
      rewrites: [],
    })
  })

  it('keeps unrelated CSS byte-for-byte unchanged', () => {
    const css = 'body { color: tomato; }'

    expect(adaptOtpBrandingCss(css)).toEqual({
      status: 'unchanged',
      css,
      rewrites: [],
    })
  })

  it('projects safe bare input visual declarations onto every slot', () => {
    const result = adaptOtpBrandingCss(`
      body, span, input {
        /* Comments inside a rule must not affect declaration filtering. */
        font-family: Georgia, serif !important;
      }
      input {
        background-color: #faf8f6 !important;
        border: 1px solid #d4c9bc !important;
        color: #1a130f !important;
      }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual(['input'])
    expect((result.css ?? '').split(SLOT_ALIAS)).toHaveLength(3)
  })

  it('deduplicates bare focus and focus-visible projections', () => {
    const result = adaptOtpBrandingCss(`
      input:focus,
      input:focus-visible,
      textarea:focus {
        border-color: #3e7053 !important;
        outline-color: #3e7053 !important;
        box-shadow: 0 0 0 3px #3e70533d !important;
      }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual(['input-focus'])
    expect((result.css ?? '').split(ACTIVE_SLOT_ALIAS)).toHaveLength(2)
  })

  it('projects a bare input placeholder color onto empty characters', () => {
    const result = adaptOtpBrandingCss(
      'input::placeholder, textarea::placeholder { color: #8c8279 !important; }',
    )

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual(['input-placeholder'])
    expect(result.css).toContain(INPUT_PLACEHOLDER_ALIAS)
  })

  it('projects class-qualified legacy input variants with matching specificity', () => {
    const result = adaptOtpBrandingCss(`
      input.otp-box {
        background: #faf8f6 !important;
        border-radius: 0 !important;
        font-family: ui-monospace, monospace !important;
      }
      input.otp-box:focus,
      input.otp-box:focus-visible {
        border-color: #3e7053 !important;
        box-shadow: 0 0 0 3px #3e70533d !important;
      }
      input.otp-box::placeholder {
        color: #8c8279 !important;
        font-style: italic !important;
      }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual([
      'input-otp-box',
      'input-otp-box-focus',
      'input-otp-box-placeholder',
    ])
    expect(result.css).toContain(CLASS_SLOT_ALIAS)
    expect(result.css).toContain(`${CLASS_SLOT_ALIAS}.active`)
    expect(result.css).toContain(
      `${CLASS_SLOT_ALIAS}>span:where(.otp-character.placeholder)`,
    )
  })

  it('projects data-slot-qualified legacy input variants with matching specificity', () => {
    const result = adaptOtpBrandingCss(`
      input[data-slot] { color: #1a130f !important; }
      input[data-slot]:focus,
      input[data-slot]:focus-visible { outline: 2px solid #d4b08a !important; }
      input[data-slot]::placeholder { color: #8c8279 !important; }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual([
      'input-data-slot',
      'input-data-slot-focus',
      'input-data-slot-placeholder',
    ])
    expect(result.css).toContain(DATA_SLOT_ALIAS)
    expect(result.css).toContain(`${DATA_SLOT_ALIAS}.active`)
    expect(result.css).toContain(
      `${DATA_SLOT_ALIAS}>span:where(.otp-character.placeholder)`,
    )
  })

  it('projects class-level focus and placeholder selectors', () => {
    const result = adaptOtpBrandingCss(`
      .otp-box:focus,
      .otp-box:focus-visible {
        border-color: #8b5cf6 !important;
        outline: 2px solid #8b5cf6 !important;
      }
      .otp-box::placeholder { color: #d9d8d2 !important; }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual(['otp-box-focus', 'otp-box-placeholder'])
    expect(result.css).toContain('.otp-box.active')
    expect(result.css).toContain(OTP_PLACEHOLDER_ALIAS)
  })

  it('preserves keyframe offsets while projecting ordinary selectors', () => {
    const result = adaptOtpBrandingCss(`
      @keyframes otp-caret-blink {
        0%, 70%, 100% { opacity: 1; }
        20%, 50% { opacity: 0; }
      }
      input { color: #1a130f !important; }
    `)

    expect(result.status).toBe('adapted')
    expect(result.rewrites).toEqual(['input'])
    expect(result.css).toContain('@keyframes otp-caret-blink')
    expect(result.css).toContain('20%, 50% { opacity: 0; }')
    expect(result.css).toContain(SLOT_ALIAS)
  })

  it('does not project mechanical declarations onto visual slots', () => {
    const css = `
      input,
      input.otp-box,
      input[data-slot] {
        display: none !important;
        touch-action: none !important;
      }
    `

    expect(adaptOtpBrandingCss(css)).toEqual({
      status: 'unchanged',
      css,
      rewrites: [],
    })
  })

  it('does not project unrelated or structurally complex selectors', () => {
    const css = `
      .field input,
      input[type="checkbox"],
      .theme input.otp-box,
      :is(.otp-box):focus {
        background: white !important;
      }
    `

    expect(adaptOtpBrandingCss(css)).toEqual({
      status: 'unchanged',
      css,
      rewrites: [],
    })
  })

  it('does not duplicate a visual alias already supplied in the same rule', () => {
    const css = `input, ${SLOT_ALIAS} { color: #1a130f; }`

    expect(adaptOtpBrandingCss(css)).toEqual({
      status: 'unchanged',
      css,
      rewrites: [],
    })
  })

  it('is idempotent', () => {
    const first = adaptOtpBrandingCss(`
      input { background: #faf8f6 !important; }
      input.otp-box:focus { border-color: #3e7053 !important; }
      input[data-slot]::placeholder { color: #8c8279 !important; }
    `)
    expect(first.status).toBe('adapted')

    const second = adaptOtpBrandingCss(first.css)
    expect(second).toEqual({
      status: 'unchanged',
      css: first.css,
      rewrites: [],
    })
  })

  it('falls back to the original CSS when parsing fails', () => {
    const css = '.otp-box:focus { color: gold;'
    const result = adaptOtpBrandingCss(css)

    expect(result.status).toBe('fallback')
    expect(result.css).toBe(css)
    expect(result.rewrites).toEqual([])
    if (result.status === 'fallback') {
      expect(result.failure.kind).toBe('stylesheet-parse-failed')
    }
  })

  it('re-escapes a closing style tag after serialization', () => {
    const result = adaptOtpBrandingCss(
      '.otp-box::placeholder { color: "</style><script>bad</script>"; }',
    )

    expect(result.status).toBe('adapted')
    expect(result.css).not.toContain('</style>')
    expect(result.css).toMatch(/\\(?:u003c|3c )\/style>/)
  })
})
