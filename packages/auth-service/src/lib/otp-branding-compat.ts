import postcss from 'postcss'
import selectorParser from 'postcss-selector-parser'
import { escapeCss } from '@certified-app/shared'

export type OtpBrandingRewriteId =
  | 'input'
  | 'input-focus'
  | 'input-placeholder'
  | 'input-otp-box'
  | 'input-otp-box-focus'
  | 'input-otp-box-placeholder'
  | 'input-data-slot'
  | 'input-data-slot-focus'
  | 'input-data-slot-placeholder'
  | 'otp-box-focus'
  | 'otp-box-placeholder'

export type OtpBrandingFailureKind =
  | 'stylesheet-parse-failed'
  | 'selector-parse-failed'
  | 'serialization-failed'

/**
 * Mechanical styles that branding must not override on the real OTP input.
 * Visual branding belongs on `.otp-box` and its projected state classes.
 */
const OTP_INPUT_INVARIANT_RULES = `
  #form-verify-otp #otp-boxes > #code.otp-input-overlay {
    box-sizing: border-box !important;
    position: absolute !important;
    inset: 0 !important;
    z-index: 2147483647 !important;
    display: block !important;
    visibility: visible !important;
    opacity: 1 !important;
    pointer-events: auto !important;
    touch-action: auto !important;
    -webkit-touch-callout: default !important;
    user-select: text !important;
    -webkit-user-select: text !important;
    width: 100% !important;
    height: 100% !important;
    min-width: 0 !important;
    min-height: 0 !important;
    max-width: none !important;
    max-height: none !important;
    margin: 0 !important;
    padding: 0 !important;
    color: transparent !important;
    -webkit-text-fill-color: transparent !important;
    -webkit-text-stroke: 0 transparent !important;
    text-shadow: none !important;
    caret-color: transparent !important;
    background: transparent !important;
    border: 0 !important;
    border-radius: 0 !important;
    outline: 0 !important;
    box-shadow: none !important;
    transform: none !important;
    filter: none !important;
    clip: auto !important;
    clip-path: none !important;
    appearance: none !important;
    -webkit-appearance: none !important;
    transition: none !important;
    animation: none !important;
    font-family: monospace !important;
    font-size: 56px !important;
    line-height: 1 !important;
    letter-spacing: -0.5em !important;
    cursor: text !important;
  }
  #form-verify-otp #otp-boxes > #code.otp-input-overlay::selection {
    color: transparent !important;
    background: transparent !important;
  }
  #form-verify-otp #otp-boxes > #code.otp-input-overlay:disabled {
    cursor: not-allowed !important;
  }
  #otp-boxes > .otp-box > .otp-character {
    font-family: inherit !important;
  }
`

/**
 * Duplicate the rules outside a layer for older browsers, then place them in
 * the first-declared layer so their important declarations beat client layers.
 */
export const OTP_INPUT_INVARIANT_CSS = `
${OTP_INPUT_INVARIANT_RULES}
@layer epds-otp-invariants {
${OTP_INPUT_INVARIANT_RULES}
}
`

export type OtpBrandingCompatResult =
  | {
      status: 'absent'
      css: null
      rewrites: readonly []
    }
  | {
      status: 'unchanged'
      css: string
      rewrites: readonly []
    }
  | {
      status: 'adapted'
      css: string
      rewrites: readonly OtpBrandingRewriteId[]
    }
  | {
      status: 'fallback'
      css: string
      rewrites: readonly []
      failure: {
        kind: OtpBrandingFailureKind
        cause: unknown
      }
    }

type SelectorProjection = {
  rewrite: OtpBrandingRewriteId
  alias: string
  allowedProperties: readonly string[]
}

const SLOT_ALIAS = ':where(#otp-boxes)>div:where(.otp-box)'
const CLASS_SLOT_ALIAS = ':where(#otp-boxes)>div.otp-box'
const DATA_SLOT_ALIAS = ':where(#otp-boxes)>div[data-slot]:where(.otp-box)'
const ACTIVE_SLOT_ALIAS = `${SLOT_ALIAS}.active`
const INPUT_PLACEHOLDER_ALIAS = `${SLOT_ALIAS}>span:where(.otp-character.placeholder)`
const OTP_PLACEHOLDER_ALIAS = '.otp-box>span:where(.otp-character.placeholder)'

/**
 * This is intentionally a finite direct-selector compatibility contract. It
 * covers broad input rules plus the most common class- and attribute-qualified
 * selectors for the old OTP inputs. Structural and functional selectors stay
 * unchanged rather than reintroducing general selector rewriting.
 */
const INPUT_VISUAL_PROPERTIES = [
  'background',
  'background-color',
  'border',
  'border-color',
  'border-radius',
  'border-style',
  'border-width',
  'box-shadow',
  'color',
  'font',
  'font-family',
  'font-size',
  'font-style',
  'font-weight',
  'letter-spacing',
  'line-height',
  'outline',
  'outline-color',
  'outline-offset',
  'outline-style',
  'outline-width',
  'text-align',
  'text-shadow',
  'text-transform',
] as const
const INPUT_FOCUS_PROPERTIES = [
  'background',
  'background-color',
  'border',
  'border-color',
  'border-radius',
  'border-style',
  'border-width',
  'box-shadow',
  'color',
  'outline',
  'outline-color',
  'outline-offset',
  'outline-style',
  'outline-width',
] as const
const PLACEHOLDER_PROPERTIES = [
  'color',
  'font-style',
  'font-weight',
  'opacity',
  'text-shadow',
] as const

const SELECTOR_PROJECTIONS: Readonly<
  Partial<Record<string, SelectorProjection>>
> = {
  input: {
    rewrite: 'input',
    alias: SLOT_ALIAS,
    allowedProperties: INPUT_VISUAL_PROPERTIES,
  },
  'input:focus': {
    rewrite: 'input-focus',
    alias: ACTIVE_SLOT_ALIAS,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input:focus-visible': {
    rewrite: 'input-focus',
    alias: ACTIVE_SLOT_ALIAS,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input::placeholder': {
    rewrite: 'input-placeholder',
    alias: INPUT_PLACEHOLDER_ALIAS,
    allowedProperties: PLACEHOLDER_PROPERTIES,
  },
  'input.otp-box': {
    rewrite: 'input-otp-box',
    alias: CLASS_SLOT_ALIAS,
    allowedProperties: INPUT_VISUAL_PROPERTIES,
  },
  'input.otp-box:focus': {
    rewrite: 'input-otp-box-focus',
    alias: `${CLASS_SLOT_ALIAS}.active`,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input.otp-box:focus-visible': {
    rewrite: 'input-otp-box-focus',
    alias: `${CLASS_SLOT_ALIAS}.active`,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input.otp-box::placeholder': {
    rewrite: 'input-otp-box-placeholder',
    alias: `${CLASS_SLOT_ALIAS}>span:where(.otp-character.placeholder)`,
    allowedProperties: PLACEHOLDER_PROPERTIES,
  },
  'input[data-slot]': {
    rewrite: 'input-data-slot',
    alias: DATA_SLOT_ALIAS,
    allowedProperties: INPUT_VISUAL_PROPERTIES,
  },
  'input[data-slot]:focus': {
    rewrite: 'input-data-slot-focus',
    alias: `${DATA_SLOT_ALIAS}.active`,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input[data-slot]:focus-visible': {
    rewrite: 'input-data-slot-focus',
    alias: `${DATA_SLOT_ALIAS}.active`,
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  'input[data-slot]::placeholder': {
    rewrite: 'input-data-slot-placeholder',
    alias: `${DATA_SLOT_ALIAS}>span:where(.otp-character.placeholder)`,
    allowedProperties: PLACEHOLDER_PROPERTIES,
  },
  '.otp-box:focus': {
    rewrite: 'otp-box-focus',
    alias: '.otp-box.active',
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  '.otp-box:focus-visible': {
    rewrite: 'otp-box-focus',
    alias: '.otp-box.active',
    allowedProperties: INPUT_FOCUS_PROPERTIES,
  },
  '.otp-box::placeholder': {
    rewrite: 'otp-box-placeholder',
    alias: OTP_PLACEHOLDER_ALIAS,
    allowedProperties: PLACEHOLDER_PROPERTIES,
  },
}

function canonicalSelector(selector: selectorParser.Selector): string {
  return selectorParser().processSync(selector.toString(), { lossless: false })
}

function parseAlias(alias: string): selectorParser.Selector {
  return selectorParser().astSync(alias).nodes[0]
}

function addKnownAliases(
  selectorRoot: selectorParser.Root,
  declarationProperties: readonly string[],
): OtpBrandingRewriteId[] {
  const appliedRewrites = new Set<OtpBrandingRewriteId>()
  const existingSelectors = new Set(selectorRoot.nodes.map(canonicalSelector))
  const originalSelectors = [...selectorRoot.nodes]

  for (const selector of originalSelectors) {
    const projection = SELECTOR_PROJECTIONS[canonicalSelector(selector)]
    // Copy only complete rules from the verified client fixtures. If a rule
    // includes a mechanical property such as display or touch-action, leave
    // it on the real input rather than applying it to the visual slot divs.
    if (
      !projection ||
      declarationProperties.length === 0 ||
      !declarationProperties.every((property) =>
        projection.allowedProperties.includes(property),
      )
    ) {
      continue
    }

    const alias = parseAlias(projection.alias)
    const canonicalAlias = canonicalSelector(alias)
    if (existingSelectors.has(canonicalAlias)) continue

    selectorRoot.append(alias)
    existingSelectors.add(canonicalAlias)
    appliedRewrites.add(projection.rewrite)
  }

  return [...appliedRewrites]
}

/**
 * Project the confirmed trusted-client selectors onto the single-input OTP DOM.
 *
 * The function never throws: malformed CSS falls back to the original,
 * already escaped stylesheet so branding cannot make login unavailable.
 */
export function adaptOtpBrandingCss(
  safeClientCss: string | null,
): OtpBrandingCompatResult {
  if (!safeClientCss) {
    return { status: 'absent', css: null, rewrites: [] }
  }

  let phase: OtpBrandingFailureKind = 'stylesheet-parse-failed'

  try {
    const root = postcss.parse(safeClientCss)
    const rewrites = new Set<OtpBrandingRewriteId>()
    phase = 'selector-parse-failed'

    root.walkRules((rule) => {
      const selectorRoot = selectorParser().astSync(rule.selector)
      const declarationProperties = rule.nodes.flatMap((node) =>
        node.type === 'decl' ? [node.prop.toLowerCase()] : [],
      )
      const ruleRewrites = addKnownAliases(selectorRoot, declarationProperties)
      if (ruleRewrites.length === 0) return

      rule.selector = selectorRoot.toString()
      for (const rewrite of ruleRewrites) rewrites.add(rewrite)
    })

    if (rewrites.size === 0) {
      return { status: 'unchanged', css: safeClientCss, rewrites: [] }
    }

    phase = 'serialization-failed'
    return {
      status: 'adapted',
      css: escapeCss(root.toString()),
      rewrites: [...rewrites],
    }
  } catch (cause) {
    return {
      status: 'fallback',
      css: safeClientCss,
      rewrites: [],
      failure: { kind: phase, cause },
    }
  }
}
