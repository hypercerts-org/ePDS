import { runInNewContext } from 'node:vm'
import { describe, expect, it, vi } from 'vitest'
import {
  appendScriptHashToCsp,
  buildChooserEnrichmentScript,
  createChooserEnrichmentMiddleware,
  injectHandleModeMeta,
  injectScriptIntoHead,
  isChooserRequest,
  sha256Base64,
} from '../chooser-enrichment.js'

describe('buildChooserEnrichmentScript (HYPER-268)', () => {
  it('captures both hydration globals (__sessions, __deviceSessions) via accessors', () => {
    const script = buildChooserEnrichmentScript()
    // Upstream uses __sessions on /oauth/authorize (inline chooser) and
    // __deviceSessions on /account (standalone account SPA). The script
    // must intercept BOTH with defineProperty setters so neither path
    // slips through untouched — missing this is how early iterations of
    // HYPER-268 rendered a plain handle-only chooser in browsers.
    expect(script).toContain("interceptGlobal('__deviceSessions')")
    expect(script).toContain("interceptGlobal('__sessions')")
    expect(script).toContain('Object.defineProperty(window, name')
    expect(script).toContain(
      'configurable: true, enumerable: true, writable: true',
    )
  })

  it('is deterministic', () => {
    expect(buildChooserEnrichmentScript()).toBe(buildChooserEnrichmentScript())
  })
})

class FakeTextNode {
  readonly nodeType = 3

  constructor(readonly data: string) {}
}

class FakeClassList {
  private readonly classes = new Set<string>()

  add(className: string): void {
    this.classes.add(className)
  }

  contains(className: string): boolean {
    return this.classes.has(className)
  }

  set(value: string): void {
    this.classes.clear()
    for (const className of value.split(/\s+/)) {
      if (className) this.classes.add(className)
    }
  }
}

class FakeElement {
  readonly nodeType = 1
  readonly childNodes: Array<FakeElement | FakeTextNode> = []
  readonly dataset: Record<string, string> = {}
  readonly classList = new FakeClassList()
  readonly style: Record<string, string> = {}
  id = ''
  hidden = false
  type = ''
  parentElement: FakeElement | null = null
  textContentOverride: string | null = null
  private readonly eventListeners = new Map<
    string,
    Array<(event: FakeEvent) => void>
  >()

  constructor(
    readonly tagName: string,
    private readonly attributes: Record<string, string> = {},
  ) {}

  appendChild(child: FakeElement | FakeTextNode): void {
    if (child instanceof FakeElement) {
      child.parentElement = this
    }
    this.childNodes.push(child)
  }

  insertAdjacentElement(position: string, element: FakeElement): void {
    if (position !== 'afterend' || !this.parentElement) return
    const siblings = this.parentElement.childNodes
    const index = siblings.indexOf(this)
    if (index === -1) return
    element.parentElement = this.parentElement
    siblings.splice(index + 1, 0, element)
  }

  set textContent(value: string) {
    this.textContentOverride = value
  }

  set className(value: string) {
    this.classList.set(value)
  }

  setAttribute(name: string, value: string): void {
    this.attributes[name] = value
    if (name === 'id') this.id = value
  }

  getAttribute(name: string): string | null {
    return this.attributes[name] ?? null
  }

  get textContent(): string {
    if (this.textContentOverride !== null) return this.textContentOverride
    return this.childNodes
      .map((child) =>
        child instanceof FakeTextNode ? child.data : child.textContent,
      )
      .join('')
  }

  closest(selector: string): FakeElement | null {
    if (selector === 'a') {
      if (this.tagName === 'a') return this

      let current = this.parentElement
      while (current) {
        if (current.tagName === 'a') return current
        current = current.parentElement
      }
      return null
    }

    if (selector !== '[role="button"][tabindex="0"]') return null

    if (this.attributes.role === 'button' && this.attributes.tabindex === '0') {
      return this
    }

    let current = this.parentElement
    while (current) {
      if (
        current.attributes.role === 'button' &&
        current.attributes.tabindex === '0'
      ) {
        return current
      }
      current = current.parentElement
    }
    return null
  }

  addEventListener(event: string, listener: (event: FakeEvent) => void): void {
    const listeners = this.eventListeners.get(event) ?? []
    listeners.push(listener)
    this.eventListeners.set(event, listeners)
  }

  dispatchEvent(eventName: string, init: { key?: string } = {}): FakeEvent {
    const event = new FakeEvent(init.key)
    for (const listener of this.eventListeners.get(eventName) ?? []) {
      listener(event)
    }
    return event
  }

  querySelectorAll(selector: string): FakeElement[] {
    const descendants = this.descendants()
    if (selector === 'button, a') {
      return descendants.filter(
        (el) => el.tagName === 'button' || el.tagName === 'a',
      )
    }
    if (selector === '[role="button"]') {
      return descendants.filter((el) => el.attributes.role === 'button')
    }
    if (selector === 'h2') {
      return descendants.filter((el) => el.tagName === 'h2')
    }
    return []
  }

  querySelector(selector: string): FakeElement | null {
    if (
      selector ===
      '[role="button"][aria-label="Login to account that is not listed"]'
    ) {
      return (
        this.descendants().find(
          (el) =>
            el.attributes.role === 'button' &&
            el.attributes['aria-label'] ===
              'Login to account that is not listed',
        ) ?? null
      )
    }
    if (selector === 'meta[name="epds-handle-mode"]') {
      return (
        this.descendants().find(
          (el) =>
            el.tagName === 'meta' && el.attributes.name === 'epds-handle-mode',
        ) ?? null
      )
    }
    if (selector === 'meta[name="epds-auth-origin"]') {
      return (
        this.descendants().find(
          (el) =>
            el.tagName === 'meta' && el.attributes.name === 'epds-auth-origin',
        ) ?? null
      )
    }
    return null
  }

  descendants(): FakeElement[] {
    const result: FakeElement[] = []
    const visit = (node: FakeElement): void => {
      for (const child of node.childNodes) {
        if (child instanceof FakeElement) {
          result.push(child)
          visit(child)
        }
      }
    }
    visit(this)
    return result
  }
}

class FakeEvent {
  defaultPrevented = false
  propagationStopped = false

  constructor(readonly key?: string) {}

  preventDefault(): void {
    this.defaultPrevented = true
  }

  stopPropagation(): void {
    this.propagationStopped = true
  }
}

class FakeDocument {
  readonly root = new FakeElement('div', { id: 'root' })
  readyState = 'loading'
  private domContentLoadedListener: (() => void) | null = null

  get documentElement(): FakeElement {
    return this.root
  }

  getElementById(id: string): FakeElement | null {
    return id === 'root' ? this.root : null
  }

  /**
   * Deliberate divergence from the browser: this snapshots the descendant
   * list up front, whereas a real TreeWalker is live. The enrichment script
   * inserts icons, tooltips and email labels *while* walking, so a browser
   * walker visits those inserted nodes and this fake does not.
   *
   * Benign today because nothing the script inserts can match
   * isConsentIdentityElement() (which requires a <b>/<strong> in an approved
   * consent phrasing) or matchAccountIdentifier(). If either ever loosens,
   * this fake would hide the resulting re-entrancy, so make it live rather
   * than trusting that the tests still cover the browser's behaviour.
   */
  createTreeWalker(root: FakeElement): { nextNode: () => FakeElement | null } {
    const elements = root.descendants()
    let index = 0
    return {
      nextNode: () => elements[index++] ?? null,
    }
  }

  createElement(tagName: string): FakeElement {
    return new FakeElement(tagName)
  }

  querySelector(selector: string): FakeElement | null {
    return this.root.querySelector(selector)
  }

  addEventListener(event: string, listener: () => void): void {
    if (event === 'DOMContentLoaded') this.domContentLoadedListener = listener
  }

  dispatchDOMContentLoaded(): void {
    this.readyState = 'complete'
    this.domContentLoadedListener?.()
  }
}

function appendText(parent: FakeElement, text: string): void {
  parent.appendChild(new FakeTextNode(text))
}

const DEFAULT_CHOOSER_LOCATION = {
  pathname: '/oauth/authorize',
  search: '',
}

const ALICE_ASSOCIATED_TOOLTIP =
  'This handle is associated with alice@example.test.'
const ASSOCIATED_TOOLTIP_PREFIX = 'This handle is associated'
const ALICE_PUBLIC_HANDLE_TOOLTIP =
  'Public AT Protocol handle: @alice.test. Handles are public account names used by AT Protocol apps.'
const EMAIL_LABEL_CLASS = 'epds-email-label'
const HIDDEN_HANDLE_DESCRIPTION_CLASS = 'epds-hidden-handle-description'
const IDENTITY_INFO_ICON_CLASS = 'epds-identity-info-icon'
const IDENTITY_TOOLTIP_CLASS = 'epds-identity-tooltip'

function findChildWithClass(
  parent: FakeElement,
  className: string,
): FakeElement | undefined {
  return parent.childNodes.find(
    (child) =>
      child instanceof FakeElement && child.classList.contains(className),
  ) as FakeElement | undefined
}

function findEmailLabel(parent: FakeElement): FakeElement | undefined {
  return findChildWithClass(parent, EMAIL_LABEL_CLASS)
}

function findHiddenHandleDescription(
  parent: FakeElement,
): FakeElement | undefined {
  return findChildWithClass(parent, HIDDEN_HANDLE_DESCRIPTION_CLASS)
}

function findDescendantsWithClass(
  parent: FakeElement,
  className: string,
): FakeElement[] {
  return parent.descendants().filter((el) => el.classList.contains(className))
}

function expectConsentTooltip(
  container: FakeElement,
  expectedText: string,
): void {
  const icon = findChildWithClass(container, IDENTITY_INFO_ICON_CLASS)
  const tooltip = findChildWithClass(container, IDENTITY_TOOLTIP_CLASS)

  expect(icon).toBeInstanceOf(FakeElement)
  expect(icon?.tagName).toBe('button')
  expect(icon?.getAttribute('aria-describedby')).toBe(tooltip?.id)
  expect(tooltip?.textContent).toBe(expectedText)
}

function expectConsentTooltipTexts(
  document: FakeDocument,
  expectedTexts: string[],
): void {
  const icons = findDescendantsWithClass(
    document.root,
    IDENTITY_INFO_ICON_CLASS,
  )
  const tooltips = findDescendantsWithClass(
    document.root,
    IDENTITY_TOOLTIP_CLASS,
  )

  expect(icons).toHaveLength(expectedTexts.length)
  expect(tooltips.map((tooltip) => tooltip.textContent)).toEqual(expectedTexts)
}

function runChooserEnrichmentScript(
  document: FakeDocument,
  globals: {
    __sessions?: unknown[]
    __deviceSessions?: unknown[]
    // Opt-in hook receiving the script's MutationObserver callback, so a
    // test can replay a re-render tick the way the real SPA would.
    onObserve?: (tick: () => void) => void
  } = {},
  location: { pathname: string; search?: string } = DEFAULT_CHOOSER_LOCATION,
): void {
  const fakeWindow: Record<string, unknown> = {
    location,
  }
  const onObserve = globals.onObserve
  const sandbox = {
    document,
    MutationObserver: class {
      observed = false

      constructor(private readonly tick: () => void) {}

      observe(): void {
        this.observed = true
        onObserve?.(this.tick)
      }
    },
    Node: { TEXT_NODE: 3 },
    NodeFilter: { SHOW_ELEMENT: 1 },
    URLSearchParams,
    window: fakeWindow,
  }

  runInNewContext(buildChooserEnrichmentScript(), sandbox) // NOSONAR — test executes only the deterministic script generated in this repository.
  fakeWindow.__sessions = globals.__sessions ?? [
    {
      selected: true,
      account: {
        sub: 'did:plc:alice',
        email: 'alice@example.test',
        preferred_username: 'alice.test',
        selected: true,
      },
    },
    {
      account: {
        sub: 'did:plc:bob',
        email: 'bob@example.test',
        preferred_username: 'bob.test',
      },
    },
  ]
  if (globals.__deviceSessions) {
    fakeWindow.__deviceSessions = globals.__deviceSessions
  }
  document.dispatchDOMContentLoaded()
}

function createChooserRow(
  document: FakeDocument,
  identifierText: string,
): { row: FakeElement; wrap: FakeElement; identifier: FakeElement } {
  const row = new FakeElement('div', { role: 'button', tabindex: '0' })
  const wrap = new FakeElement('span')
  const identifier = new FakeElement('span')
  appendText(identifier, identifierText)
  wrap.appendChild(identifier)
  row.appendChild(wrap)
  document.root.appendChild(row)
  return { row, wrap, identifier }
}

function createAccountListRow(
  document: FakeDocument,
  identifierText: string,
  { emptyTitle = false }: { emptyTitle?: boolean } = {},
): {
  anchor: FakeElement
  title?: FakeElement
  wrap: FakeElement
  identifier: FakeElement
} {
  const anchor = new FakeElement('a', {
    href: '/account/did:plc:alice',
    'aria-label': 'View and manage account for alice.test',
  })
  const wrap = new FakeElement('span')
  const identifier = new FakeElement('span')
  const title = emptyTitle ? new FakeElement('h2') : undefined

  if (title) anchor.appendChild(title)
  appendText(identifier, identifierText)
  wrap.appendChild(identifier)
  anchor.appendChild(wrap)
  document.root.appendChild(anchor)
  return { anchor, title, wrap, identifier }
}

function createAccountSelector(
  document: FakeDocument,
  identifierTexts: string[],
): { button: FakeElement; identifiers: FakeElement[]; wrap: FakeElement } {
  const button = new FakeElement('button', {
    'aria-label': 'Select an account',
  })
  const wrap = new FakeElement('span')
  const identifiers = identifierTexts.map((identifierText) => {
    const identifier = new FakeElement('p')
    appendText(identifier, identifierText)
    wrap.appendChild(identifier)
    return identifier
  })
  button.appendChild(wrap)
  document.root.appendChild(button)
  return { button, identifiers, wrap }
}

function createConsentIdentity(
  document: FakeDocument,
  textBefore: string,
  identifierText: string,
  textAfter: string,
  tagName = 'b',
): { container: FakeElement; identifier: FakeElement } {
  const container = new FakeElement('p')
  appendText(container, textBefore)
  const identifier = new FakeElement(tagName)
  appendText(identifier, identifierText)
  container.appendChild(identifier)
  appendText(container, textAfter)
  document.root.appendChild(container)
  return { container, identifier }
}

function createPreviewChooserConsentIdentities(
  document: FakeDocument,
  mode: string,
): {
  sidebar: { container: FakeElement; identifier: FakeElement }
  mainCard: { container: FakeElement; identifier: FakeElement }
} {
  appendHandleModeMeta(document, mode)

  return {
    sidebar: createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    ),
    mainCard: createConsentIdentity(
      document,
      'wants to access your ',
      'alice.test',
      ' account',
    ),
  }
}

function runPreviewChooserConsentEnrichment(
  document: FakeDocument,
  mode: string,
): void {
  runChooserEnrichmentScript(
    document,
    { __sessions: selectedAliceSession() },
    {
      pathname: '/preview/chooser',
      search: `?epds_handle_mode=${mode}`,
    },
  )
}

function expectArbitraryConsentProseUntouched({
  prefix,
  identifierText,
  suffix,
  tagName,
  expectedText,
}: {
  prefix: string
  identifierText: string
  suffix: string
  tagName?: string
  expectedText: string
}): void {
  const document = new FakeDocument()
  appendHandleModeMeta(document, 'picker')
  const { container, identifier } = createConsentIdentity(
    document,
    prefix,
    identifierText,
    suffix,
    tagName,
  )

  runChooserEnrichmentScript(document, { __sessions: selectedAliceSession() })

  expect(identifier.textContent).toBe(identifierText)
  expect(container.textContent).toBe(expectedText)
  expect(container.textContent).not.toContain(ASSOCIATED_TOOLTIP_PREFIX)
}

function findConsentIdentityTooltip(container: FakeElement): {
  icon: FakeElement
  tooltip: FakeElement
} {
  const icon = findChildWithClass(container, IDENTITY_INFO_ICON_CLASS)
  const tooltip = findChildWithClass(container, IDENTITY_TOOLTIP_CLASS)

  return { icon: icon as FakeElement, tooltip: tooltip as FakeElement }
}

function selectedAliceSession(preferredUsername = 'alice.test'): unknown[] {
  return [
    {
      selected: true,
      account: {
        sub: 'did:plc:alice',
        email: 'alice@example.test',
        preferred_username: preferredUsername,
        selected: true,
      },
    },
  ]
}

function aliceDeviceSession(): unknown[] {
  return [
    {
      account: {
        sub: 'did:plc:alice',
        email: 'alice@example.test',
        preferred_username: 'alice.test',
      },
      selected: true,
    },
  ]
}

/** An account with no handle yet, so only its DID can match the rendered text. */
function handlelessDeviceSession(): unknown[] {
  return [
    {
      account: {
        sub: 'did:plc:alice',
        email: 'alice@example.test',
      },
      selected: true,
    },
  ]
}

function appendHandleModeMeta(document: FakeDocument, mode: string): void {
  document.root.appendChild(
    new FakeElement('meta', { name: 'epds-handle-mode', content: mode }),
  )
}

describe('buildChooserEnrichmentScript account row scoping', () => {
  it('does not enrich consent copy outside a chooser account row', () => {
    const document = new FakeDocument()
    const paragraph = new FakeElement('p')
    const consentHandle = new FakeElement('span')
    appendText(consentHandle, 'alice.test')
    paragraph.appendChild(consentHandle)
    appendText(paragraph, ' grants access to did:plc:alice')
    document.root.appendChild(paragraph)

    runChooserEnrichmentScript(document)

    expect(document.root.descendants()).not.toContainEqual(
      expect.objectContaining({ textContentOverride: 'alice@example.test' }),
    )
    expect(consentHandle.classList.contains('epds-handle-label')).toBe(false)
  })

  it('enriches a chooser-like account row', () => {
    const document = new FakeDocument()
    const {
      row,
      wrap,
      identifier: handle,
    } = createChooserRow(document, 'alice.test')

    runChooserEnrichmentScript(document)

    const emailLabel = findEmailLabel(wrap)

    expect(emailLabel).toBeInstanceOf(FakeElement)
    // Trimmed: the chooser label is rendered with a leading space for
    // visual separation from the handle, which is presentation, not identity.
    expect(emailLabel?.textContent.trim()).toBe('alice@example.test')
    expect(handle.classList.contains('epds-handle-label')).toBe(true)
    expect(handle.style.display).toBeUndefined()
    expect(row.getAttribute('aria-label')).toBe('Sign in as alice@example.test')
  })

  it('enriches preview chooser rows in picker-with-random mode', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker-with-random')
    const {
      row,
      wrap,
      identifier: handle,
    } = createChooserRow(document, 'alice.test')

    runChooserEnrichmentScript(
      document,
      {},
      { pathname: '/preview/chooser', search: '' },
    )

    expect(wrap.textContent).toContain('alice@example.test')
    expect(handle.classList.contains('epds-handle-label')).toBe(true)
    expect(handle.style.display).toBeUndefined()
    expect(row.getAttribute('aria-label')).toBe('Sign in as alice@example.test')
  })

  it('uses email as the visible random-mode identifier and describes the hidden handle', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const {
      row,
      wrap,
      identifier: handle,
    } = createChooserRow(document, 'alice.test')

    runChooserEnrichmentScript(document)

    const emailLabel = findEmailLabel(wrap)
    const handleDescription = findHiddenHandleDescription(row)

    expect(emailLabel?.textContent.trim()).toBe('alice@example.test')
    expect(handle.style.display).toBe('none')
    expect(handleDescription?.textContent).toBe('Underlying handle: alice.test')
    expect(row.getAttribute('aria-describedby')).toBe(handleDescription?.id)
    expect(emailLabel?.getAttribute('title')).toBeNull()
    expect(row.getAttribute('aria-label')).toBe('Sign in as alice@example.test')
  })

  it('uses email as the visible random-mode identifier on preview chooser rows', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const {
      row,
      wrap,
      identifier: handle,
    } = createChooserRow(document, 'alice.test')

    runChooserEnrichmentScript(
      document,
      {},
      { pathname: '/preview/chooser', search: '' },
    )

    const emailLabel = findEmailLabel(wrap)
    const handleDescription = findHiddenHandleDescription(row)

    expect(emailLabel?.textContent.trim()).toBe('alice@example.test')
    expect(handle.style.display).toBe('none')
    expect(handleDescription?.textContent).toBe('Underlying handle: alice.test')
    expect(row.getAttribute('aria-describedby')).toBe(handleDescription?.id)
  })

  it('gives rows enriched on a later re-render tick a distinct hidden-handle id', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { row: aliceRow } = createChooserRow(document, 'alice.test')

    let replayTick: (() => void) | undefined
    runChooserEnrichmentScript(document, {
      onObserve: (tick) => {
        replayTick = tick
      },
    })

    // Bob's row arrives in a later SPA render. The first row is already
    // marked enriched and so is excluded from the rebuilt match list,
    // which is exactly the situation where a per-tick index restarts
    // at 0 and collides with Alice's existing description id.
    const { row: bobRow } = createChooserRow(document, 'bob.test')
    expect(replayTick).toBeDefined()
    replayTick?.()

    const aliceId = findHiddenHandleDescription(aliceRow)?.id
    const bobId = findHiddenHandleDescription(bobRow)?.id

    expect(aliceId).toBeTruthy()
    expect(bobId).toBeTruthy()
    // Duplicate ids would make aria-describedby resolve to the first
    // node, so Bob's row would announce Alice's handle.
    expect(bobId).not.toBe(aliceId)
    expect(bobRow.getAttribute('aria-describedby')).toBe(bobId)
  })

  it('does not hide random-mode handles outside oauth authorize', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { wrap, identifier, anchor } = createAccountListRow(
      document,
      'alice.test',
    )

    runChooserEnrichmentScript(
      document,
      {},
      { pathname: '/account', search: '' },
    )

    expect(wrap.textContent).toContain('alice@example.test')
    expect(identifier.style.display).toBeUndefined()
    expect(anchor.getAttribute('aria-label')).toBe(
      'View and manage account for alice@example.test (@alice.test)',
    )
  })

  it('uses an empty account-list title slot for the email on account pages', () => {
    const document = new FakeDocument()
    const { title, identifier, anchor } = createAccountListRow(
      document,
      'alice.test',
      { emptyTitle: true },
    )

    runChooserEnrichmentScript(
      document,
      {},
      { pathname: '/account', search: '' },
    )

    expect(title?.textContent).toBe('alice@example.test')
    expect(identifier.textContent).toBe('alice.test')
    expect(identifier.style.display).toBeUndefined()
    expect(anchor.getAttribute('aria-label')).toBe(
      'View and manage account for alice@example.test (@alice.test)',
    )
  })

  it('leaves non-account links on account pages untouched', () => {
    const document = new FakeDocument()
    const anotherAccount = new FakeElement('a', {
      href: '/account/login',
      'aria-label': 'Sign in with another account',
    })
    appendText(anotherAccount, 'Sign in with another account')
    document.root.appendChild(anotherAccount)
    const terms = new FakeElement('a', { href: '/terms' })
    appendText(terms, 'Terms')
    document.root.appendChild(terms)
    const prose = new FakeElement('p')
    appendText(prose, 'Manage alice.test from this page.')
    document.root.appendChild(prose)

    runChooserEnrichmentScript(
      document,
      {},
      { pathname: '/account', search: '' },
    )

    expect(anotherAccount.textContent).toBe('Sign in with another account')
    expect(terms.textContent).toBe('Terms')
    expect(prose.textContent).toBe('Manage alice.test from this page.')
    expect(document.root.textContent).not.toContain('alice@example.test')
  })

  it('adds email next to the current account selector handle on account detail pages', () => {
    const document = new FakeDocument()
    const { button, identifiers, wrap } = createAccountSelector(document, [
      'alice.test',
    ])

    runChooserEnrichmentScript(
      document,
      { __sessions: [], __deviceSessions: aliceDeviceSession() },
      { pathname: '/account/did:plc:alice', search: '' },
    )

    expect(identifiers[0].textContent).toBe('alice.test')
    expect(identifiers[0].style.display).toBeUndefined()
    expect(wrap.textContent).toContain('alice@example.test')
    expect(button.getAttribute('aria-label')).toBe(
      'Select account alice@example.test (@alice.test)',
    )
  })

  it('does not present a DID as a handle in the account selector accessible name', () => {
    const document = new FakeDocument()
    const { button } = createAccountSelector(document, ['did:plc:alice'])

    runChooserEnrichmentScript(
      document,
      { __sessions: [], __deviceSessions: handlelessDeviceSession() },
      { pathname: '/account/did:plc:alice', search: '' },
    )

    // A DID is not a handle, so it must not be decorated with '@'.
    expect(button.getAttribute('aria-label')).toBe(
      'Select account alice@example.test (did:plc:alice)',
    )
  })

  it('collapses duplicate current account selector handle lines to email plus handle', () => {
    const document = new FakeDocument()
    const { button, identifiers } = createAccountSelector(document, [
      'alice.test',
      'alice.test',
    ])

    runChooserEnrichmentScript(
      document,
      { __sessions: [], __deviceSessions: aliceDeviceSession() },
      { pathname: '/account/did:plc:alice', search: '' },
    )

    expect(identifiers[0].textContent).toBe('alice@example.test')
    expect(identifiers[1].textContent).toBe('alice.test')
    expect(button.textContent).toBe('alice@example.testalice.test')
    expect(button.getAttribute('aria-label')).toBe(
      'Select account alice@example.test (@alice.test)',
    )
  })

  it('keeps the current account selector handle visible when account pages use random mode', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { identifiers, wrap } = createAccountSelector(document, [
      'alice.test',
    ])

    runChooserEnrichmentScript(
      document,
      { __sessions: [], __deviceSessions: aliceDeviceSession() },
      { pathname: '/account/did:plc:alice', search: '' },
    )

    expect(identifiers[0].textContent).toBe('alice.test')
    expect(identifiers[0].style.display).toBeUndefined()
    expect(wrap.textContent).toContain('alice@example.test')
  })

  it('does not enrich non-selector controls on account detail pages', () => {
    const document = new FakeDocument()
    createAccountSelector(document, ['alice.test'])
    const connectedApp = new FakeElement('button', {
      'aria-label': 'Open app settings',
    })
    appendText(connectedApp, 'alice.test')
    document.root.appendChild(connectedApp)
    const signOut = new FakeElement('button', { 'aria-label': 'Sign out' })
    appendText(signOut, 'Sign out alice.test')
    document.root.appendChild(signOut)
    const breadcrumb = new FakeElement('a', { href: '/account' })
    appendText(breadcrumb, 'alice.test')
    document.root.appendChild(breadcrumb)

    runChooserEnrichmentScript(
      document,
      { __sessions: [], __deviceSessions: aliceDeviceSession() },
      { pathname: '/account/did:plc:alice', search: '' },
    )

    expect(connectedApp.textContent).toBe('alice.test')
    expect(signOut.textContent).toBe('Sign out alice.test')
    expect(breadcrumb.textContent).toBe('alice.test')
  })

  it('enriches exact at-prefixed handle matches', () => {
    const document = new FakeDocument()
    const { wrap, identifier } = createChooserRow(document, '@alice.test')

    runChooserEnrichmentScript(document)

    expect(wrap.textContent).toContain('alice@example.test')
    expect(identifier.classList.contains('epds-handle-label')).toBe(true)
  })

  it('enriches exact DID matches', () => {
    const document = new FakeDocument()
    const { wrap, identifier } = createChooserRow(document, 'did:plc:alice')

    runChooserEnrichmentScript(document)

    expect(wrap.textContent).toContain('alice@example.test')
    expect(identifier.classList.contains('epds-handle-label')).toBe(true)
  })

  it('enriches rows from captured device sessions', () => {
    const document = new FakeDocument()
    const { wrap, identifier } = createChooserRow(document, 'carol.test')

    runChooserEnrichmentScript(document, {
      __sessions: [],
      __deviceSessions: [
        {
          account: {
            sub: 'did:plc:carol',
            email: 'carol@example.test',
            preferred_username: 'carol.test',
          },
          selected: true,
        },
      ],
    })

    expect(wrap.textContent).toContain('carol@example.test')
    expect(identifier.classList.contains('epds-handle-label')).toBe(true)
  })

  it('does not enrich substring-only chooser row prose', () => {
    const document = new FakeDocument()
    const { wrap, identifier } = createChooserRow(
      document,
      'Signed in as alice.test',
    )

    runChooserEnrichmentScript(document)

    expect(wrap.textContent).not.toContain('alice@example.test')
    expect(identifier.classList.contains('epds-handle-label')).toBe(false)
  })

  it('enriches multiple chooser-like account rows', () => {
    const document = new FakeDocument()
    const rows = ['alice.test', 'bob.test'].map((handleText) => {
      const row = new FakeElement('div', { role: 'button', tabindex: '0' })
      const wrap = new FakeElement('span')
      const handle = new FakeElement('span')
      appendText(handle, handleText)
      wrap.appendChild(handle)
      row.appendChild(wrap)
      document.root.appendChild(row)
      return { wrap, handle }
    })

    runChooserEnrichmentScript(document)

    expect(rows[0].wrap.textContent).toContain('alice@example.test')
    expect(rows[1].wrap.textContent).toContain('bob@example.test')
    expect(rows[0].handle.classList.contains('epds-handle-label')).toBe(true)
    expect(rows[1].handle.classList.contains('epds-handle-label')).toBe(true)
  })
})

describe('buildChooserEnrichmentScript consent identity enrichment', () => {
  it('enriches grant-access consent identity copy', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker')
    const { container, identifier } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document)

    expect(identifier.textContent).toBe('alice.test')
    expectConsentTooltip(container, ALICE_ASSOCIATED_TOOLTIP)
  })

  it('enriches client-wants-access consent identity copy', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker')
    const { container, identifier } = createConsentIdentity(
      document,
      'Example App wants to access your ',
      'alice.test',
      ' account',
      'strong',
    )

    runChooserEnrichmentScript(document, {
      __sessions: selectedAliceSession(),
    })

    expect(identifier.textContent).toBe('alice.test')
    expect(container.textContent).toContain(ALICE_ASSOCIATED_TOOLTIP)
  })

  it('enriches upstream main-card consent identity copy without same-paragraph client name', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker')
    const { container, identifier } = createConsentIdentity(
      document,
      'wants to access your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document, {
      __sessions: selectedAliceSession(),
    })

    const iconIndex = container.childNodes.findIndex(
      (child) =>
        child instanceof FakeElement &&
        child.classList.contains(IDENTITY_INFO_ICON_CLASS),
    )
    const identifierIndex = container.childNodes.indexOf(identifier)

    expect(identifier.textContent).toBe('alice.test')
    expect(iconIndex).toBe(identifierIndex + 1)
    expect(container.textContent).toContain(ALICE_ASSOCIATED_TOOLTIP)
  })

  it('enriches sidebar and main-card consent identities on the same page', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker-with-random')
    const sidebar = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )
    const mainCard = createConsentIdentity(
      document,
      'wants to access your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(
      document,
      { __sessions: selectedAliceSession() },
      { pathname: '/preview/consent', search: '' },
    )

    expect(sidebar.identifier.textContent).toBe('alice.test')
    expect(mainCard.identifier.textContent).toBe('alice.test')
    expectConsentTooltipTexts(document, [
      ALICE_ASSOCIATED_TOOLTIP,
      ALICE_ASSOCIATED_TOOLTIP,
    ])
  })

  it('treats picker-with-random and default consent like picker consent', () => {
    for (const mode of ['picker-with-random', null]) {
      const document = new FakeDocument()
      if (mode) appendHandleModeMeta(document, mode)
      const { container, identifier } = createConsentIdentity(
        document,
        'Example App wants to access your ',
        'alice.test',
        ' account',
      )

      runChooserEnrichmentScript(document, {
        __sessions: selectedAliceSession(),
      })

      expect(identifier.textContent).toBe('alice.test')
      expect(container.textContent).toContain(ALICE_ASSOCIATED_TOOLTIP)
    }
  })

  it('shows the email for random consent and exposes the public handle in the tooltip', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { container, identifier } = createConsentIdentity(
      document,
      'Grant access to your ',
      '@alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document, {
      __sessions: selectedAliceSession('@alice.test'),
    })

    expect(identifier.textContent).toBe('alice@example.test')
    expect(container.textContent).toContain(ALICE_PUBLIC_HANDLE_TOOLTIP)
    expect(container.textContent).not.toContain('@@alice.test')
  })

  it('describes a DID as an identifier, not a handle, in the random consent tooltip', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { container, identifier } = createConsentIdentity(
      document,
      'Grant access to your ',
      'did:plc:alice',
      ' account',
    )

    runChooserEnrichmentScript(document, {
      __sessions: [
        {
          selected: true,
          account: {
            sub: 'did:plc:alice',
            email: 'alice@example.test',
            selected: true,
          },
        },
      ],
    })

    expect(identifier.textContent).toBe('alice@example.test')
    expect(container.textContent).toContain(
      'Public AT Protocol identifier: did:plc:alice. This account has no handle yet, so its DID is shown instead.',
    )
    expect(container.textContent).not.toContain('@did:plc:alice')
  })

  it('enriches preview consent identity copy', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker-with-random')
    const { container, identifier } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(
      document,
      { __sessions: selectedAliceSession() },
      { pathname: '/preview/consent', search: '' },
    )

    expect(identifier.textContent).toBe('alice.test')
    expect(container.textContent).toContain(ALICE_ASSOCIATED_TOOLTIP)
  })

  it('enriches preview chooser consent state in picker-with-random mode', () => {
    const document = new FakeDocument()
    const { sidebar, mainCard } = createPreviewChooserConsentIdentities(
      document,
      'picker-with-random',
    )

    runPreviewChooserConsentEnrichment(document, 'picker-with-random')

    expect(sidebar.identifier.textContent).toBe('alice.test')
    expect(mainCard.identifier.textContent).toBe('alice.test')
    expectConsentTooltipTexts(document, [
      ALICE_ASSOCIATED_TOOLTIP,
      ALICE_ASSOCIATED_TOOLTIP,
    ])
  })

  it('uses email as the visible preview chooser consent identity in random mode', () => {
    const document = new FakeDocument()
    const { sidebar, mainCard } = createPreviewChooserConsentIdentities(
      document,
      'random',
    )

    runPreviewChooserConsentEnrichment(document, 'random')

    expect(sidebar.identifier.textContent).toBe('alice@example.test')
    expect(mainCard.identifier.textContent).toBe('alice@example.test')
    expectConsentTooltipTexts(document, [
      ALICE_PUBLIC_HANDLE_TOOLTIP,
      ALICE_PUBLIC_HANDLE_TOOLTIP,
    ])
  })

  it('uses email as the visible preview consent identity in random mode', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'random')
    const { container, identifier } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(
      document,
      { __sessions: selectedAliceSession() },
      { pathname: '/preview/consent', search: '' },
    )

    expect(identifier.textContent).toBe('alice@example.test')
    expect(container.textContent).toContain(ALICE_PUBLIC_HANDLE_TOOLTIP)
  })

  it('leaves generic and legal consent paragraphs untouched', () => {
    const document = new FakeDocument()
    appendHandleModeMeta(document, 'picker')
    const legal = new FakeElement('p')
    appendText(
      legal,
      'By clicking Authorize, you confirm that alice.test is your account.',
    )
    document.root.appendChild(legal)
    const unrelated = createConsentIdentity(
      document,
      'Grant access to your ',
      'bob.test',
      ' account',
    )

    runChooserEnrichmentScript(document, { __sessions: selectedAliceSession() })

    expect(document.root.textContent).not.toContain(ASSOCIATED_TOOLTIP_PREFIX)
    expect(unrelated.identifier.textContent).toBe('bob.test')
  })

  it('leaves arbitrary bold selected-account legal copy untouched', () => {
    expectArbitraryConsentProseUntouched({
      prefix: 'By clicking Authorize, ',
      identifierText: 'alice.test',
      suffix: ' confirms access.',
      expectedText: 'By clicking Authorize, alice.test confirms access.',
    })
  })

  it('leaves arbitrary strong selected-account technical prose untouched', () => {
    expectArbitraryConsentProseUntouched({
      prefix: 'Technical details for ',
      identifierText: 'alice.test',
      suffix: ' may include OAuth scopes.',
      tagName: 'strong',
      expectedText:
        'Technical details for alice.test may include OAuth scopes.',
    })
  })

  it('opens the tooltip on hover/focus and toggles it on click/tap', () => {
    const document = new FakeDocument()
    const { container } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document, { __sessions: selectedAliceSession() })

    const { icon, tooltip } = findConsentIdentityTooltip(container)

    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
    icon.dispatchEvent('mouseenter')
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')
    icon.dispatchEvent('mouseleave')
    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
    icon.dispatchEvent('focus')
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')
    icon.dispatchEvent('blur')
    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
    const click = icon.dispatchEvent('click')
    expect(click.defaultPrevented).toBe(true)
    expect(click.propagationStopped).toBe(true)
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')
    icon.dispatchEvent('mouseleave')
    expect(tooltip.hidden).toBe(false)
    icon.dispatchEvent('blur')
    expect(tooltip.hidden).toBe(false)
    icon.dispatchEvent('click')
    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
  })

  it('dismisses the consent tooltip on Escape, including when pinned', () => {
    const document = new FakeDocument()
    const { container } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document, { __sessions: selectedAliceSession() })

    const { icon, tooltip } = findConsentIdentityTooltip(container)

    // Pinned is the case that matters: hide() bails out early while
    // pinned, so before the Escape handler a keyboard user had no way
    // to dismiss it without moving focus (WCAG 1.4.13 Dismissible).
    icon.dispatchEvent('click')
    expect(tooltip.hidden).toBe(false)

    const escape = icon.dispatchEvent('keyup', { key: 'Escape' })
    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
    expect(escape.propagationStopped).toBe(true)

    // Unpinned hover/focus content is dismissible the same way.
    icon.dispatchEvent('focus')
    expect(tooltip.hidden).toBe(false)
    icon.dispatchEvent('keyup', { key: 'Escape' })
    expect(tooltip.hidden).toBe(true)

    // Other keys leave it alone, and Escape on an already-hidden tooltip
    // does not claim the event from the surrounding page.
    icon.dispatchEvent('focus')
    icon.dispatchEvent('keyup', { key: 'a' })
    expect(tooltip.hidden).toBe(false)
    icon.dispatchEvent('keyup', { key: 'Escape' })
    const escapeWhenHidden = icon.dispatchEvent('keyup', { key: 'Escape' })
    expect(escapeWhenHidden.propagationStopped).toBe(false)
  })

  it('keeps the tooltip pinned open when touch focus fires before click', () => {
    const document = new FakeDocument()
    const { container } = createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(document, { __sessions: selectedAliceSession() })

    const { icon, tooltip } = findConsentIdentityTooltip(container)

    icon.dispatchEvent('focus')
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')

    icon.dispatchEvent('click')
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')

    icon.dispatchEvent('blur')
    expect(tooltip.hidden).toBe(false)
    expect(icon.getAttribute('aria-expanded')).toBe('true')

    icon.dispatchEvent('click')
    expect(tooltip.hidden).toBe(true)
    expect(icon.getAttribute('aria-expanded')).toBe('false')
  })

  it('does not apply consent tooltip behavior on account pages', () => {
    const document = new FakeDocument()
    createConsentIdentity(
      document,
      'Grant access to your ',
      'alice.test',
      ' account',
    )

    runChooserEnrichmentScript(
      document,
      { __sessions: selectedAliceSession() },
      { pathname: '/account', search: '' },
    )

    expect(document.root.textContent).not.toContain(ASSOCIATED_TOOLTIP_PREFIX)
  })
})

describe('sha256Base64', () => {
  it('produces a stable SHA256 base64 hash', () => {
    // Known value for the empty string.
    expect(sha256Base64('')).toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
    )
  })

  it('returns a different hash for different inputs', () => {
    expect(sha256Base64('foo')).not.toBe(sha256Base64('bar'))
  })
})

describe('appendScriptHashToCsp (HYPER-268)', () => {
  const hash = 'abc123=='

  it('appends the hash to an existing script-src directive', () => {
    const csp =
      "default-src 'none'; script-src 'self' 'sha256-xyz='; style-src 'self'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe(
      "default-src 'none'; script-src 'self' 'sha256-xyz=' 'sha256-abc123=='; style-src 'self'",
    )
  })

  it('leaves other directives untouched', () => {
    const csp = "default-src 'none'; script-src 'self'; style-src 'self'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toContain("default-src 'none'")
    expect(result).toContain("style-src 'self'")
  })

  it('adds a fresh script-src clause when none exists', () => {
    const csp = "default-src 'none'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe("default-src 'none'; script-src 'sha256-abc123=='")
  })

  it('handles a CSP that already ends with a semicolon', () => {
    const csp = "default-src 'none';"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe("default-src 'none'; script-src 'sha256-abc123=='")
  })

  it('is idempotent on the no-script-src branch when called twice', () => {
    // First call adds a script-src, second call should append to it
    // rather than add another fresh clause.
    const csp = "default-src 'none'"
    const once = appendScriptHashToCsp(csp, hash)
    const twice = appendScriptHashToCsp(once, 'def456==')
    expect(twice).toBe(
      "default-src 'none'; script-src 'sha256-abc123==' 'sha256-def456=='",
    )
  })
})

describe('isChooserRequest (HYPER-268)', () => {
  it('matches GET /account', () => {
    expect(isChooserRequest({ method: 'GET', path: '/account' })).toBe(true)
  })

  it('matches GET /account/foo', () => {
    expect(isChooserRequest({ method: 'GET', path: '/account/foo' })).toBe(true)
  })

  it('matches GET /account/deep/path', () => {
    expect(
      isChooserRequest({ method: 'GET', path: '/account/deep/path' }),
    ).toBe(true)
  })

  it('rejects non-GET methods', () => {
    expect(isChooserRequest({ method: 'POST', path: '/account' })).toBe(false)
    expect(isChooserRequest({ method: 'PUT', path: '/account' })).toBe(false)
  })

  it('matches GET /oauth/authorize — upstream renders the chooser inline there', () => {
    expect(isChooserRequest({ method: 'GET', path: '/oauth/authorize' })).toBe(
      true,
    )
  })

  it('rejects unrelated paths', () => {
    expect(isChooserRequest({ method: 'GET', path: '/' })).toBe(false)
    expect(
      isChooserRequest({ method: 'GET', path: '/accounts' }), // plural
    ).toBe(false)
    expect(
      isChooserRequest({ method: 'GET', path: '/oauth/authorize/accept' }),
    ).toBe(false)
    expect(isChooserRequest({ method: 'POST', path: '/oauth/authorize' })).toBe(
      false,
    )
  })
})

describe('injectScriptIntoHead (HYPER-268)', () => {
  const tag = '<script>window.__foo=1</script>'

  it('inserts the script tag immediately after <head>', () => {
    const html =
      '<!DOCTYPE html><html><head><title>X</title></head><body></body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(true)
    expect(result.body).toBe(
      '<!DOCTYPE html><html><head><script>window.__foo=1</script><title>X</title></head><body></body></html>',
    )
  })

  it('returns injected=false when no <head> is present', () => {
    const html = '<html><body>no head here</body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(false)
    expect(result.body).toBe(html)
  })

  it('only rewrites the first <head> occurrence', () => {
    const html =
      '<html><head><title>A</title></head><body>text mentioning <head> literally</body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(true)
    // The first <head> gets the script; the literal string in the body stays.
    const firstHeadIdx = result.body.indexOf('<head>')
    const secondHeadIdx = result.body.indexOf('<head>', firstHeadIdx + 6)
    expect(secondHeadIdx).toBeGreaterThan(0)
    // The script is only inserted once.
    expect(result.body.split(tag).length - 1).toBe(1)
  })
})

// Fake response object used across every middleware describe below.
// Records every header / body operation so tests can assert on what
// the middleware did.
function makeRes({ headersSent = false }: { headersSent?: boolean } = {}) {
  const calls = {
    setHeader: [] as Array<[string, unknown]>,
    removedHeaders: [] as string[],
    end: [] as unknown[][],
  }
  const res = {
    headersSent,
    setHeader: vi.fn((name: string, value: unknown) => {
      calls.setHeader.push([name, value])
    }),
    removeHeader: vi.fn((name: string) => {
      if (res.headersSent) {
        // Mirror Node's real behaviour: removeHeader() throws once
        // the response has been flushed. Tests rely on this shape so
        // the middleware's headersSent guard is exercised.
        throw new Error(
          'Cannot remove headers after they are sent to the client',
        )
      }
      calls.removedHeaders.push(name)
    }),
    end: vi.fn((...args: unknown[]) => {
      calls.end.push(args)
    }),
  }
  return { res, calls }
}

// Drive the middleware against a chooser request and return the
// HTML body that upstream would have received (i.e. what was passed
// to the wrapped res.end). Collapses the boilerplate of
// `createChooserEnrichmentMiddleware + makeRes + await mw + res.end +
// read calls.end[0][0]` that otherwise repeats across every
// meta-tag / rewrite test.
async function captureWrittenHtml(
  opts: Parameters<typeof createChooserEnrichmentMiddleware>[0],
  query: Record<string, string> = {},
  body = '<html><head></head></html>',
): Promise<string> {
  const mw = createChooserEnrichmentMiddleware(opts)
  const { res, calls } = makeRes()
  await mw({ method: 'GET', path: '/account', query }, res, () => {})
  res.end(body)
  return calls.end[0][0] as string
}

describe('createChooserEnrichmentMiddleware (HYPER-268)', () => {
  it('passes non-chooser requests through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    const next = vi.fn()
    await mw({ method: 'GET', path: '/oauth/token' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    // setHeader should not be wrapped — calling it should record the
    // raw call without any rewriting.
    res.setHeader('Content-Security-Policy', "default-src 'none'")
    expect(calls.setHeader[0]).toEqual([
      'Content-Security-Policy',
      "default-src 'none'",
    ])
  })

  it('passes non-GET requests through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res } = makeRes()
    const next = vi.fn()
    await mw({ method: 'POST', path: '/account' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('appends the script hash to CSP script-src on chooser requests', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    expect(calls.setHeader[0][0]).toBe('Content-Security-Policy')
    const newCsp = calls.setHeader[0][1] as string
    expect(newCsp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+='/)
  })

  it('leaves non-CSP headers untouched on chooser requests', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader('Content-Type', 'text/html')
    expect(calls.setHeader[0]).toEqual(['Content-Type', 'text/html'])
  })

  it('injects the enrichment script into the <head> of an HTML body', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head><title>X</title></head><body></body></html>')
    const written = calls.end[0][0] as string
    // Head rewrite must start with the handle-mode meta (so the script
    // can read it synchronously on DOMContentLoaded), followed by the
    // enrichment <script>. The meta is always present — handleMode
    // resolves to `picker-with-random` when no query / metadata
    // overrides it.
    expect(written).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
  })

  it('strips Content-Length / ETag after rewriting the body', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.removedHeaders).toContain('Content-Length')
    expect(calls.removedHeaders).toContain('ETag')
  })

  it('does not strip Content-Length when no <head> is present', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('not html, no head here')
    expect(calls.removedHeaders).not.toContain('Content-Length')
    expect(calls.end[0][0]).toBe('not html, no head here')
  })

  it('rewrites a Buffer body that contains <head>', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end(Buffer.from('<html><head></head></html>'))
    const written = calls.end[0][0] as string
    expect(typeof written).toBe('string')
    expect(written).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
    expect(calls.removedHeaders).toContain('Content-Length')
  })

  it('passes Buffer bodies without <head> through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    const buf = Buffer.from('<not html>')
    res.end(buf)
    // Original buffer is preserved (the wrapped end is called with
    // the original chunk reference, untouched).
    expect(calls.end[0][0]).toBe(buf)
    expect(calls.removedHeaders).not.toContain('Content-Length')
  })

  it('matches /account/foo and /account subpaths', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account/foo' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.end[0][0]).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
  })

  it('reuses the same script (and hash) across instances', async () => {
    // Since the script is deterministic, two middleware instances
    // should produce identical script tags and identical CSP hashes —
    // verifies the factory doesn't leak per-call state.
    const mw1 = createChooserEnrichmentMiddleware()
    const mw2 = createChooserEnrichmentMiddleware()
    const r1 = makeRes()
    const r2 = makeRes()
    await mw1({ method: 'GET', path: '/account' }, r1.res, () => {})
    await mw2({ method: 'GET', path: '/account' }, r2.res, () => {})
    r1.res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    r2.res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    expect(r1.calls.setHeader[0][1]).toEqual(r2.calls.setHeader[0][1])
  })

  // ─── Regression: ERR_HTTP_HEADERS_SENT crash ─────────────────────────
  //
  // @atproto/oauth-provider's account-chooser route flushes its headers
  // before calling res.end(). Before this guard, our wrapped end() called
  // removeHeader('Content-Length') afterwards, which throws
  // ERR_HTTP_HEADERS_SENT at Node's HTTP layer. The throw escapes the
  // Express error pipeline (it's raised from a method replacement on
  // `res`, not from middleware body) and lands as an uncaught exception,
  // crashing pds-core. See the comment in chooser-enrichment.ts end()
  // wrapper for details.
  it('does not throw when upstream flushes headers before end()', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res } = makeRes({ headersSent: true })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    expect(() => {
      res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    }).not.toThrow()
  })

  it('skips Content-Length rewrite once headers have been flushed', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes({ headersSent: true })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    expect(calls.removedHeaders).toEqual([])
    expect(calls.end.length).toBe(1)
  })

  it('still rewrites Content-Length when headers have not been flushed', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes({ headersSent: false })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    expect(calls.removedHeaders).toEqual(['Content-Length', 'ETag'])
  })
})

describe('buildChooserEnrichmentScript handle-mode hiding (HYPER-268 Layer 4)', () => {
  it('reads the epds-handle-mode meta tag at runtime', () => {
    const script = buildChooserEnrichmentScript()
    expect(script).toContain('querySelector(\'meta[name="epds-handle-mode"]\')')
  })

  it("hides the handle span and adds an accessible description when mode is 'random'", () => {
    const script = buildChooserEnrichmentScript()
    // Hiding strategy: display:none on the handle element plus an
    // aria-describedby target carrying the original handle text.
    expect(script).toContain(
      "hideHandle = handleMode === 'random' && isChooserLikePage()",
    )
    expect(script).toContain("m.el.style.display = 'none'")
    expect(script).toContain("appendAriaReference(row, 'aria-describedby'")
  })

  it('leaves the handle visible for picker / picker-with-random', () => {
    // The hideHandle branch is the only path that manipulates the
    // handle element; non-random modes fall through untouched.
    const script = buildChooserEnrichmentScript()
    expect(script).toMatch(/if \(hideHandle\)/)
  })
})

describe('injectHandleModeMeta (HYPER-268 Layer 4)', () => {
  it('inserts a meta tag carrying the handle mode into <head>', () => {
    const html =
      '<!DOCTYPE html><html><head><title>X</title></head><body></body></html>'
    const result = injectHandleModeMeta(html, 'random')
    expect(result.injected).toBe(true)
    expect(result.body).toContain(
      '<meta name="epds-handle-mode" content="random">',
    )
  })

  it('returns injected=false when no <head> is present', () => {
    const html = '<html><body>no head</body></html>'
    const result = injectHandleModeMeta(html, 'picker-with-random')
    expect(result.injected).toBe(false)
    expect(result.body).toBe(html)
  })
})

describe('createChooserEnrichmentMiddleware handle-mode meta (HYPER-268 Layer 4)', () => {
  it('falls back to picker-with-random when no query / metadata provides a mode', async () => {
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
    })
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('honours the epds_handle_mode query override', async () => {
    const written = await captureWrittenHtml(
      { resolveClientMetadata: () => Promise.resolve({}) },
      { epds_handle_mode: 'random' },
    )
    expect(written).toContain('<meta name="epds-handle-mode" content="random">')
  })

  it('falls through to client metadata when query has no override', async () => {
    // The middleware awaits the metadata resolver before calling
    // next(), so the resolved value is always incorporated into the
    // meta tag — no races with upstream's synchronous res.end.
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () =>
          Promise.resolve({ epds_handle_mode: 'random' as const }),
      },
      { client_id: 'https://demo.example/client' },
    )
    expect(written).toContain('<meta name="epds-handle-mode" content="random">')
  })

  it('resolves client metadata handle mode from request_uri when client_id is absent', async () => {
    const resolveClientIdFromRequestUri = vi
      .fn()
      .mockResolvedValue('https://demo.example/client')
    const resolveClientMetadata = vi
      .fn()
      .mockResolvedValue({ epds_handle_mode: 'random' as const })

    const written = await captureWrittenHtml(
      {
        resolveClientMetadata,
        resolveClientIdFromRequestUri,
      },
      { request_uri: 'urn:ietf:params:oauth:request_uri:req-123' },
    )

    expect(resolveClientIdFromRequestUri).toHaveBeenCalledWith(
      'urn:ietf:params:oauth:request_uri:req-123',
    )
    expect(resolveClientMetadata).toHaveBeenCalledWith(
      'https://demo.example/client',
    )
    expect(written).toContain('<meta name="epds-handle-mode" content="random">')
  })

  it('keeps explicit query handle mode ahead of request_uri metadata', async () => {
    const resolveClientIdFromRequestUri = vi
      .fn()
      .mockResolvedValue('https://demo.example/client')
    const resolveClientMetadata = vi
      .fn()
      .mockResolvedValue({ epds_handle_mode: 'random' as const })

    const written = await captureWrittenHtml(
      {
        resolveClientMetadata,
        resolveClientIdFromRequestUri,
      },
      {
        epds_handle_mode: 'picker',
        request_uri: 'urn:ietf:params:oauth:request_uri:req-123',
      },
    )

    expect(resolveClientIdFromRequestUri).not.toHaveBeenCalled()
    expect(resolveClientMetadata).not.toHaveBeenCalled()
    expect(written).toContain('<meta name="epds-handle-mode" content="picker">')
  })

  it('degrades silently when request_uri client-id resolution rejects', async () => {
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: vi.fn(),
        resolveClientIdFromRequestUri: () =>
          Promise.reject(new Error('request expired')),
      },
      { request_uri: 'urn:ietf:params:oauth:request_uri:req-123' },
    )

    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('degrades silently when request_uri metadata lookup rejects', async () => {
    const resolveClientMetadata = vi
      .fn()
      .mockRejectedValue(new Error('metadata unavailable'))

    const written = await captureWrittenHtml(
      {
        resolveClientMetadata,
        resolveClientIdFromRequestUri: () =>
          Promise.resolve('https://demo.example/client'),
      },
      { request_uri: 'urn:ietf:params:oauth:request_uri:req-123' },
    )

    expect(resolveClientMetadata).toHaveBeenCalledWith(
      'https://demo.example/client',
    )
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('ignores invalid handle modes from metadata (fall through to fallback)', async () => {
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () =>
          // Value shape is intentional: an invalid string should be
          // ignored by the resolver, not propagated into the meta tag.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- deliberate bad value
          Promise.resolve({ epds_handle_mode: 'garbage' as any }),
      },
      { client_id: 'https://demo.example/client' },
    )
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('ignores invalid request_uri metadata handle modes through the shared resolver', async () => {
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- deliberate bad value
          Promise.resolve({ epds_handle_mode: 'garbage' as any }),
        resolveClientIdFromRequestUri: () =>
          Promise.resolve('https://demo.example/client'),
      },
      { request_uri: 'urn:ietf:params:oauth:request_uri:req-123' },
    )

    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('logs and falls back when the metadata resolver rejects', async () => {
    const debug = vi.fn()

    const written = await captureWrittenHtml(
      {
        logger: { debug },
        resolveClientMetadata: () => Promise.reject(new Error('network error')),
      },
      { client_id: 'https://demo.example/client' },
    )
    // Falls back to the default — no network means no upgrade.
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
    expect(debug).toHaveBeenCalledWith(
      expect.objectContaining({
        err: expect.any(Error),
        queryMode: undefined,
        // This flow carried client_id, not request_uri.
        hasRequestUri: false,
      }),
      'chooser-enrichment: failed to resolve handle mode from OAuth request context',
    )
  })

  // request_uri is a short-lived bearer reference to the PAR entry, so a
  // log line carrying its value is replayable by anyone reading the logs.
  it('logs request_uri presence but never its value', async () => {
    const requestUri = 'urn:ietf:params:oauth:request_uri:secret-par-handle'
    const debug = vi.fn()
    await captureWrittenHtml(
      {
        logger: { debug },
        resolveClientMetadata: () => Promise.resolve({}),
        resolveClientIdFromRequestUri: () =>
          Promise.reject(new Error('network error')),
      },
      { request_uri: requestUri },
    )
    expect(debug).toHaveBeenCalledWith(
      expect.objectContaining({ hasRequestUri: true }),
      'chooser-enrichment: failed to resolve handle mode from OAuth request context',
    )
    expect(JSON.stringify(debug.mock.calls)).not.toContain(requestUri)
  })
})

describe('buildChooserEnrichmentScript sign-up hide + another-account rebind', () => {
  it('reads the epds-auth-origin meta tag at runtime', () => {
    const script = buildChooserEnrichmentScript()
    expect(script).toContain('querySelector(\'meta[name="epds-auth-origin"]\')')
  })

  it('hides upstream\'s "Sign up" button and marks it to stay idempotent', () => {
    const script = buildChooserEnrichmentScript()
    // Matches by trimmed text content — idempotent via dataset.epdsHidden
    // so the MutationObserver doesn't re-hide on every tick.
    expect(script).toContain("text === 'Sign up'")
    expect(script).toContain("el.style.display = 'none'")
    expect(script).toContain("el.setAttribute('aria-hidden', 'true'")
    expect(script).toContain("el.dataset.epdsHidden = '1'")
  })

  it('rebinds the "Another account" button via capture-phase listener', () => {
    const script = buildChooserEnrichmentScript()
    // Capture-phase is essential — React's delegated root-level click
    // listener fires in bubble phase, so a bubble listener on the button
    // would run AFTER React swaps to upstream's stock sign-in component.
    expect(script).toContain(
      '\'[role="button"][aria-label="Login to account that is not listed"]\'',
    )
    expect(script).toContain('e.preventDefault()')
    expect(script).toContain('e.stopImmediatePropagation()')
    expect(script).toContain('window.location.href')
    // The `true` third arg to addEventListener switches to capture phase.
    expect(script).toMatch(/addEventListener\([\s\S]*?true,?\s*\);/)
    expect(script).toContain("btn.dataset.epdsRebound = '1'")
  })

  it('forces prompt=login on the Another-account redirect URL', () => {
    const script = buildChooserEnrichmentScript()
    // OIDC's force-reauth signal; auth-service's shouldReuseSession
    // honours it and falls through to the email form instead of
    // redirecting back to pds-core's chooser.
    expect(script).toContain("params.set('prompt', 'login')")
  })
})

describe('createChooserEnrichmentMiddleware auth-origin meta (Another-account rebind)', () => {
  it('injects the auth-origin meta tag when authOrigin is provided', async () => {
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example',
    })
    expect(written).toContain(
      '<meta name="epds-auth-origin" content="https://auth.example">',
    )
  })

  it('injects an empty auth-origin meta tag when authOrigin is omitted', async () => {
    // Empty value signals the script to skip the rebind — fails-open to
    // upstream's default behaviour rather than throwing on a missing meta.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
    })
    expect(written).toContain('<meta name="epds-auth-origin" content="">')
  })

  it('HTML-escapes authOrigin so a misconfigured value cannot break attribute quoting', async () => {
    // authOrigin is operator-configured, not user-controlled, but a
    // malformed value with a stray `"` or `<` would otherwise escape the
    // attribute and break the injected head. Cheap defense-in-depth.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example/"><script>alert(1)</script>',
    })
    expect(written).toContain(
      '<meta name="epds-auth-origin" content="https://auth.example/&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">',
    )
    // The raw attacker payload must not appear unescaped.
    expect(written).not.toContain('"><script>alert(1)</script>')
  })

  it('emits both meta tags before the script tag in head', async () => {
    // Order matters for the script's synchronous read on DOMContentLoaded.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example',
    })
    const handleModeIdx = written.indexOf('epds-handle-mode')
    const authOriginIdx = written.indexOf('epds-auth-origin')
    const scriptIdx = written.indexOf('<script>')
    expect(handleModeIdx).toBeGreaterThan(-1)
    expect(authOriginIdx).toBeGreaterThan(handleModeIdx)
    expect(scriptIdx).toBeGreaterThan(authOriginIdx)
  })
})
