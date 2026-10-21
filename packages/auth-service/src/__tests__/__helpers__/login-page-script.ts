/**
 * Runs the login page's real inline script in a `node:vm` context against a
 * minimal stand-in DOM, so tests can click its buttons and submit its forms.
 * There is no DOM test environment in this repo, and asserting on the
 * script's source text alone would not show that a handler is wired up.
 *
 * Only the elements the sign-in handlers use are real fakes; everything else
 * the script touches (OTP boxes, steps, heartbeat UI) absorbs reads, writes
 * and calls.
 */
import * as vm from 'node:vm'
import { vi, type Mock } from 'vitest'
import type { renderLoginPage } from '../../routes/login-page.js'

export type LoginPageOptions = Parameters<typeof renderLoginPage>[0]

/**
 * renderLoginPage options for a plain email-step page with both social
 * buttons requested; tests override what they need.
 */
export const LOGIN_PAGE_OPTIONS: LoginPageOptions = {
  flowId: 'flow-1',
  clientId: 'https://app.example.com/client-metadata.json',
  clientName: 'Example',
  branding: { epds_social_providers: ['google', 'github'] },
  customCss: null,
  customFaviconUrl: null,
  customFaviconUrlDark: null,
  loginHint: '',
  initialStep: 'email',
  otpAlreadySent: false,
  csrfToken: 'csrf',
  authBasePath: '/api/auth',
  pdsPublicUrl: 'https://pds.example.com',
  otpLength: 6,
  otpCharset: 'numeric',
  heartbeatEnabled: false,
}

/** The page's main inline script (the one that owns the login flow). */
export function mainScript(html: string): string {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(
    (m) => m[1],
  )
  const main = scripts.find((s) => s.includes('var authBasePath'))
  if (!main) throw new Error('login page main script not found')
  return main
}

/**
 * A value that absorbs any property read, call or construction by returning
 * itself, so page-script initialisation that does not concern the test
 * runs without a real DOM.
 */
function absorbing(): unknown {
  const target = function () {}
  const proxy: unknown = new Proxy(target, {
    get: (_t, key) => {
      if (key === Symbol.toPrimitive) return () => ''
      if (key === 'length') return 0
      return proxy
    },
    set: () => true,
    apply: () => proxy,
    construct: () => proxy as object,
  })
  return proxy
}

type Listener = (this: FakeElement, e: unknown) => unknown

/** A stand-in for the few DOM elements the sign-in handlers drive. */
export interface FakeElement {
  disabled: boolean
  value: string
  textContent: string
  type: string
  getAttribute: (name: string) => string | null
  addEventListener: (type: string, fn: Listener) => void
  /** Run this element's click listeners; resolves when they settle. */
  click: () => Promise<unknown>
  /** Run this element's submit listeners; resolves when they settle. */
  submit: () => Promise<unknown>
  [key: string]: unknown
}

function fakeElement(
  attributes: Record<string, string> = {},
  children: Record<string, FakeElement> = {},
): FakeElement {
  const listeners: Record<string, Listener[]> = {}
  const fire = (type: string) =>
    Promise.all(
      (listeners[type] ?? []).map((fn) =>
        fn.call(el, { preventDefault: () => undefined }),
      ),
    )
  const el: FakeElement = {
    disabled: false,
    value: '',
    textContent: '',
    type: '',
    style: {},
    classList: { add: () => undefined, remove: () => undefined },
    getAttribute: (name) => attributes[name] ?? null,
    setAttribute: () => undefined,
    removeAttribute: () => undefined,
    focus: () => undefined,
    querySelector: (selector: string) => children[selector] ?? null,
    addEventListener: (type, fn) => {
      ;(listeners[type] ??= []).push(fn)
    },
    click: () => fire('click'),
    submit: () => fire('submit'),
  }
  return el
}

type FetchImpl = (url: string, init: RequestInit) => unknown

/** The page's forms and controls, keyed by what they do. */
export interface PageElements {
  emailInput: FakeElement
  sendOtpForm: FakeElement
  sendOtpButton: FakeElement
  verifyForm: FakeElement
  verifyButton: FakeElement
  code: FakeElement
  resendButton: FakeElement
  atprotoButton: FakeElement
}

/** What a test drives and observes on a page script run by runPageScript. */
export interface PageScriptHandles {
  buttons: { google: FakeButton; github: FakeButton }
  elements: PageElements
  /** `window.location.assign`. */
  assign: Mock<(url: string) => void>
  /** Every URL the page navigated to, by `assign` or by setting `href`. */
  navigations: string[]
  /** The stubbed `fetch`. */
  fetchSpy: Mock<FetchImpl>
  windowListeners: Partial<Record<string, ((e: unknown) => void)[]>>
  /** `text` is the last message shown in the flash region (`#error-msg`). */
  flash: { text: string }
}

export type FakeButton = FakeElement

/**
 * Run the main script of `html` with fake Google/GitHub buttons, fake
 * email/OTP forms and a stubbed `fetch`, and return the handles a test
 * needs to drive and observe it.
 */
export function runPageScript(
  html: string,
  fetchImpl: FetchImpl,
): PageScriptHandles {
  const buttons = {
    google: fakeElement({ 'data-social-provider': 'google' }),
    github: fakeElement({ 'data-social-provider': 'github' }),
  }
  const sendOtpButton = fakeElement()
  const verifyButton = fakeElement()
  const elements: PageElements = {
    emailInput: fakeElement(),
    sendOtpForm: fakeElement({}, { 'button[type=submit]': sendOtpButton }),
    sendOtpButton,
    verifyForm: fakeElement({}, { 'button[type=submit]': verifyButton }),
    verifyButton,
    code: fakeElement(),
    resendButton: fakeElement(),
    atprotoButton: fakeElement(),
  }
  const navigations: string[] = []
  const assign = vi.fn<(url: string) => void>((url) => {
    navigations.push(url)
  })
  const fetchSpy = vi.fn(fetchImpl)
  const windowListeners: Partial<Record<string, ((e: unknown) => void)[]>> = {}
  const flash = { text: '' }
  const errorEl = {
    classList: { add: () => undefined, remove: () => undefined },
    replaceChildren: (frag?: { children: { textContent: string }[] }) => {
      flash.text = frag ? frag.children.map((c) => c.textContent).join('') : ''
    },
  }
  const byId: Record<string, unknown> = {
    'error-msg': errorEl,
    email: elements.emailInput,
    'form-send-otp': elements.sendOtpForm,
    'form-verify-otp': elements.verifyForm,
    code: elements.code,
    'btn-resend': elements.resendButton,
    'btn-start-over': null,
  }
  const bySelector: Record<string, unknown> = {
    '.btn-atproto': elements.atprotoButton,
    '#form-send-otp button[type=submit]': sendOtpButton,
    '#form-verify-otp button[type=submit]': verifyButton,
  }
  const fakeDocument: Record<string, unknown> = {
    querySelectorAll: (selector: string) =>
      selector === '[data-social-provider]'
        ? [buttons.google, buttons.github]
        : [],
    querySelector: (selector: string) =>
      selector in bySelector ? bySelector[selector] : absorbing(),
    getElementById: (id: string) => (id in byId ? byId[id] : absorbing()),
    createDocumentFragment: () => {
      const children: unknown[] = []
      return { children, appendChild: (n: unknown) => children.push(n) }
    },
    createElement: () => fakeElement(),
    createTextNode: (text: string) => ({ textContent: text }),
  }
  const document = new Proxy(absorbing() as object, {
    get: (target, key) =>
      typeof key === 'string' && key in fakeDocument
        ? fakeDocument[key]
        : (target as Record<PropertyKey, unknown>)[key],
  })
  const location = {
    assign,
    search: '',
    get href() {
      return navigations.at(-1) ?? ''
    },
    set href(url: string) {
      navigations.push(url)
    },
  }
  const window = {
    location,
    addEventListener: (type: string, fn: (e: unknown) => void) => {
      ;(windowListeners[type] ??= []).push(fn)
    },
  }
  vm.runInNewContext(mainScript(html), {
    document,
    window,
    fetch: fetchSpy,
    setInterval: () => 0,
    clearInterval: () => undefined,
    setTimeout: () => 0,
    clearTimeout: () => undefined,
    navigator: absorbing(),
    URL,
    console,
  })
  return {
    buttons,
    elements,
    assign,
    navigations,
    fetchSpy,
    windowListeners,
    flash,
  }
}

export function jsonResponse(status: number, body: unknown) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  })
}
