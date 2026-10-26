/**
 * Behaviour of the login page's inline script when the server holds the
 * account email (handle/DID login_hint) and the page does not.
 *
 * login-page.test.ts pins the script's structure by substring. That cannot
 * tell whether the flag is actually sent, or actually cleared when the user
 * switches to their own email, so this file runs the real rendered script in
 * a `vm` sandbox against a small fake DOM and records the fetch() calls it
 * makes to better-auth. No browser or DOM library is involved; the fake
 * implements only what the script touches.
 */
import { describe, it, expect } from 'vitest'
import vm from 'node:vm'
import { renderLoginPage } from '../routes/login-page.js'

const FLOW_MASKED = 'al***@example.com'
const FLOW_EMAIL_UNAVAILABLE = 'EPDS_FLOW_EMAIL_UNAVAILABLE'
const SEND_URL = '/api/auth/email-otp/send-verification-otp'
const VERIFY_URL = '/api/auth/sign-in/email-otp'

// ---------------------------------------------------------------------------
// Fake DOM
// ---------------------------------------------------------------------------

type Listener = (event: { preventDefault: () => void }) => unknown

class FakeElement {
  value = ''
  textContent = ''
  disabled = false
  type = ''
  className = ''
  style: Record<string, string> = {}
  parentNode: FakeElement | null = null
  children: FakeElement[] = []
  private readonly classes = new Set<string>()
  private readonly listeners = new Map<string, Listener>()
  readonly classList = {
    add: (...names: string[]) => {
      names.forEach((n) => this.classes.add(n))
    },
    remove: (...names: string[]) => {
      names.forEach((n) => this.classes.delete(n))
    },
    contains: (name: string) => this.classes.has(name),
  }

  constructor(private readonly buttons: FakeElement[] = []) {}

  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, listener)
  }
  async fire(type: string): Promise<void> {
    await this.listeners.get(type)?.call(this, { preventDefault: () => {} })
  }
  appendChild(child: FakeElement): FakeElement {
    child.parentNode = this
    this.children.push(child)
    return child
  }
  replaceChildren(...nodes: FakeElement[]): void {
    this.children = nodes.flatMap((n) => n.children)
  }
  querySelector(): FakeElement | null {
    return this.buttons[0] ?? null
  }
  focus(): void {}
  select(): void {}
  setAttribute(): void {}
  removeAttribute(): void {}
  insertBefore(): void {}

  /** Visible text, as a screen reader would read the flash region. */
  get text(): string {
    return this.children.map((c) => c.textContent).join('')
  }
}

interface FetchCall {
  url: string
  body: Record<string, unknown>
}
interface FakeResponse {
  status: number
  json?: unknown
}

function mountPage(
  pageOpts: Partial<Parameters<typeof renderLoginPage>[0]>,
  respond: (call: FetchCall) => FakeResponse = () => ({ status: 200 }),
) {
  const html = renderLoginPage({
    flowId: 'flow-1',
    clientId: 'https://example.com/client-metadata.json',
    clientName: 'Example',
    branding: {},
    customCss: null,
    customFaviconUrl: null,
    customFaviconUrlDark: null,
    loginHint: '',
    initialStep: 'otp',
    otpAlreadySent: false,
    csrfToken: 'csrf',
    authBasePath: '/api/auth',
    pdsPublicUrl: 'https://pds.example.com',
    otpLength: 6,
    otpCharset: 'numeric',
    heartbeatEnabled: false,
    ...pageOpts,
  })
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  const pageScript = scripts[scripts.length - 1][1]

  const submitButton = new FakeElement()
  const elements = new Map<string, FakeElement>()
  for (const id of [
    'error-msg',
    'step-email',
    'step-otp',
    'otp-subtitle',
    'otp-email',
    'form-send-otp',
    'email',
    'form-verify-otp',
    'heading',
    'code',
    'btn-resend',
    'btn-back',
    'flash-slot-email',
    'flash-slot-otp',
  ]) {
    elements.set(id, new FakeElement([submitButton]))
  }
  const el = (id: string): FakeElement => elements.get(id)!
  if (html.includes('class="step-otp active"')) {
    el('step-otp').classList.add('active')
  }
  if (html.includes('class="step-email hidden"')) {
    el('step-email').classList.add('hidden')
  }
  const otpBoxes = Array.from({ length: 6 }, () => new FakeElement())

  const calls: FetchCall[] = []
  const location = { href: '' }
  const sandbox = {
    document: {
      getElementById: (id: string) => elements.get(id) ?? null,
      querySelector: (selector: string) =>
        selector.startsWith('#form-send-otp') ? submitButton : null,
      querySelectorAll: () => otpBoxes,
      createElement: () => new FakeElement(),
      createDocumentFragment: () => new FakeElement(),
      createTextNode: (text: string) => {
        const node = new FakeElement()
        node.textContent = text
        return node
      },
      addEventListener: () => {},
      visibilityState: 'visible',
    },
    window: { addEventListener: () => {}, location },
    fetch: (url: string, init?: { body?: string }) => {
      if (url === '/auth/ping') {
        return Promise.resolve({ json: () => Promise.resolve({ ok: true }) })
      }
      const call = {
        url,
        body: JSON.parse(init?.body ?? '{}') as FetchCall['body'],
      }
      calls.push(call)
      const res = respond(call)
      return Promise.resolve({
        ok: res.status < 400,
        json: () => Promise.resolve(res.json ?? {}),
      })
    },
    setInterval: () => 1,
    clearInterval: () => {},
    URL,
  }
  vm.runInNewContext(pageScript, sandbox)

  const settle = async (): Promise<void> => {
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r))
  }
  /** Type a full code into the boxes and submit the verify form. */
  const submitCode = async (code = '123456'): Promise<void> => {
    el('code').value = code
    await el('form-verify-otp').fire('submit')
    await settle()
  }
  /** Type an email and submit the email form. */
  const submitEmail = async (address: string): Promise<void> => {
    el('email').value = address
    await el('form-send-otp').fire('submit')
    await settle()
  }
  return { el, calls, location, settle, submitCode, submitEmail }
}

const flowMode = {
  loginHint: '',
  flowEmailMasked: FLOW_MASKED,
  initialStep: 'otp' as const,
}

const flowEmailGone = (): FakeResponse => ({
  status: 400,
  json: { code: FLOW_EMAIL_UNAVAILABLE, message: 'Enter your email address.' },
})

// ---------------------------------------------------------------------------

describe('login page script with a server-held email (handle/DID hint)', () => {
  it('auto-sends the OTP with useFlowEmail and no email', async () => {
    const page = mountPage(flowMode)
    await page.settle()

    expect(page.calls).toEqual([
      { url: SEND_URL, body: { type: 'sign-in', useFlowEmail: true } },
    ])
    expect(page.el('otp-subtitle').textContent).toContain(FLOW_MASKED)
  })

  it('does not auto-send on a duplicate load, but Resend still sends useFlowEmail', async () => {
    const page = mountPage({ ...flowMode, otpAlreadySent: true })
    await page.settle()
    expect(page.calls).toEqual([])

    await page.el('btn-resend').fire('click')
    await page.settle()

    expect(page.calls).toEqual([
      { url: SEND_URL, body: { type: 'sign-in', useFlowEmail: true } },
    ])
  })

  it('verifies the code with useFlowEmail and no email', async () => {
    const page = mountPage(flowMode)
    await page.settle()
    page.calls.length = 0

    await page.submitCode('654321')

    expect(page.calls).toEqual([
      { url: VERIFY_URL, body: { otp: '654321', useFlowEmail: true } },
    ])
    expect(page.location.href).toBe('/auth/complete')
  })

  it('"Use different email" switches to the typed address for every later call', async () => {
    const page = mountPage(flowMode)
    await page.settle()
    page.calls.length = 0

    await page.el('btn-back').fire('click')
    await page.submitEmail('Typed@Example.com')
    await page.el('btn-resend').fire('click')
    await page.settle()
    await page.submitCode()

    expect(page.calls).toEqual([
      { url: SEND_URL, body: { type: 'sign-in', email: 'typed@example.com' } },
      { url: SEND_URL, body: { type: 'sign-in', email: 'typed@example.com' } },
      { url: VERIFY_URL, body: { otp: '123456', email: 'typed@example.com' } },
    ])
  })

  it('stops sending the server-held address once the user leaves for the email step', async () => {
    const page = mountPage({ ...flowMode, otpAlreadySent: true })
    await page.settle()

    await page.el('btn-back').fire('click')
    // A stray late click (double-click race, stale handler) must not
    // silently bring the server-held address back.
    await page.el('btn-resend').fire('click')
    await page.settle()

    expect(page.calls).toHaveLength(1)
    expect(page.calls[0].body).not.toHaveProperty('useFlowEmail')
  })

  describe('when the server reports it no longer holds the email', () => {
    it('on auto-send: shows the email step with the server message and uses typed emails from then on', async () => {
      let first = true
      const page = mountPage(flowMode, ({ body }) => {
        if (first && body.useFlowEmail) {
          first = false
          return flowEmailGone()
        }
        return { status: 200 }
      })
      await page.settle()

      expect(page.el('step-email').classList.contains('hidden')).toBe(false)
      expect(page.el('step-otp').classList.contains('active')).toBe(false)
      expect(page.el('error-msg').text).toBe('Enter your email address.')

      await page.submitEmail('typed@example.com')
      expect(page.calls[page.calls.length - 1].body).toEqual({
        type: 'sign-in',
        email: 'typed@example.com',
      })
    })

    it('on verify: falls back to the email step instead of showing a code error', async () => {
      const page = mountPage(flowMode, ({ url }) =>
        url === VERIFY_URL ? flowEmailGone() : { status: 200 },
      )
      await page.settle()

      await page.submitCode()

      expect(page.el('step-email').classList.contains('hidden')).toBe(false)
      expect(page.el('step-otp').classList.contains('active')).toBe(false)
      expect(page.el('error-msg').text).toBe('Enter your email address.')
      // The verify form is usable again for the typed-email flow.
      expect(page.el('form-verify-otp').querySelector()?.disabled).toBe(false)
    })

    it('on resend: falls back to the email step', async () => {
      const page = mountPage({ ...flowMode, otpAlreadySent: true }, () =>
        flowEmailGone(),
      )
      await page.settle()

      await page.el('btn-resend').fire('click')
      await page.settle()

      expect(page.el('step-email').classList.contains('hidden')).toBe(false)
      expect(page.el('step-otp').classList.contains('active')).toBe(false)
      expect(page.el('error-msg').text).toBe('Enter your email address.')
    })
  })
})

describe('login page script with an email hint (unchanged behaviour)', () => {
  const emailHint = {
    loginHint: 'bob@example.com',
    initialStep: 'otp' as const,
  }

  it('auto-sends and verifies with the email, never useFlowEmail', async () => {
    const page = mountPage(emailHint)
    await page.settle()
    await page.submitCode()

    expect(page.calls).toEqual([
      { url: SEND_URL, body: { type: 'sign-in', email: 'bob@example.com' } },
      { url: VERIFY_URL, body: { otp: '123456', email: 'bob@example.com' } },
    ])
  })
})
