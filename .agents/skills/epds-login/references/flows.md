# Legacy Flow Walkthrough

This reference previously documented a hand-rolled email-first OAuth flow.
Do not use it for new integrations.

Use `NodeOAuthClient` for email, hosted-form, handle, and DID login. For an
email-first flow:

```typescript
const url = await client.authorize(epdsUrl)
url.searchParams.set('login_hint', email)
```

When fresh authentication is required, also pass `prompt=login` to
`authorize()` so it enters PAR, then append it to returned URL for ePDS
auth-service session handling:

```typescript
const url = await client.authorize(epdsUrl, { prompt: 'login' })
url.searchParams.set('login_hint', email)
url.searchParams.set('prompt', 'login')
```

Email `login_hint` belongs only on the returned browser authorization URL,
never in the PAR body. `NodeOAuthClient` must retain ownership of PAR, PKCE,
DPoP, nonce retry, token exchange, and OAuth state/session storage.

See [`../SKILL.md`](../SKILL.md) for maintained flow, callback, and application
session guidance.
