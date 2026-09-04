# Flow Walkthrough

Use `NodeOAuthClient` for email, hosted-form, handle, and DID login.

For a hosted-form flow, where the client does not collect the user's email:

```typescript
const url = await client.authorize(epdsUrl)
// Redirect without adding login_hint.
```

The ePDS presents its hosted login form, where the user supplies their email.
“No email” means the client does not collect the email before redirecting; it
does not mean the account has no email.

For an email-first flow:

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
never in the PAR body.

See [`../SKILL.md`](../SKILL.md) for maintained flow and callback guidance.
