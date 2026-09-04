# PKCE and DPoP

`NodeOAuthClient` handles PKCE, DPoP, and the associated OAuth state, including
for email-first login:

```typescript
const url = await client.authorize(epdsUrl)
url.searchParams.set('login_hint', email)
```

The SDK handles PKCE, DPoP key generation and proof signing, nonce retry, PAR,
token exchange, client assertions, and persisted OAuth state.

See [`../SKILL.md`](../SKILL.md) for maintained integration guidance.
