# Legacy PKCE and DPoP Helpers

This reference previously contained hand-rolled PKCE and DPoP helpers. They were
removed because partial OAuth implementations risk mismatched keys, invalid
issuer or audience values, replay vulnerabilities, broken nonce handling, and
refresh races.

Use `NodeOAuthClient`, including for email-first login:

```typescript
const url = await client.authorize(epdsUrl)
url.searchParams.set('login_hint', email)
```

The SDK handles PKCE, DPoP key generation and proof signing, nonce retry, PAR,
token exchange, client assertions, and persisted OAuth state.

See [`../SKILL.md`](../SKILL.md) for maintained integration guidance.
