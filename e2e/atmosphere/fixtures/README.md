# Permission-set lexicon fixtures

These are byte-for-byte copies of the current source documents in
[`hypercerts-lexicon`](https://github.com/hypercerts-org/hypercerts-lexicon),
checked out at commit `645177d67752834ae0e8a2876c118489b50c0a50`:

- `org/hypercerts/authWrite.json`
- `app/certified/authWrite.json`

Atmosphere in a Box 0.7.0 snapshots these files during provisioning. Its managed
lexicon authority creates a private account, publishes each document as a
`com.atproto.lexicon.schema` record, and verifies normal DNS, DID, HTTPS, and
record resolution during `sandbox seed`.

Fixture changes require a fresh sandbox state. The ePDS harness does not alter
the documents, implement a custom authority, or fetch lexicons while the
isolated services run.
