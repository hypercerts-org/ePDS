# Permission-set Lexicon fixtures

These are byte-for-byte copies of the current source documents in
[`hypercerts-lexicon`](https://github.com/hypercerts-org/hypercerts-lexicon),
checked out at commit `645177d67752834ae0e8a2876c118489b50c0a50`:

- `org/hypercerts/authWrite.json`
- `app/certified/authWrite.json`

The test authority adds only the required AT record `$type` envelope when it
places each complete document in its temporary, signed repository. It does not
alter the permission definitions or collection/action grants. The test-only
`did:web:lexicons.atmosbox.test` authority and private signing key exist only
inside the job's isolated network and are regenerated for each run.
