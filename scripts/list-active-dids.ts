function addActiveRepo(dids: Set<string>, value: unknown): void {
  const repo = value as { did?: unknown; active?: unknown } | null
  if (
    !repo ||
    typeof repo !== 'object' ||
    typeof repo.did !== 'string' ||
    !/^did:[a-z]+:(?:[A-Za-z0-9._:-]|%[0-9A-Fa-f]{2})*[A-Za-z0-9._-]$/.test(
      repo.did,
    )
  ) {
    throw new Error('Invalid repository DID in listRepos response')
  }
  if (typeof repo.active !== 'boolean') {
    throw new Error(
      'Unknown repository activity: listRepos must provide active booleans',
    )
  }
  if (repo.active === true) dids.add(repo.did)
}

export async function listActiveDids(
  pdsUrl: string,
  fetchPage: typeof fetch = fetch,
): Promise<string[]> {
  const origin = new URL(pdsUrl)
  if (
    !['https:', 'http:'].includes(origin.protocol) ||
    origin.username ||
    origin.password ||
    origin.search ||
    origin.hash ||
    origin.pathname !== '/'
  ) {
    throw new Error(
      'Use a trusted HTTP(S) origin without credentials, path, query, or fragment',
    )
  }
  const dids = new Set<string>()
  const cursors = new Set<string>()
  let cursor: string | undefined
  while (true) {
    const url = new URL('/xrpc/com.atproto.sync.listRepos', origin)
    url.searchParams.set('limit', '1000')
    if (cursor) url.searchParams.set('cursor', cursor)
    const response = await fetchPage(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    })
    if (!response.ok)
      throw new Error(`listRepos failed: HTTP ${response.status}`)
    const page: unknown = await response.json()
    if (
      !page ||
      typeof page !== 'object' ||
      !('repos' in page) ||
      !Array.isArray(page.repos) ||
      ('cursor' in page && typeof page.cursor !== 'string')
    ) {
      throw new Error('Invalid listRepos response')
    }
    for (const repo of page.repos) addActiveRepo(dids, repo)
    if (page.repos.length === 0 || !('cursor' in page) || !page.cursor) break
    cursor = page.cursor as string
    if (cursors.has(cursor)) throw new Error('Repeated listRepos cursor')
    cursors.add(cursor)
  }
  return [...dids]
}

if (import.meta.main) {
  try {
    if (Deno.args.length === 1 && Deno.args[0] === '--help') {
      console.error(
        'Usage: deno run --allow-net=HOST scripts/list-active-dids.ts --pds-url URL\nLists active DIDs, one per stdout line. No admin password required. Use a trusted HTTP(S) origin.',
      )
    } else {
      if (Deno.args.length !== 2 || Deno.args[0] !== '--pds-url') {
        throw new Error('Usage: list-active-dids.ts --pds-url URL (or --help)')
      }
      const dids = await listActiveDids(Deno.args[1])
      if (dids.length) console.log(dids.join('\n'))
      console.error(`${dids.length} active DIDs`)
    }
  } catch (error) {
    console.error(
      error instanceof Error ? error.message : 'Failed to list active DIDs',
    )
    Deno.exitCode = 1
  }
}
