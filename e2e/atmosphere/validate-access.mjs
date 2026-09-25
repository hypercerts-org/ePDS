import { readFile } from 'node:fs/promises'

const [accessPath, project] = process.argv.slice(2)
if (!accessPath || !project) {
  throw new Error('usage: validate-access.mjs <access.json> <project>')
}

const access = JSON.parse(await readFile(accessPath, 'utf8'))
const expectedEndpoints = [
  ['application', 'epds.atmosbox.test', 'exact'],
  ['application', 'auth.epds.atmosbox.test', 'exact'],
  ['application', '*.epds.atmosbox.test', 'wildcard'],
  ['application', 'authority.atmosbox.test', 'exact'],
  ['application', '*.authority.atmosbox.test', 'wildcard'],
]

if (
  access.schemaVersion !== 1 ||
  access.project !== project ||
  access.network?.internal !== true ||
  access.observations?.configuration !== 'current' ||
  access.trust?.certificateExists !== true
) {
  throw new Error(
    'Atmosphere access projection did not describe a current private sandbox',
  )
}

for (const [serviceType, hostname, kind] of expectedEndpoints) {
  if (
    !access.endpoints?.some(
      (endpoint) =>
        endpoint.serviceType === serviceType &&
        endpoint.hostname === hostname &&
        endpoint.kind === kind,
    )
  ) {
    throw new Error(`Atmosphere access projection omitted ${hostname}`)
  }
}

console.log(`Validated private access projection for ${project}.`)
