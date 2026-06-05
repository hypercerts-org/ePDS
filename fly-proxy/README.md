# Failover TLS-terminating front proxy (HYPER-477)

Standalone Caddy proxy on Fly.io that terminates TLS with **our own cert** and
fans out to the PDS deployment on Railway. It sits in front of the in-stack
Caddy (`../Caddyfile`), off Railway's HTTP edge, so we hold the public cert and
run its renewal ourselves.

See [HYPER-477](https://linear.app/hypercerts/issue/HYPER-477) and the failover
plan in [HYPER-473](https://linear.app/hypercerts/issue/HYPER-473).

## Why it exists

The 2026-06-02 Railway outage served the wrong cert for our custom domain.
Terminating TLS here, with a cert we control (DNS-01 ACME via Cloudflare),
removes that client-facing failure class. Failover then becomes a scriptable
backend flip (`caddy reload` / Admin API) with **no DNS change**.

Two TLS hops, both on healthy certs:

1. **Client -> Caddy (here):** our cert, DNS-01 renewed. Clients only ever see this.
2. **Caddy -> Railway backend:** the `*.up.railway.app` platform wildcard, which
   is a *separate, healthy* cert from the broken custom-domain one. `BACKEND_SNI`
   pins it so Railway's edge serves the good wildcard.

## Cert strategy: one DNS-01 wildcard

Handles are `<random>.$PROXY_HOSTNAME` and number in the thousands to hundreds of
thousands, so a cert per handle is infeasible — Let's Encrypt allows only ~50
certs/week per registered domain. Instead the proxy holds a single **`*.$PROXY_HOSTNAME`
wildcard** (plus an apex cert), which covers every handle and the `auth.` subdomain.

Wildcards can **only** be issued via **DNS-01**: Caddy proves domain control by
writing a short-lived `_acme-challenge` **TXT** record through the Cloudflare API,
which Let's Encrypt reads, then Caddy deletes it. This is why a Cloudflare token is
required. It only writes throwaway challenge records — it never touches the
**A/AAAA routing records**, which you point at Fly once and leave alone.

Handles are single-level under the apex (confirmed in `pds-core`), so a
single-level wildcard suffices.

## Prerequisites

- `flyctl` installed and `fly auth login`.
- A Cloudflare API token scoped **Zone:DNS:Edit** for the proxy's zone.
- The Railway service's `*.up.railway.app` hostname.

## One proxy per environment

Each environment is a separate Fly app with its own cert, IP, and volume, so a
failover flip or cert problem in one never touches another. The `Dockerfile` and
`Caddyfile` are shared; per-env values live in `fly.<env>.toml`:

| Env  | Config          | Public hostname (`PROXY_HOSTNAME`) | Backend (`*.up.railway.app`)                  |
|------|-----------------|------------------------------------|-----------------------------------------------|
| test | `fly.test.toml` | `epds1.test.certified.app`         | `certified-apppds-core-test.up.railway.app`   |
| dev  | `fly.dev.toml`  | `dev.certified.app`                | `certified-apppds-core-dev.up.railway.app`    |
| prod | `fly.prod.toml` | `certified.one`                    | `certified-apppds-core-production.up.railway.app` |

Each `fly.<env>.toml` `[env]` block carries `PROXY_HOSTNAME`, the PDS backend
(`BACKEND_URL`/`BACKEND_SNI`) and the auth backend (`AUTH_BACKEND_URL`/
`AUTH_BACKEND_SNI`). The auth backend is `certified-appauth-service-<env>.up.railway.app`;
`auth.$PROXY_HOSTNAME` routes there, everything else (apex + handles) to the PDS.
Each `*_SNI` pins the healthy `*.up.railway.app` platform wildcard — see above.

## Deploy (per env)

Substitute `<env>` with `test`, `dev`, or `prod`:

```sh
fly launch --no-deploy -c fly.<env>.toml --copy-config --region ams
fly volumes create caddy_data -a epds-tls-proxy-<env> --region ams --size 1
fly secrets set CF_API_TOKEN=<cloudflare-token> -a epds-tls-proxy-<env>
fly ips allocate-v4 -a epds-tls-proxy-<env>   # dedicated v4 required for raw-TCP passthrough
fly ips allocate-v6 -a epds-tls-proxy-<env>
fly deploy -c fly.<env>.toml
```

## DNS

Per env, point that env's hostnames at its app's allocated Fly IPs in Cloudflare.
Both the **apex** and a **wildcard** record are needed (the wildcard covers all
handle subdomains and `auth.`):

- `$PROXY_HOSTNAME` — **A** -> `fly ips` v4, **AAAA** -> v6
- `*.$PROXY_HOSTNAME` — **A** -> same v4, **AAAA** -> same v6
- **DNS-only (grey cloud)** on all of them. Orange-cloud re-terminates TLS at
  Cloudflare and reintroduces the loss-of-cert-control problem.

(For a hostname like `epds1.test.certified.app` the wildcard is `*.epds1.test.certified.app`.)

## Verify

```sh
# Clients get OUR cert with the right SAN, not Railway's:
echo | openssl s_client -connect "$PROXY_HOSTNAME:443" -servername "$PROXY_HOSTNAME" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# Fan-out and firehose through the proxy:
curl -sS "https://$PROXY_HOSTNAME/xrpc/_health"
# wss://$PROXY_HOSTNAME/xrpc/com.atproto.sync.subscribeRepos
```

## Failover flip (no DNS change)

Edit the backend in `Caddyfile` (or patch upstreams via the localhost Admin API)
and reload:

```sh
fly ssh console -a epds-tls-proxy-<env> -C "caddy reload --config /etc/caddy/Caddyfile"
```
