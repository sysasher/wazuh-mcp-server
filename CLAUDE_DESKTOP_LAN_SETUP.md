# Running Wazuh MCP Server on your LAN, connected to Claude Desktop

This guide covers your specific setup: the MCP server runs on a separate
machine on your local network (not the same computer as Claude Desktop),
using a reverse proxy with a self-signed certificate for HTTPS.

**Why HTTPS is required at all:** Claude Desktop's Custom Connectors only
accept plain HTTP for `localhost`. Since your server lives on a different
LAN machine, Claude Desktop will only connect to it over HTTPS — and the
Wazuh MCP Server itself speaks plain HTTP only (by design; TLS termination
is meant to happen in front of it). The two new files added to this repo,
`Caddyfile` and `compose.override.yml`, add that TLS-terminating reverse
proxy using [Caddy](https://caddyserver.com/), which can generate its own
locally-trusted certificate authority automatically — no public domain name
or manual OpenSSL commands needed.

---

## Part 1 — Deploy on the LAN server

Do this on the machine that will actually run the server (your NAS, home
server, etc. — copy this whole `Wazuh-MCP-Server` folder there, or `git
clone` it fresh and copy `Caddyfile` + `compose.override.yml` in).

### 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
WAZUH_HOST=https://your-wazuh-server
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

ENVIRONMENT=production
AUTH_MODE=bearer

# Generate with: openssl rand -hex 32
AUTH_SECRET_KEY=<paste generated value here>

# Bearer tokens normally expire after 24h (TOKEN_LIFETIME_HOURS). Since this
# server never leaves your LAN, bumping it to 30 days avoids re-pasting a
# token into Claude Desktop every day. Adjust to taste.
TOKEN_LIFETIME_HOURS=720
```

### 2. Point the reverse proxy at your server's address

Edit `Caddyfile` and replace `REPLACE_WITH_YOUR_LAN_IP_OR_HOSTNAME` with
this machine's actual LAN IP (e.g. `192.168.1.50`) or hostname (e.g.
`wazuh-mcp.local`) — whatever address the Claude Desktop machine will use
to reach it:

```
https://192.168.1.50 {
	tls internal
	reverse_proxy wazuh-main-server:3000
}
```

### 3. Start everything

```bash
docker compose up -d
```

This starts both `wazuh-main-server` and the new `caddy` container (Compose
automatically merges `compose.override.yml` with `compose.yml`). Caddy
listens on port 443 and proxies to the MCP server internally — no need to
open port 3000 to the LAN.

Confirm it's up:

```bash
curl -k https://192.168.1.50/health
```

(`-k` skips certificate verification for this one local check, since your
computer doesn't trust Caddy's self-signed CA yet — that's Part 2.)

### 4. Get your access token

```bash
# Get the auto-generated API key
docker compose logs wazuh-main-server | grep "API key"

# Exchange it for a bearer token (JWT) — this is what goes into Claude Desktop
curl -k -X POST https://192.168.1.50/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_the-key-from-above"}'
```

Copy the `access_token` value from the response — you'll paste it into
Claude Desktop in Part 3.

---

## Part 2 — Trust Caddy's certificate on the Claude Desktop machine

Caddy generated its own local root certificate the first time it started.
Pull it off the server and install it as a trusted root **on the Windows
machine running Claude Desktop** — otherwise Claude Desktop will reject the
connection as an untrusted certificate.

### 1. Extract the root certificate (on the server)

```bash
docker cp wazuh-mcp-caddy:/data/caddy/pki/authorities/local/root.crt ./wazuh-mcp-root-ca.crt
```

Copy `wazuh-mcp-root-ca.crt` to the Windows machine (USB drive, network
share, or however you'd normally move a file between them).

### 2. Install it as a trusted root (on the Windows machine)

Easiest: double-click `wazuh-mcp-root-ca.crt` → **Install Certificate** →
choose **Local Machine** (needs admin) → **Place all certificates in the
following store** → **Trusted Root Certification Authorities** → Finish.

Or via an elevated PowerShell:

```powershell
Import-Certificate -FilePath "wazuh-mcp-root-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

Verify by browsing to `https://192.168.1.50/health` in a browser on the
Windows machine — it should show no certificate warning.

---

## Part 3 — Connect from Claude Desktop

1. Open **Claude Desktop** → **Settings** → **Connectors**
2. Click **Add custom connector**
3. URL: `https://192.168.1.50/mcp` (use whatever address you put in the
   Caddyfile)
4. Under **Advanced settings**, paste the `access_token` (JWT) from Part 1,
   step 4, as the Bearer token
5. Click **Connect**
6. In a chat, click **Search and tools**, find the Wazuh connector, and
   enable the tools you want available

---

## Notes and gotchas

- **Firewall:** make sure the LAN server's firewall allows inbound
  connections on port 443 from your network (e.g. `ufw allow 443/tcp` on
  Debian/Ubuntu).
- **Token expiry:** with `AUTH_MODE=bearer`, the token in Claude Desktop
  will stop working after `TOKEN_LIFETIME_HOURS` and needs to be
  regenerated (repeat step 4 of Part 1) and re-pasted into the connector's
  Advanced settings.
- **Smoother long-term option — OAuth:** if re-pasting a token periodically
  gets annoying, `AUTH_MODE=oauth` with `OAUTH_ENABLE_DCR=true` lets Claude
  Desktop register itself and refresh tokens automatically, no manual
  copy-pasting. It's more moving parts to set up initially (and its
  browser-based login redirect needs to trust the same Caddy root CA), so
  this guide defaults to the simpler bearer-token flow — ask if you'd like
  the OAuth version instead.
- **Changing the LAN IP later:** if the server's IP changes (e.g. DHCP
  reassigns it), update the address in `Caddyfile`, `docker compose up -d`
  again, and update the URL in Claude Desktop's connector settings.
