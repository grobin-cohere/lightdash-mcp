# Configuration

## Requirements

- Python 3.15 or later and [uv](https://docs.astral.sh/uv/).
- Redis.
- A Lightdash instance with its OAuth server. It is part of open-source Lightdash; tested on 3.93.6.

## Register an OAuth client with Lightdash

The server signs users in through one OAuth client registered with Lightdash. Its redirect URI is `<PUBLIC_URL>/oauth/lightdash/callback`, such as `http://localhost:8000/oauth/lightdash/callback`. Change it whenever `PUBLIC_URL` changes.

### In Lightdash

An organization admin registers it in Lightdash:

1. Open **Settings → OAuth applications** (`<LIGHTDASH_URL>/generalSettings/oauthClients`).
2. Click **Register new OAuth application**.
3. Fill in:
   - **Application name**: `lightdash-mcp`, or any name. Users see it when they sign in.
   - **Redirect URI**: `<PUBLIC_URL>/oauth/lightdash/callback`
4. Click **Register application**.
5. Copy the **Client ID** into `LIGHTDASH_CLIENT_ID` and the **Client secret** into `LIGHTDASH_CLIENT_SECRET`. The secret is shown only once.

The client belongs to the organization: only its members can sign in with it. To change the redirect URI later, edit the application in the same list.

### Through the API

Lightdash registration is also open to anyone, without signing in:

```bash
curl -X POST "$LIGHTDASH_URL/api/v1/oauth/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"lightdash-mcp","redirect_uris":["<PUBLIC_URL>/oauth/lightdash/callback"],"scope":"read write"}'
```

Keep the `client_id` and `client_secret` it returns. Lightdash accepts `http://localhost` redirect URIs.

## Environment variables

Copy `.env.example` to `.env` and fill it in.

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `LIGHTDASH_URL` | No | `http://localhost:8080` | The Lightdash instance, an `http` or `https` address |
| `LIGHTDASH_CLIENT_ID` | Yes | | The OAuth client from the step above |
| `LIGHTDASH_CLIENT_SECRET` | Yes | | Its secret |
| `FERNET_KEY` | Yes | | Encrypts everything stored in Redis |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Where sign-ins, clients and tokens are kept. With a password: `redis://:<password>@127.0.0.1:6380/0`. See [Redis](#redis) |
| `HOST` | No | `127.0.0.1` (`0.0.0.0` in the Docker image) | Address the server listens on. See [Docker](#docker) |
| `PORT` | No | `8000` | Port the server listens on |
| `PUBLIC_URL` | No | `http://localhost:<PORT>` | The address clients reach this server at, as in [Behind a proxy or a tunnel](#behind-a-proxy-or-a-tunnel). It is the OAuth issuer, and its host is accepted on incoming requests. It must be `https`, unless its host is `localhost`, `127.0.0.1` or `[::1]`, and at the root of its host |
| `ACCESS_TOKEN_TTL` | No | `3600` | Seconds an access token issued to MCP clients lasts, from 60 to 1209600 (14 days). Raise it for clients that never refresh their token, such as Dex's OAuth connector: with the default they get 401 an hour after signing in |
| `REDIRECT_HOSTS` | No | Any host | Comma-separated hosts, such as `dex.example.com,claude.ai`. When set, clients can register `https` redirect URIs on these hosts only, and the consent page doesn't warn about them. Loopback `http` and app redirect URIs are always accepted |

Generate a `FERNET_KEY`:

```bash
uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The server stops with `Missing settings: ...` when a required variable is empty, and with a message naming the variable when `LIGHTDASH_URL` or `PUBLIC_URL` isn't a valid address. It logs a warning when `PUBLIC_URL` is `https` and `HOST` isn't a loopback address: the server then also answers plain HTTP on that address, around the HTTPS proxy.

A sign-in lasts at most 90 days, then the user signs in again. A client registration expires 30 days after its last token exchange.

After an upgrade from 0.3.0 or earlier, every user signs in again once: the records in Redis now name their own key, and older ones count as missing.

## Run

```bash
uv sync
uv run lightdash-mcp
```

### Docker

The image sets `HOST=0.0.0.0`: inside a container, the server must listen on every interface for a published port to reach it.

```bash
docker run --env-file .env -p 127.0.0.1:8000:8000 ghcr.io/grobin-cohere/lightdash-mcp:0.4.2
```

Each release has its own image tag, such as `0.4.2`. `:latest` follows the newest one. Pin a version tag, so an upgrade happens only when you change it.

Inside the container, `localhost` is the container itself. Point `REDIS_URL` at an address the container can reach, such as `redis://host.docker.internal:6379/0` for Redis on the host. `LIGHTDASH_URL` must be reachable from both the container and your browser, which signs in there.

With `network_mode: host`, the container shares the machine's interfaces, so `HOST=0.0.0.0` exposes the server, over plain HTTP, on every address of the machine. Set `HOST=127.0.0.1` and let the proxy on the machine, such as Tailscale serve, reach it there:

```yaml
services:
  lightdash-mcp:
    image: ghcr.io/grobin-cohere/lightdash-mcp:0.4.2
    network_mode: host
    env_file: .env
    environment:
      HOST: 127.0.0.1
      PORT: 8001
      PUBLIC_URL: https://lightdash-mcp.example.ts.net
      REDIS_URL: redis://:<password>@127.0.0.1:6380/0
```

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8001
```

The MCP endpoint is `<PUBLIC_URL>/mcp`, over Streamable HTTP.

MCP clients keep a stream open to the server. On stop, the server gives them 3 seconds, then closes them.

`GET /health` answers 200 when the server can reach Redis, and 503 when it can't. The Docker image uses it as its health check. Lightdash being down doesn't make the server unhealthy: tools say so instead.

The server writes a JSON audit log of every tool call, with the user, the tool and its arguments, and of every sign-in event, as in [Logs](architecture.md#logs).

## Behind a proxy or a tunnel

The server listens on `HOST:PORT`. Clients, and their browsers during sign-in, reach it at `PUBLIC_URL`. Behind a proxy or a tunnel the two differ:

1. Set `PUBLIC_URL` to the address clients use, at the root of its host: `https://mcp.example.com`, not `https://example.com/mcp`.
2. Add `<PUBLIC_URL>/oauth/lightdash/callback` to the redirect URIs of the Lightdash OAuth client.
3. Restart the server. Clients connect to `<PUBLIC_URL>/mcp`.

The server accepts requests for `PUBLIC_URL`'s host, and marks its consent cookie `Secure` when `PUBLIC_URL` is HTTPS.

### Reverse proxy

- Serve it over HTTPS, and forward every path to `http://<HOST>:<PORT>`. `HOST` stays `127.0.0.1` when the proxy runs on the same machine.
- Don't buffer responses: Streamable HTTP can answer with a stream of server-sent events. With nginx, set `proxy_buffering off`.

### Tunnel

To reach a local server from Claude.ai or ChatGPT, which need a public HTTPS address:

```bash
cloudflared tunnel --url http://localhost:8000
```

Set `PUBLIC_URL` to the address the tunnel prints, such as `https://abc.trycloudflare.com`, then register its callback with Lightdash and restart, as above. A quick tunnel gets a new address on every start, so repeat these steps each time, or use a named tunnel.

## Run it publicly

- Serve it over HTTPS behind a reverse proxy, as above.
- Rate-limit `/register`, `/authorize` and `/token` at the proxy when it can. Registration is open, as MCP clients need, and each registration or sign-in request is kept in Redis: registrations 30 days after their last token exchange, sign-in requests 10 minutes. The server limits the size of each (as in [What registration accepts](architecture.md#what-registration-accepts)), but not their number. Tailscale serve can't rate-limit: there, these limits and the Redis settings below are what protect Redis.
- Set `REDIRECT_HOSTS` to the hosts of the web clients you use, such as Dex or claude.ai, so no one can register a client that sends codes to another website.
- Keep Redis private, and `FERNET_KEY` and `LIGHTDASH_CLIENT_SECRET` out of the repository.

### Redis

Anyone who can write to Redis can end sign-ins, or fill it. Values are encrypted and tied to their keys, so they can't read tokens or move a sign-in to another user, but:

- Give Redis a password (`requirepass`, or an ACL user), put it in `REDIS_URL`, and listen on `127.0.0.1` only.
- Cap its memory, so unauthenticated registrations can't fill the machine: `maxmemory 256mb` with `maxmemory-policy volatile-ttl`. Every key this server writes has a TTL, and `volatile-ttl` drops those closest to expiry first, such as sign-in requests.
- The server gives up on a Redis request after 5 seconds, and tries it once more, on a new connection, after a timeout or a connection error. When Redis stops answering, each Redis command fails after about 10 seconds instead of hanging the request, and a connection that Redis closed, such as after a restart, doesn't fail the next request.

```bash
redis-server --bind 127.0.0.1 --port 6380 --requirepass '<password>' --maxmemory 256mb --maxmemory-policy volatile-ttl
```

## Connect a client

| Client | How |
| --- | --- |
| Claude Code | `claude mcp add --transport http lightdash <PUBLIC_URL>/mcp` |
| MCP Inspector | `npx @modelcontextprotocol/inspector`, then connect to `<PUBLIC_URL>/mcp` |
| Claude.ai | Add a custom connector with `<PUBLIC_URL>/mcp`. Claude.ai needs a public HTTPS address |
| ChatGPT | In developer mode, add a connector with `<PUBLIC_URL>/mcp` and OAuth. ChatGPT needs a public HTTPS address |

On first use, the client opens a consent page on this server that names the client and shows the address it returns to, with a warning when that address is a website or an app rather than this computer. After **Continue to Lightdash**, Lightdash asks the user to sign in and approve, then the client is connected.

To connect Claude.ai or ChatGPT to a local server, run a [tunnel](#tunnel).
