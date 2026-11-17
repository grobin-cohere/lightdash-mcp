# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` points here, so Claude Code reads it too.

lightdash-mcp: an MCP server for self-hosted Lightdash (data queries, access, content, deliveries). Python 3.15+, managed with uv.

## Commands

| Command | Does |
| --- | --- |
| `make dev` | Start the local Lightdash (Docker, demo data on :8080), create `.env` if missing (`dev/init_env.py`), then run the MCP server on :8000/mcp |
| `make mcp` | Run the MCP server only |
| `make test` | `uv run pytest` |
| `make lint` | `ruff check .` and `ruff format --check .` (line length 130) |
| `make check` | `dagger check`: CI's checks in containers, with their own Lightdash (needs Docker and the Dagger CLI) |
| `make logs` / `make stop` / `make clean` | Follow logs / stop / delete containers, volumes, `.lightdash/` and the `.env` created by `make dev` |

- Single test: `uv run pytest tests/unit/test_provider.py::test_name`
- Unit tests use `respx` and `fakeredis`. Integration tests (`tests/integration`) need the local Lightdash from `make dev` (or `make check`'s own), start the server on port 8765, use Redis db 15, and skip themselves when Lightdash is down. They modify the demo data: run `make clean` and `make dev` after an interrupted run.
- CI is the Dagger module in `.dagger/` (Python, Dagger 0.21, `dagger.json` at the root). `dagger check` runs `ci:lint`, `ci:unit-tests`, `ci:integration-tests` (a fresh Lightdash, MinIO and Redis as Dagger services; with `INTEGRATION_LIGHTDASH_URL` set, the tests fail instead of skipping when Lightdash doesn't start) and `ci:image` (builds the `Dockerfile`, no push), with Python and uv from the `Dockerfile`'s build image. `.github/workflows/ci.yml` runs it on each PR and push to `main`. Its Lightdash version and image digests in `.dagger/src/ci/main.py` follow the Makefile and `dev/lightdash.compose.yml`; Dependabot doesn't update them. Details in `docs/development.md`.
- `Dockerfile` builds the server image (uv build stage, slim runtime as `nobody`, `HOST=0.0.0.0`). `.github/workflows/docker.yml` pushes it to `ghcr.io/grobin-cohere/lightdash-mcp` (tags: `pyproject.toml` version and `latest`, amd64 and arm64) on each published release, or by hand from `main`, after `dagger check` passes, and never over an existing version tag. Actions and base images are pinned by SHA and digest.
- `.github/dependabot.yml` opens weekly update PRs for `uv.lock`, the GitHub Actions and the base images, a week after each release. Security updates come as soon as an alert opens.
- Not published to PyPI: the `lightdash-mcp` name there belongs to another project. The Docker image is the release.
- Run `make lint` and `make test` before a PR, and update `docs/` in the same change as the code.

## Architecture

One process built on the official MCP Python SDK (`MCPServer`, Streamable HTTP). It is both the MCP server and the OAuth authorization server its clients sign in with, and it calls the Lightdash REST API with each user's own Lightdash token. All state is in Redis, encrypted with `FERNET_KEY`. Details in `docs/architecture.md`.

- `server.py`: `create_server` wires the auth settings, the custom routes (`/health`, `/oauth/consent`, `/oauth/lightdash/callback`), the `audit` middleware (one JSON line per tool call, from `auth/audit.py`, which also logs the sign-in events), a lifespan that closes the shared HTTP client and Redis, and each tools module's `register(server, provider)`. `transport_security` adds `PUBLIC_URL`'s host to the SDK's localhost-only allowed hosts. `asgi_app` wraps the app in `BasicAuthClientId`, which copies a Basic header's client credentials into `/token` and `/revoke` bodies that lack them, reading at most 64 KiB: the SDK requires them in the body, and Dex sends them only in the header.
- `auth/provider.py`: `LightdashOAuthProvider` proxies sign-in to Lightdash OAuth. A grant (one sign-in) holds the Lightdash tokens; clients only get the server's own tokens, which point to the grant. Lightdash tokens never leave the server. Refreshes and revocations run under a Redis lock per grant, and the new tokens are written in one transaction. A token loads only while its grant points back to it. `invalid_grant` from Lightdash, a reused refresh token or the 90-day grant lifetime ends the grant; other errors keep it, and `/token` answers them, a busy grant lock and any Redis error with `invalid_request` so the client may retry (never `invalid_grant`, which drops its session). `/revoke` answers a busy lock or a Redis error with 503, `Retry-After` and no body (the `TryAgain` middleware in `server.py`, as the SDK only catches `TokenError` around the exchanges; it sits outside the SDK's Bearer middleware, which loads tokens too). Once new tokens are written nothing may fail the request: a failed lock release or client renewal is ignored. A Redis failure can still cost a sign-in when Redis applied a write but its answer was lost (`docs/architecture.md`, "What a Redis failure can still cost"). `register_client` checks redirect URIs (loopback `http`, `https`, app schemes; `REDIRECT_HOSTS` limits `https` hosts) and caps what it stores. `auth/pages.py` holds the consent and error pages.
- `auth/store.py`: encrypted Redis storage and locks. Keys are `lightdash-mcp:{client,transaction,code,access,refresh,grant,rotated}:<id>`, token keys are sha256 digests. Each ciphertext holds its own key, so a value copied under another key reads as missing, as does a record that no longer fits its model.
- `lightdash.py`: async `LightdashClient` and `LightdashError`. Every client shares the provider's `httpx.AsyncClient` (`provider.http`), which never keeps or sends cookies, so one user's cookie can't reach another's request.
- `tools/common.py`: every tool body runs inside `async with lightdash(provider) as ld:`, which gets the signed-in user's token (refreshing it if needed) and maps Lightdash errors to `ToolError` (a 401 refreshes the token, once even for concurrent calls, and retries once; a second 401 is a plain tool error). It also defines the tool annotations (`READ`, `WRITE`, `CREATE`, `DESTRUCTIVE`) and the `Uuid` / `Name` / `Slug` / `ChartRef` argument types, which must be used for anything interpolated into a Lightdash URL path. `tools/shared.py` has `every_page` (paginated lists, capped) and `conforms` (the same checks on values inside a chart or dashboard).
- `tools/{access,content,schedulers,data,code}.py`: the tools, each module with a `register` function. `code.py` reads and saves charts and dashboards through Lightdash's content-as-code API, the one `lightdash upload` uses. Destructive tools, including those that grant access, take `dry_run` (default `True`, so they only preview unless called with `dry_run=false`) and use the `DESTRUCTIVE` annotation. Every tool is listed in `docs/tools.md` with the Lightdash API it calls.

## Configuration

Settings come from `.env` (`config.py`, pydantic-settings). Required: `LIGHTDASH_CLIENT_ID`, `LIGHTDASH_CLIENT_SECRET` (an OAuth client registered with Lightdash, redirect `<PUBLIC_URL>/oauth/lightdash/callback`) and `FERNET_KEY`. See `docs/configuration.md`. Local demo login: `demo@lightdash.com` / `demo_password!`.
