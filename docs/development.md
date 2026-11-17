# Development

## Start

Needs Docker, git, curl and [uv](https://docs.astral.sh/uv/).

```bash
make dev
```

`make dev` sets everything up, then runs the MCP server:

1. Sparse-clones Lightdash at `LIGHTDASH_VERSION` into `.lightdash/` (git-ignored): the jaffle shop demo and its Docker files.
2. Starts the demo with the same image tag, layered with `dev/lightdash.compose.yml` (site URL, scheduler, groups, MinIO for the S3 storage Lightdash requires, and Redis) and `dev/entrypoint.sh`, which sets up the database only when it is empty and fixes upstream's reset and seed.
3. Waits for Lightdash on http://localhost:8080.
4. Creates `.env` if it is missing, with `dev/init_env.py`: registers an OAuth client with the local Lightdash and generates a Fernet key.
5. Runs the MCP server on http://localhost:8000/mcp, with `.env`.

## Make targets

| Command | Does |
| --- | --- |
| `make dev` | Set up everything, then run the MCP server |
| `make mcp` | Run the MCP server only |
| `make test` | Run the tests |
| `make lint` | Check the code with Ruff: lint and formatting |
| `make check` | Run the CI checks with Dagger: see [CI](#ci) |
| `make logs` | Follow the Lightdash logs |
| `make stop` | Stop Lightdash and Redis |
| `make clean` | Stop and delete the containers, volumes, `.lightdash/` and the `.env` created by `make dev` |

Use another Lightdash release with `make dev LIGHTDASH_VERSION=<tag>`. Run `make clean` before switching.

## The local Lightdash

The demo comes from the Lightdash repository:

- **Database:** one Postgres is both the Lightdash database and the warehouse. dbt seeds the data into the `jaffle` schema.
- **dbt project:** the jaffle shop, mounted at `/usr/app/dbt`, connected to a project named "Jaffle shop".
- **Content:** charts, dashboards, nested spaces, groups and scheduled deliveries.
- **Users:** all with the password `demo_password!`.

| User | Role |
| --- | --- |
| `demo@lightdash.com` | Organization 1 admin |
| `demo2@lightdash.com` | Organization 1 editor |
| `demo3@lightdash.com` | Organization 1 viewer |
| `another@lightdash.com` | Organization 2 admin |

- The first start seeds the data, migrates and loads the sample content. Later starts keep the database, with what was created and the registered OAuth clients. After `make clean`, the next `make dev` starts from the sample data with a new `.env`, and MCP clients sign in again.
- The image is `linux/amd64`. On Apple Silicon it runs under emulation and is slower.

## Use your own local Lightdash

`make dev` always starts the demo Lightdash and Redis. To use a Lightdash already running on your machine, skip it:

1. Register an OAuth client with your Lightdash, as in [Configuration](configuration.md), with the redirect URI `http://localhost:8000/oauth/lightdash/callback`.
2. In `.env`, set `LIGHTDASH_URL` to your Lightdash, such as `http://localhost:3000`, with the client's `LIGHTDASH_CLIENT_ID`, `LIGHTDASH_CLIENT_SECRET` and a `FERNET_KEY`.
3. Start a Redis at `REDIS_URL`, such as `docker run -d -p 6379:6379 redis:7-alpine`.
4. Run the server:

```bash
make mcp
```

- The demo stack publishes ports 8080 and 6379: running `make dev` alongside your Lightdash clashes if it uses either.
- The integration tests ignore `.env`: they target `http://localhost:8080` with the demo users, unless `INTEGRATION_LIGHTDASH_URL` is set (see [CI](#ci)). If your Lightdash is on 8080, `make test` runs them against it and changes its content. Otherwise they skip themselves.

## Tests

```bash
make test
```

| Suite | Runs against | Covers |
| --- | --- | --- |
| `tests/unit` | `respx` and `fakeredis` | Encryption at rest, records bound to their keys, refresh under the lock, refreshes of the same token coalesced into one, refresh-token reuse, grant lifetime, ended sign-ins, error mapping, revocation, separate grants, the consent page and its CSRF token, redirect URI checks, size limits, the audit log, the tools, the Lightdash client |
| `tests/integration` | The local Lightdash and Redis database 15 | The whole sign-in over HTTP, every tool, admin against viewer, refresh, revoke, PKCE, the consent cookie |

- The unit tests are in `test_auth_flow.py` (consent, callback, registration), `test_provider.py` (grants, tokens, refresh, revocation), `test_server.py` (token endpoints, audit log, Redis), `test_tools.py` and `test_code.py` (tools), and `test_smoke.py` (settings, the Lightdash client, health).
- The integration tests register their own OAuth clients, start the server on port 8765, and sign in as `demo@` (admin) and `demo3@` (viewer). They need nothing in `.env`, and they are skipped when Lightdash is down, except in CI.
- They change the local Lightdash: they create and delete spaces and schedulers, grant and revoke access, and move a chart and back. They expect the seeded demo data, so run `make clean` and `make dev` if a run was interrupted.

## CI

CI is a [Dagger](https://dagger.io) module in `.dagger/` (Python, `dagger.json` at the root). Its checks run the same way on your machine and in GitHub Actions:

| Check | Does |
| --- | --- |
| `ci:lint` | `ruff check` and `ruff format --check`, the module's code included |
| `ci:unit-tests` | `tests/unit` |
| `ci:integration-tests` | `tests/integration`, against a fresh Lightdash with the demo data, MinIO and Redis, started as Dagger services. It fails, instead of skipping, when Lightdash doesn't start |
| `ci:image` | Builds the Docker image from the `Dockerfile`, without publishing it |

Run them all with `make check`, or some with `dagger check ci:lint ci:unit-tests`. They need Docker and the [Dagger CLI](https://docs.dagger.io/0.21/getting-started/installation) at the version in `dagger.json` (`engineVersion`), nothing else: no `.lightdash/`, no `.env` and no running Lightdash. They don't touch the local Lightdash from `make dev`.

- The tests run with Python and uv from the `Dockerfile`'s build image, so they match the release.
- Lightdash is the same as `make dev`'s: `LIGHTDASH_VERSION` and the image digests at the top of `.dagger/src/ci/main.py`. Change them with the Makefile and `dev/lightdash.compose.yml`. Dependabot doesn't update them.
- `.github/workflows/ci.yml` runs `dagger check` on every pull request and push to `main`. In `.github/workflows/docker.yml`, the release runs the same checks before it builds and publishes the image.
- The integration tests take a few minutes more than the others: Lightdash seeds its demo data and migrates before it answers. The tests wait for it, up to 15 minutes.
- To point the integration tests at another Lightdash and Redis, set `INTEGRATION_LIGHTDASH_URL` and `INTEGRATION_REDIS_URL`. The Lightdash's `SITE_URL` must be the same URL. With `INTEGRATION_LIGHTDASH_URL` set, the tests wait for that Lightdash and fail when it doesn't start.
- To update Dagger, change `engineVersion` in `dagger.json` and `version` in both workflows, then run `dagger develop` and commit the changes in `.dagger/`.
