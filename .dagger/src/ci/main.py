import re
from typing import Annotated

import dagger
from dagger import DefaultPath, Ignore, check, dag, function, object_type

# The same Lightdash as `make dev`: keep in step with LIGHTDASH_VERSION in the Makefile and the images in
# dev/lightdash.compose.yml. Images are pinned by digest: take a new one from `docker buildx imagetools inspect`.
LIGHTDASH_VERSION = "3.93.6"
LIGHTDASH = f"lightdash/lightdash:{LIGHTDASH_VERSION}@sha256:084a4527caff1a745aa0bd9af0a6a8ffd4d4beba13cb7759f7195108f34d4f57"
POSTGRES = "postgres:18@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc"
MINIO = "coollabsio/minio:RELEASE.2025-10-15T17-29-55Z@sha256:69b55a1c1c5dc285ce04db96689f5b2102317fc77a50680a1874ca6efd1c87f9"
REDIS = "redis:7-alpine@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe"
GIT = "alpine/git:2.54.1@sha256:2306e2b05ee0ef99f5d25b0779f645b24ae9f91ba187107503592fcdfe78da3a"

# Lightdash's address in the test container. Its SITE_URL must be the same, for the sign-in redirects.
LIGHTDASH_URL = "http://lightdash:8080"


@object_type
class Ci:
    """lightdash-mcp's checks: lint, unit tests, integration tests against a fresh Lightdash, and the image build."""

    source: Annotated[
        dagger.Directory,
        DefaultPath("/"),
        Ignore(
            [
                ".git",
                ".env",
                ".venv",
                ".lightdash",
                ".dagger/sdk",
                ".dagger/.venv",
                "**/__pycache__",
                ".pytest_cache",
                ".ruff_cache",
                ".coverage",
            ]
        ),
    ]

    async def _python(self) -> dagger.Container:
        """The project and its dev dependencies, on the Dockerfile's build image, so Python and uv match the release."""
        dockerfile = await self.source.file("Dockerfile").contents()
        image = re.search(r"^FROM (\S+) AS build$", dockerfile, re.MULTILINE).group(1)
        return (
            dag.container()
            .from_(image)
            # lupa, which fakeredis[lua] needs, has no Python 3.15 wheels yet: it builds from source.
            .with_exec(["sh", "-c", "apt-get update -qq && apt-get install -qq -y --no-install-recommends build-essential"])
            .with_env_variable("UV_LINK_MODE", "copy")
            .with_env_variable("UV_PYTHON_DOWNLOADS", "0")
            .with_mounted_cache("/root/.cache/uv", dag.cache_volume("uv"))
            .with_workdir("/app")
            .with_directory("/app", self.source)
            .with_exec(["uv", "sync", "--locked"])
        )

    @function
    @check
    async def lint(self) -> None:
        """ruff check and ruff format --check."""
        python = await self._python()
        await (
            python.with_exec(["uv", "run", "ruff", "check", "."])
            .with_exec(["uv", "run", "ruff", "format", "--check", "."])
            .sync()
        )

    @function
    @check
    async def unit_tests(self) -> None:
        """tests/unit."""
        await (await self._python()).with_exec(["uv", "run", "pytest", "tests/unit"]).sync()

    @function
    @check
    async def integration_tests(self) -> None:
        """tests/integration, against a fresh Lightdash with the jaffle-shop demo data, and Redis."""
        redis = dag.container().from_(REDIS).with_exposed_port(6379).as_service(use_entrypoint=True)
        await (
            (await self._python())
            .with_service_binding("lightdash", self._lightdash())
            .with_service_binding("redis", redis)
            .with_env_variable("INTEGRATION_LIGHTDASH_URL", LIGHTDASH_URL)
            .with_env_variable("INTEGRATION_REDIS_URL", "redis://redis:6379/15")
            .with_exec(["uv", "run", "pytest", "tests/integration"])
            .sync()
        )

    @function
    @check
    async def image(self) -> None:
        """Build the Docker image from the Dockerfile, without publishing it."""
        await self.source.docker_build().sync()

    def _demo(self) -> dagger.Directory:
        """The files `make lightdash` checks out from the Lightdash repository: the demo project and the MinIO setup."""
        return (
            dag.container()
            .from_(GIT)
            .with_workdir("/lightdash")
            .with_exec(
                [
                    "git",
                    "clone",
                    "-q",
                    "--depth=1",
                    f"--branch={LIGHTDASH_VERSION}",
                    "--filter=blob:none",
                    "--sparse",
                    "https://github.com/lightdash/lightdash",
                    ".",
                ]
            )
            .with_exec(["git", "sparse-checkout", "set", "docker", "examples/full-jaffle-shop-demo"])
            .directory("/lightdash")
        )

    def _lightdash(self) -> dagger.Service:
        """Lightdash as `make dev` runs it: examples/full-jaffle-shop-demo/docker-compose.yml with dev/lightdash.compose.yml."""
        demo = self._demo()
        example = demo.directory("examples/full-jaffle-shop-demo")
        db = (
            dag.container()
            .from_(POSTGRES)
            .with_env_variable("POSTGRES_PASSWORD", "password")
            .with_exposed_port(5432)
            .as_service(use_entrypoint=True)
        )
        minio = (
            dag.container()
            .from_(MINIO)
            .with_file("/init-minio.sh", demo.file("docker/init-minio.sh"), permissions=0o755)
            .with_env_variable("MINIO_ROOT_USER", "minioadmin")
            .with_env_variable("MINIO_ROOT_PASSWORD", "minioadmin")
            .with_env_variable("MINIO_DEFAULT_BUCKETS", "default")
            .with_exposed_port(9000)
            .as_service(args=["/init-minio.sh"])
        )
        environment = {
            "PGHOST": "db",
            "PGPASSWORD": "password",
            "PGUSER": "postgres",
            "PGPORT": "5432",
            "PGDATABASE": "postgres",
            "SECURE_COOKIES": "false",
            "TRUST_PROXY": "false",
            "LIGHTDASH_SECRET": "not very secret",
            "SAVED_METRICS_TREE_ENABLED": "false",
            "SITE_URL": LIGHTDASH_URL,
            "SCHEDULER_ENABLED": "true",
            "GROUPS_ENABLED": "true",
            "DBT_DEMO_DIR": "/usr/app",
            "S3_ENDPOINT": "http://minio:9000",
            "S3_REGION": "us-east-1",
            "S3_BUCKET": "default",
            "S3_ACCESS_KEY": "minioadmin",
            "S3_SECRET_KEY": "minioadmin",
            "S3_FORCE_PATH_STYLE": "true",
        }
        lightdash = (
            # Lightdash publishes amd64 images only.
            dag.container(platform=dagger.Platform("linux/amd64"))
            .from_(LIGHTDASH)
            .with_user("root")
            .with_directory("/usr/app/dbt", example.directory("dbt"))
            .with_directory("/usr/app/profiles", example.directory("profiles"))
            .with_file("/usr/bin/entrypoint.sh", self.source.file("dev/entrypoint.sh"), permissions=0o755)
            .with_service_binding("db", db)
            .with_service_binding("minio", minio)
        )
        for name, value in environment.items():
            lightdash = lightdash.with_env_variable(name, value)
        # Lightdash opens its port only once the demo data is seeded, which takes minutes: the tests wait for it.
        return lightdash.with_exposed_port(8080, experimental_skip_healthcheck=True).as_service(
            args=["/usr/bin/entrypoint.sh", "pnpm", "start"]
        )
