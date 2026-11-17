import logging
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]")
WEB_SCHEMES = ("http", "https")
REQUIRED_SETTINGS = ("lightdash_client_id", "lightdash_client_secret", "fernet_key")

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    lightdash_url: str = "http://localhost:8080"
    lightdash_client_id: str = ""
    lightdash_client_secret: str = ""
    # Defaults to http://localhost:<port>.
    public_url: str = ""
    fernet_key: str = ""
    redis_url: str = "redis://localhost:6379/0"
    host: str = "127.0.0.1"
    port: int = 8000
    # Lifetime of the access tokens this server issues. Clients that don't refresh them, such as
    # Dex's OAuth connector, need a longer one. At most 14 days, the refresh-token lifetime.
    access_token_ttl: int = Field(default=60 * 60, ge=60, le=14 * 24 * 60 * 60)
    # Comma-separated. When set, MCP clients can register https redirect URIs on these hosts only.
    redirect_hosts: Annotated[list[str], NoDecode] = []

    @field_validator("lightdash_url", "public_url")
    @classmethod
    def _strip_slash(cls, url: str) -> str:
        return url.rstrip("/")

    @field_validator("redirect_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, hosts: str | list[str]) -> list[str]:
        if isinstance(hosts, str):
            hosts = hosts.split(",")

        stripped = [host.strip() for host in hosts]
        return [host.lower() for host in stripped if host]

    @model_validator(mode="after")
    def _default_public_url(self) -> Self:
        self.public_url = self.public_url or f"http://localhost:{self.port}"
        return self

    def check(self) -> None:
        self._check_required()
        self._check_lightdash_url()
        self._check_public_url()

    def _check_required(self) -> None:
        unset = [name for name in REQUIRED_SETTINGS if not getattr(self, name)]

        if unset:
            names = ", ".join(name.upper() for name in unset)
            raise SystemExit(f"Missing settings: {names}. See .env.example.")

    def _check_lightdash_url(self) -> None:
        lightdash = urlsplit(self.lightdash_url)

        if lightdash.scheme not in WEB_SCHEMES or not lightdash.hostname:
            raise SystemExit(
                f"LIGHTDASH_URL must be an http or https address, not {self.lightdash_url!r}."
            )

    def _check_public_url(self) -> None:
        public = urlsplit(self.public_url)
        is_web_address = public.scheme in WEB_SCHEMES and bool(public.hostname)
        is_host_root = not (public.path or public.query or public.fragment)

        if not is_web_address or not is_host_root:
            raise SystemExit(
                "PUBLIC_URL must be an http or https address at the root of its host, "
                f"not {self.public_url!r}."
            )

        is_https = public.scheme == "https"

        # Browsers sign in and clients send their tokens there: only a loopback address may be
        # plain HTTP.
        if not is_https and public.hostname not in LOOPBACK_HOSTS:
            raise SystemExit(
                f"PUBLIC_URL must be https unless its host is localhost, not {self.public_url!r}."
            )

        if is_https and self.host not in LOOPBACK_HOSTS:
            logger.warning(
                "HOST=%s: the server also answers over plain HTTP on that address, around the "
                "HTTPS proxy at PUBLIC_URL. Use HOST=127.0.0.1 when the proxy runs on this "
                "machine, as Tailscale serve or Docker with network_mode host do. Keep "
                "HOST=0.0.0.0 only inside a container whose port is published to the proxy alone.",
                self.host,
            )

    @property
    def callback_url(self) -> str:
        return f"{self.public_url}/oauth/lightdash/callback"
