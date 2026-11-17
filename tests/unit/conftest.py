import httpx
import pytest
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.auth.store import Store
from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashClient

LIGHTDASH = "http://lightdash.test"
TOKEN_URL = f"{LIGHTDASH}/api/v1/oauth/token"
REVOKE_URL = f"{LIGHTDASH}/api/v1/oauth/revoke"
REDIRECT = "http://localhost:9999/callback"
PROJECT = "3675b69e-8324-4110-bdca-059031aa8da3"


def token_response(
    access: str = "ld-access-2",
    refresh: str = "ld-refresh-2",
    expires_in: int = 3600,
) -> httpx.Response:
    tokens = {"access_token": access, "refresh_token": refresh, "expires_in": expires_in}

    return httpx.Response(200, json=tokens)


REFRESHED = token_response()


def make_settings(**overrides) -> Settings:
    """Settings that pass `check()`, with a fresh Fernet key, ignoring the developer's `.env`."""
    defaults = {
        "_env_file": None,
        "lightdash_url": LIGHTDASH,
        "lightdash_client_id": "id",
        "lightdash_client_secret": "secret",
        "fernet_key": Fernet.generate_key().decode(),
    }

    return Settings(**(defaults | overrides))


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def redis() -> FakeAsyncRedis:
    return FakeAsyncRedis()


@pytest.fixture
def provider(settings, redis) -> LightdashOAuthProvider:
    return LightdashOAuthProvider(settings, Store(redis, settings.fernet_key))


@pytest.fixture
async def client():
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        yield LightdashClient(http, "token")
