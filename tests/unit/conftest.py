import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

from lightdash_mcp.auth.provider import Access, Code, Grant, LightdashOAuthProvider, _challenge
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashClient
from lightdash_mcp.server import create_server

LIGHTDASH = "http://lightdash.test"
TOKEN_URL = f"{LIGHTDASH}/api/v1/oauth/token"
REVOKE_URL = f"{LIGHTDASH}/api/v1/oauth/revoke"
REDIRECT = "http://localhost:9999/callback"
PROJECT = "3675b69e-8324-4110-bdca-059031aa8da3"
VERIFIER = "v" * 64

TOKEN_LIFETIME = 3600
GRANT_TTL = 600
CODE_TTL = 300


def token_response(
    access: str = "ld-access-2",
    refresh: str = "ld-refresh-2",
    expires_in: int = TOKEN_LIFETIME,
) -> httpx.Response:
    tokens = {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
    }

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


async def add_code(
    settings: Settings,
    redis: FakeAsyncRedis,
    client: dict,
    grant_id: str = "grant",
) -> str:
    """A finished sign-in, as the Lightdash callback leaves it. Returns the client's code."""
    store = Store(redis, settings.fernet_key)
    code = f"code-{grant_id}"
    grant = Grant(
        client_id=client["client_id"],
        subject="user",
        access_token="ld-access",
        refresh_token="ld-refresh",
        expires_at=time.time() + TOKEN_LIFETIME,
        code_digest=digest(code),
    )
    pending = Code(
        code=code,
        scopes=["lightdash"],
        expires_at=time.time() + CODE_TTL,
        client_id=client["client_id"],
        code_challenge=_challenge(VERIFIER),
        redirect_uri=REDIRECT,
        redirect_uri_provided_explicitly=True,
        subject="user",
        grant_id=grant_id,
    )

    await store.put("grant", grant_id, grant, GRANT_TTL)
    await store.put("code", digest(code), pending, CODE_TTL)

    return code


def signed_in_tools(settings: Settings, redis: FakeAsyncRedis) -> Callable[..., Awaitable[Any]]:
    """Calls the server's tools as a signed-in user with a fresh Lightdash token, as the bearer
    middleware does."""
    server = create_server(settings, redis)
    store = Store(redis, settings.fernet_key)
    access = Access(
        token="our-access",
        client_id="client",
        scopes=[],
        subject="user",
        grant_id="grant",
    )

    async def call(tool_name: str, /, **arguments: Any) -> Any:
        grant = Grant(
            client_id="client",
            subject="user",
            access_token="ld-access",
            refresh_token="ld-refresh",
            expires_at=time.time() + TOKEN_LIFETIME,
        )
        await store.put("grant", "grant", grant)
        context = auth_context_var.set(AuthenticatedUser(access))

        try:
            result = await server.call_tool(tool_name, arguments)
        finally:
            auth_context_var.reset(context)

        structured = result.structured_content
        is_a_single_result = set(structured) == {"result"}

        if is_a_single_result:
            return structured["result"]

        return structured

    return call


@pytest.fixture
def call_tool(settings, redis) -> Callable[..., Awaitable[Any]]:
    return signed_in_tools(settings, redis)
