"""The server over HTTP: the SDK's token and revocation endpoints with this provider, body limits, the audit log."""

import base64
import json
import logging
import time
from types import SimpleNamespace

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis

from lightdash_mcp import server as server_module
from lightdash_mcp.auth import store as store_module
from lightdash_mcp.auth.audit import MAX_VALUE
from lightdash_mcp.auth.provider import Code, Grant, _challenge
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.config import Settings
from lightdash_mcp.server import asgi_app, audit, create_server

LIGHTDASH = "http://lightdash.test"
REDIRECT = "http://localhost:9999/callback"
VERIFIER = "v" * 64
REFRESHED = httpx.Response(200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600})


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        lightdash_url=LIGHTDASH,
        lightdash_client_id="id",
        lightdash_client_secret="lightdash-secret",
        fernet_key=Fernet.generate_key().decode(),
    )


@pytest.fixture
def redis() -> FakeAsyncRedis:
    return FakeAsyncRedis()


@pytest.fixture
async def http(settings, redis):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(asgi_app(settings, redis)), base_url="http://localhost:8000"
    ) as http:
        yield http


async def register(http: httpx.AsyncClient, auth_method: str = "client_secret_post") -> dict:
    response = await http.post(
        "/register", json={"client_name": "App", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": auth_method}
    )
    assert response.status_code == 201, response.text
    return response.json()


async def add_code(settings: Settings, redis: FakeAsyncRedis, client: dict, grant_id: str = "grant") -> str:
    """A finished sign-in, as the Lightdash callback leaves it. Returns the client's code."""
    store, code = Store(redis, settings.fernet_key), f"code-{grant_id}"
    grant = Grant(
        client_id=client["client_id"],
        subject="user",
        access_token="ld-access",
        refresh_token="ld-refresh",
        expires_at=time.time() + 3600,
        code_digest=digest(code),
    )
    await store.put("grant", grant_id, grant, 600)
    await store.put(
        "code",
        digest(code),
        Code(
            code=code,
            scopes=["lightdash"],
            expires_at=time.time() + 300,
            client_id=client["client_id"],
            code_challenge=_challenge(VERIFIER),
            redirect_uri=REDIRECT,
            redirect_uri_provided_explicitly=True,
            subject="user",
            grant_id=grant_id,
        ),
        300,
    )
    return code


def credentials(client: dict) -> dict:
    return {"client_id": client["client_id"], "client_secret": client["client_secret"]}


async def exchange(http: httpx.AsyncClient, client: dict, code: str, verifier: str = VERIFIER) -> httpx.Response:
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}
    return await http.post("/token", data={**form, **credentials(client)})


async def refresh(http: httpx.AsyncClient, client: dict, refresh_token: str) -> httpx.Response:
    return await http.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token, **credentials(client)})


async def test_a_code_needs_its_verifier_and_works_once(http, settings, redis):
    client = await register(http)
    code = await add_code(settings, redis, client)
    wrong = await exchange(http, client, code, "w" * 64)
    assert (wrong.status_code, wrong.json()["error"]) == (400, "invalid_grant")
    assert (await exchange(http, client, code)).status_code == 200
    reused = await exchange(http, client, code)
    assert (reused.status_code, reused.json()["error"]) == (400, "invalid_grant")


async def test_a_code_works_for_its_own_client_only(http, settings, redis):
    client, other = await register(http), await register(http)
    code = await add_code(settings, redis, client)
    assert (await exchange(http, other, code)).status_code == 400
    assert (await exchange(http, client, code)).status_code == 200


@respx.mock
async def test_a_refresh_token_works_for_its_own_client_only(http, settings, redis):
    client, other = await register(http), await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(f"{LIGHTDASH}/api/v1/oauth/token").mock(return_value=REFRESHED)

    stolen = await refresh(http, other, tokens["refresh_token"])
    assert (stolen.status_code, stolen.json()["error"]) == (400, "invalid_grant")
    rotated = await refresh(http, client, tokens["refresh_token"])
    assert rotated.status_code == 200, rotated.text


async def test_a_basic_auth_client_can_revoke(http, settings, redis):
    client = await register(http, "client_secret_basic")
    basic = {"Authorization": "Basic " + base64.b64encode(f"{client['client_id']}:{client['client_secret']}".encode()).decode()}
    form = {"grant_type": "authorization_code", "code": await add_code(settings, redis, client)}
    tokens = await http.post("/token", headers=basic, data={**form, "redirect_uri": REDIRECT, "code_verifier": VERIFIER})
    assert tokens.status_code == 200, tokens.text

    with respx.mock:
        respx.post(f"{LIGHTDASH}/api/v1/oauth/revoke").mock(return_value=httpx.Response(200))
        revoked = await http.post("/revoke", headers=basic, data={"token": tokens.json()["access_token"]})
    assert revoked.status_code == 200, revoked.text
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant) is None


async def test_large_token_bodies_are_refused_before_they_are_read(http):
    basic = {"Authorization": "Basic " + base64.b64encode(b"client:secret").decode()}
    declared = await http.post("/token", headers=basic, content=b"a=" + b"x" * 100_000)
    assert declared.status_code == 413

    async def chunks():
        for _ in range(100):
            yield b"x" * 1024

    streamed = await http.post("/revoke", headers=basic, content=chunks())
    assert streamed.status_code == 413


async def test_the_audit_log_is_one_json_line_per_call(caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    name = 'list_projects\n{"event": "tool_call", "user": "admin", "tool": "delete_everything"}'
    ctx = SimpleNamespace(method="tools/call", params={"name": name, "arguments": {"body": "x" * 10_000, "dry_run": False}})

    async def call_next(_):
        return {"isError": False}

    await audit(ctx, call_next)
    [line] = [r.getMessage() for r in caplog.records if r.name == "lightdash_mcp.audit"]
    assert "\n" not in line
    logged = json.loads(line)
    assert (logged["event"], logged["tool"], logged["error"]) == ("tool_call", name, False)
    assert logged["arguments"]["dry_run"] is False
    assert len(logged["arguments"]["body"]) == MAX_VALUE + 3


@respx.mock
async def test_the_audit_log_follows_a_sign_in_without_its_secrets(http, settings, redis, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(f"{LIGHTDASH}/api/v1/oauth/token").mock(return_value=REFRESHED)
    respx.post(f"{LIGHTDASH}/api/v1/oauth/revoke").mock(return_value=httpx.Response(200))
    tokens = (await refresh(http, client, tokens["refresh_token"])).json()
    await http.post("/revoke", data={"token": tokens["refresh_token"], **credentials(client)})

    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "lightdash_mcp.audit"]
    assert [line["event"] for line in lines] == ["client_registered", "token_revoked", "grant_ended"]
    assert lines[-1]["reason"] == "revoked"
    secrets = [client["client_secret"], tokens["access_token"], tokens["refresh_token"], "ld-refresh-2", "lightdash-secret"]
    assert not [secret for secret in secrets if secret in caplog.text]


@pytest.fixture
def busy(redis, monkeypatch):
    """The lock of grant `grant`, to hold as a request in flight would. Waiting for it gives up after 0.1 seconds."""
    monkeypatch.setattr(store_module, "LOCK_TIMEOUT", 0.1)
    return redis.lock("lightdash-mcp:lock:grant:grant", timeout=60)


@respx.mock
async def test_a_revocation_while_the_grant_is_busy_logs_no_token_revoked(settings, redis, busy, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    respx.post(f"{LIGHTDASH}/api/v1/oauth/revoke").mock(return_value=httpx.Response(200))
    # A busy lock fails the request: answered as an error, not raised into the test.
    transport = httpx.ASGITransport(asgi_app(settings, redis), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as http:
        client = await register(http)
        tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
        async with busy:
            failed = await http.post("/revoke", data={"token": tokens["access_token"], **credentials(client)})

    assert failed.status_code >= 500, failed.text
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant)
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "lightdash_mcp.audit"]
    assert [line["event"] for line in lines] == ["client_registered", "revoke_busy"]
    assert (lines[-1]["grant"], lines[-1]["subject"], lines[-1]["client_id"]) == ("grant", "user", client["client_id"])
    assert [r.levelno for r in caplog.records if "revoke_busy" in r.getMessage()] == [logging.WARNING]


async def test_stopping_closes_the_http_client_and_redis(settings, redis, monkeypatch):
    closed = []
    monkeypatch.setattr(Store, "close", lambda self: closed.append("redis") or _done())
    monkeypatch.setattr(httpx.AsyncClient, "aclose", lambda self: _fail())
    app = create_server(settings, redis).streamable_http_app()
    with pytest.raises(RuntimeError, match="aclose failed"):
        async with app.router.lifespan_context(app):
            pass
    # Closed even though closing the HTTP client failed.
    assert closed == ["redis"]


async def _done() -> None:
    pass


async def _fail() -> None:
    raise RuntimeError("aclose failed")


def test_redis_requests_time_out(settings, monkeypatch):
    created = {}
    monkeypatch.setattr(server_module.Redis, "from_url", lambda url, **options: created.update(options) or FakeAsyncRedis())
    create_server(settings)
    assert created["socket_timeout"] and created["socket_connect_timeout"]
