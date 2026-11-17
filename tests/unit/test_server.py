"""The server over HTTP: the SDK's token and revocation endpoints with this provider, body limits, the audit log."""

import asyncio
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
from redis.asyncio.client import Pipeline
from redis.asyncio.lock import Lock
from redis.exceptions import ConnectionError

from lightdash_mcp import server as server_module
from lightdash_mcp.auth import store as store_module
from lightdash_mcp.auth.audit import MAX_VALUE
from lightdash_mcp.auth.provider import Code, Grant, _challenge
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.config import Settings
from lightdash_mcp.server import asgi_app, audit, create_server

LIGHTDASH = "http://lightdash.test"
TOKEN_URL = f"{LIGHTDASH}/api/v1/oauth/token"
REVOKE_URL = f"{LIGHTDASH}/api/v1/oauth/revoke"
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


@pytest.fixture
def busy(redis, monkeypatch):
    """The lock of grant `grant`, to hold as a request in flight would. Waiting for it gives up after 0.1 seconds."""
    monkeypatch.setattr(store_module, "LOCK_TIMEOUT", 0.1)
    return redis.lock("lightdash-mcp:lock:grant:grant", timeout=60)


def retryable(response: httpx.Response) -> bool:
    """An OAuth error that tells the client to try again with the same code or refresh token, which still work."""
    body = response.json()
    return response.status_code == 400 and body["error"] == "invalid_request" and "Try again" in body["error_description"]


@pytest.mark.parametrize(
    "lightdash",
    [
        httpx.ConnectError("down"),
        httpx.ReadTimeout("slow"),
        httpx.Response(502),
        httpx.Response(401, json={"error": "invalid_client"}),
        httpx.Response(200, json={"access_token": "only"}),
    ],
)
@respx.mock
async def test_a_refresh_lightdash_fails_can_be_retried(http, settings, redis, lightdash):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    route = respx.post(TOKEN_URL).mock(side_effect=[lightdash])

    failed = await refresh(http, client, tokens["refresh_token"])
    assert retryable(failed), failed.text
    assert failed.headers["cache-control"] == "no-store"
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant)

    route.mock(side_effect=None, return_value=REFRESHED)
    assert (await refresh(http, client, tokens["refresh_token"])).status_code == 200


@respx.mock
async def test_a_refresh_while_the_grant_is_busy_can_be_retried(http, settings, redis, busy):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    async with busy:
        failed = await refresh(http, client, tokens["refresh_token"])
    assert retryable(failed), failed.text
    assert not route.called
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant)
    assert (await refresh(http, client, tokens["refresh_token"])).status_code == 200


async def test_a_code_exchange_while_the_grant_is_busy_can_be_retried(http, settings, redis, busy):
    client = await register(http)
    code = await add_code(settings, redis, client)
    async with busy:
        failed = await exchange(http, client, code)
    assert retryable(failed), failed.text
    assert (await exchange(http, client, code)).status_code == 200


@respx.mock
async def test_a_reused_refresh_token_while_the_grant_is_busy_still_ends_the_grant(http, settings, redis, busy):
    client = await register(http)
    first = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    assert (await refresh(http, client, first["refresh_token"])).status_code == 200

    # Reuse is found while the token loads, outside the SDK's error handling: the grant can't end with its lock busy.
    async with busy:
        failed = await refresh(http, client, first["refresh_token"])
    assert retryable(failed), failed.text
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant)

    reused = await refresh(http, client, first["refresh_token"])
    assert (reused.status_code, reused.json()["error"]) == (400, "invalid_grant")
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant) is None


@respx.mock
async def test_a_revocation_while_the_grant_is_busy_can_be_retried(http, settings, redis, busy):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    form = {"token": tokens["access_token"], **credentials(client)}

    async with busy:
        failed = await http.post("/revoke", data=form)
    # RFC 7009 section 2.2.1: the client must assume the token still works, and may retry.
    assert failed.status_code == 503, failed.text
    assert failed.headers["retry-after"]
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant)

    assert (await http.post("/revoke", data=form)).status_code == 200
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant) is None


@respx.mock
async def test_a_refresh_that_outlasts_the_lock_still_returns_its_tokens(http, settings, redis, monkeypatch):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    monkeypatch.setattr(store_module, "LOCK_TIMEOUT", 0.05)

    async def slow(request):
        await asyncio.sleep(0.2)
        return REFRESHED

    respx.post(TOKEN_URL).mock(side_effect=slow)
    # The new tokens are saved and the old refresh token rotated: an error here would leave the client with neither.
    refreshed = await refresh(http, client, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    assert (await refresh(http, client, refreshed.json()["refresh_token"])).status_code == 200


def fail(monkeypatch: pytest.MonkeyPatch, target: object, name: str) -> None:
    async def down(*args, **kwargs):
        raise ConnectionError("Redis is down")

    monkeypatch.setattr(target, name, down)


def fail_command(monkeypatch: pytest.MonkeyPatch, redis: FakeAsyncRedis, step: int) -> list[str]:
    """Fail the Redis command number `step`, from 0. Returns the failed command's name, once it fails.

    Transactions aren't counted: a pipeline sends them on its own, without the client's execute_command.
    """
    original, sent, failed = redis.execute_command, [0], []

    async def execute(*args, **kwargs):
        sent[0] += 1
        if sent[0] - 1 == step:
            failed.append(args[0])
            raise ConnectionError("Redis is down")
        return await original(*args, **kwargs)

    monkeypatch.setattr(redis, "execute_command", execute)
    return failed


# Sent once the new tokens or the grant's end are written: the lock's release, and the client registration's renewal.
AFTER_THE_WRITE = ("EVALSHA", "SCRIPT LOAD", "EXPIRE")


@respx.mock
async def test_a_refresh_with_any_redis_command_failing_can_be_retried(http, settings, redis, monkeypatch):
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    store, step = Store(redis, settings.fernet_key), 0
    while True:
        client, grant_id = await register(http), f"grant-{step}"
        tokens = (await exchange(http, client, await add_code(settings, redis, client, grant_id))).json()
        with monkeypatch.context() as down:
            failed = fail_command(down, redis, step)
            response = await refresh(http, client, tokens["refresh_token"])
        if not failed:
            break
        grant = await store.get("grant", grant_id, Grant)
        if failed[0] in AFTER_THE_WRITE:
            assert response.status_code == 200, (failed, response.text)
            assert grant and grant.refresh_digest == digest(response.json()["refresh_token"])
        else:
            assert retryable(response), (failed, response.text)
            assert grant and grant.refresh_digest == digest(tokens["refresh_token"]), failed
            assert (await refresh(http, client, tokens["refresh_token"])).status_code == 200, failed
        step += 1
    assert step >= 8


async def test_a_code_exchange_with_any_redis_command_failing_can_be_retried_until_the_code_is_taken(
    http, settings, redis, monkeypatch
):
    store, step, spent = Store(redis, settings.fernet_key), 0, []
    while True:
        client, grant_id = await register(http), f"grant-{step}"
        code = await add_code(settings, redis, client, grant_id)
        with monkeypatch.context() as down:
            failed = fail_command(down, redis, step)
            response = await exchange(http, client, code)
        if not failed:
            break
        if failed[0] in AFTER_THE_WRITE:
            assert response.status_code == 200, (failed, response.text)
        else:
            assert retryable(response), (failed, response.text)
            # Taken by GETDEL before the tokens are written: a failure after it spends the code.
            taken = await store.get("code", digest(code), Code) is None
            retried = await exchange(http, client, code)
            assert (retried.status_code, retried.json().get("error")) == ((400, "invalid_grant") if taken else (200, None))
            spent += [failed[0]] if taken else []
        step += 1
    # The grant's read, just after GETDEL. Here a failed command never runs; on Redis, a GETDEL whose answer is lost has.
    assert spent == ["GET"]


@respx.mock
async def test_a_revocation_with_any_redis_command_failing_can_be_retried(http, settings, redis, monkeypatch):
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    store, step = Store(redis, settings.fernet_key), 0
    while True:
        client, grant_id = await register(http), f"grant-{step}"
        tokens = (await exchange(http, client, await add_code(settings, redis, client, grant_id))).json()
        form = {"token": tokens["access_token"], **credentials(client)}
        with monkeypatch.context() as down:
            failed = fail_command(down, redis, step)
            response = await http.post("/revoke", data=form)
        if not failed:
            break
        if failed[0] in AFTER_THE_WRITE:
            assert response.status_code == 200, (failed, response.text)
        else:
            assert (response.status_code, response.headers.get("retry-after")) == (503, "5"), (failed, response.text)
            grant = await store.get("grant", grant_id, Grant)
            assert grant and grant.access_digest == digest(tokens["access_token"]), failed
            assert (await http.post("/revoke", data=form)).status_code == 200, failed
        assert await store.get("grant", grant_id, Grant) is None
        step += 1
    assert step >= 6


@respx.mock
async def test_a_refresh_whose_token_write_fails_can_be_retried(http, settings, redis, monkeypatch, caplog):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await refresh(http, client, tokens["refresh_token"])
    assert retryable(failed), failed.text
    assert failed.headers["cache-control"] == "no-store"
    assert '"storage_failed"' in caplog.text
    grant = await Store(redis, settings.fernet_key).get("grant", "grant", Grant)
    assert grant and grant.refresh_digest == digest(tokens["refresh_token"])
    assert (await refresh(http, client, tokens["refresh_token"])).status_code == 200


async def test_a_code_whose_tokens_failed_to_save_is_spent(http, settings, redis, monkeypatch):
    client = await register(http)
    code = await add_code(settings, redis, client)
    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await exchange(http, client, code)
    # Answered as any outage, but the code was taken before the write failed: the user signs in again.
    assert retryable(failed), failed.text
    spent = await exchange(http, client, code)
    assert (spent.status_code, spent.json()["error"]) == (400, "invalid_grant")


@respx.mock
async def test_a_revocation_whose_transaction_fails_keeps_the_grant(http, settings, redis, monkeypatch):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    lightdash = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    form = {"token": tokens["access_token"], **credentials(client)}

    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await http.post("/revoke", data=form)
    assert failed.status_code == 503, failed.text
    assert failed.headers["retry-after"] == "5"
    assert failed.json()["error"] == "temporarily_unavailable"
    assert not lightdash.called
    grant = await Store(redis, settings.fernet_key).get("grant", "grant", Grant)
    assert grant and grant.access_digest == digest(tokens["access_token"])

    assert (await http.post("/revoke", data=form)).status_code == 200
    assert await Store(redis, settings.fernet_key).get("grant", "grant", Grant) is None


async def test_a_bearer_header_during_a_redis_outage_can_be_retried(http, settings, redis, monkeypatch):
    # The SDK's Bearer middleware loads the token before the endpoint, outside the routes' error handling.
    client = await register(http)
    bearer = {"Authorization": "Bearer some-token"}
    fail(monkeypatch, redis, "execute_command")
    token = await http.post(
        "/token", headers=bearer, data={"grant_type": "refresh_token", "refresh_token": "r", **credentials(client)}
    )
    assert retryable(token), token.text
    revoked = await http.post("/revoke", headers=bearer, data={"token": "t", **credentials(client)})
    assert revoked.status_code == 503, revoked.text


@pytest.mark.parametrize("failing", [(Lock, "do_release"), (FakeAsyncRedis, "expire")], ids=["lock release", "client renewal"])
@respx.mock
async def test_a_refresh_saved_before_redis_fails_still_returns_its_tokens(http, settings, redis, monkeypatch, failing):
    client = await register(http)
    tokens = (await exchange(http, client, await add_code(settings, redis, client))).json()
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with monkeypatch.context() as down:
        fail(down, *failing)
        refreshed = await refresh(http, client, tokens["refresh_token"])
    # The old refresh token is rotated by then: an error would leave the client with neither.
    assert refreshed.status_code == 200, refreshed.text
    grant = await Store(redis, settings.fernet_key).get("grant", "grant", Grant)
    assert grant and grant.refresh_digest == digest(refreshed.json()["refresh_token"])


async def test_a_redis_outage_elsewhere_is_still_a_server_error(settings, redis, monkeypatch):
    transport = httpx.ASGITransport(asgi_app(settings, redis), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as http:
        fail(monkeypatch, redis, "execute_command")
        consent = await http.get("/oauth/consent", params={"transaction": "t"})
    assert consent.status_code == 500


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
