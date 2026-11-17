"""The sign-in flow's refusals: registration, /authorize, the consent page and the Lightdash callback."""

from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request

from lightdash_mcp.auth.provider import LightdashOAuthProvider, Transaction, _consent_cookie
from lightdash_mcp.auth.store import Store
from lightdash_mcp.config import Settings

LIGHTDASH = "http://lightdash.test"
REDIRECT = "http://localhost:9999/callback"


@pytest.fixture
def provider() -> LightdashOAuthProvider:
    settings = Settings(
        _env_file=None,
        lightdash_url=LIGHTDASH,
        lightdash_client_id="id",
        lightdash_client_secret="secret",
        fernet_key=Fernet.generate_key().decode(),
    )
    return LightdashOAuthProvider(settings, Store(FakeAsyncRedis(), settings.fernet_key))


def request(path: str, query: dict | None = None, cookies: dict | None = None, form: dict | None = None) -> Request:
    headers = []
    if cookies:
        headers.append((b"cookie", "; ".join(f"{name}={value}" for name, value in cookies.items()).encode()))
    body = urlencode(form or {}).encode()
    if form is not None:
        headers += [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(body)).encode())]

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST" if form is not None else "GET",
        "path": path,
        "query_string": urlencode(query or {}).encode(),
        "headers": headers,
    }
    return Request(scope, receive)


def client(*redirect_uris: str, **fields) -> OAuthClientInformationFull:
    fields = {"client_id": "client", "client_name": "App", "redirect_uris": list(redirect_uris or [REDIRECT]), **fields}
    return OAuthClientInformationFull(**fields)


def params(**overrides) -> AuthorizationParams:
    fields = {
        "state": "client-state",
        "scopes": [],
        "code_challenge": "x" * 43,
        "redirect_uri": REDIRECT,
        "redirect_uri_provided_explicitly": True,
    }
    return AuthorizationParams(**{**fields, **overrides})


async def start(provider: LightdashOAuthProvider) -> tuple[str, str]:
    """A registered client's /authorize. Returns the transaction ID and its CSRF token."""
    await provider.register_client(client())
    location = await provider.authorize(client(), params())
    transaction_id = parse_qs(urlparse(location).query)["transaction"][0]
    return transaction_id, (await provider.store.get("transaction", transaction_id, Transaction)).csrf


async def test_the_consent_form_needs_the_csrf_token_and_the_cookie(provider):
    transaction_id, csrf = await start(provider)
    cookie = _consent_cookie(transaction_id)
    for form_csrf, cookies in [
        (None, {cookie: csrf}),
        ("wrong", {cookie: csrf}),
        ("é" * 43, {cookie: csrf}),  # compare_digest raises TypeError on a non-ASCII str: it must be a 400, not a 500
        (csrf, {}),
        (csrf, {cookie: "wrong"}),
        (csrf, {cookie: "é"}),
        (csrf, {_consent_cookie("another transaction"): csrf}),
    ]:
        form = {"transaction": transaction_id, "action": "allow"} | ({"csrf": form_csrf} if form_csrf else {})
        response = await provider.consent_submit(request("/oauth/consent", cookies=cookies, form=form))
        assert response.status_code == 400, (form_csrf, cookies)
        assert not (await provider.store.get("transaction", transaction_id, Transaction)).approved

    form = {"transaction": transaction_id, "csrf": csrf, "action": "allow"}
    response = await provider.consent_submit(request("/oauth/consent", cookies={cookie: csrf}, form=form))
    assert response.status_code == 303
    assert response.headers["location"].startswith(f"{LIGHTDASH}/api/v1/oauth/authorize?")


async def test_a_second_load_of_the_consent_page_keeps_the_first_one_working(provider):
    transaction_id, csrf = await start(provider)
    for _ in range(2):  # a prefetch, or a second tab
        page = await provider.consent_page(request("/oauth/consent", {"transaction": transaction_id}))
        assert f'name="csrf" value="{csrf}"' in page.body.decode()
    form = {"transaction": transaction_id, "csrf": csrf, "action": "allow"}
    response = await provider.consent_submit(
        request("/oauth/consent", cookies={_consent_cookie(transaction_id): csrf}, form=form)
    )
    assert response.status_code == 303


async def test_a_large_consent_form_is_refused(provider):
    transaction_id, csrf = await start(provider)
    form = {"transaction": transaction_id, "csrf": csrf, "action": "allow", "padding": "x" * 100_000}
    response = await provider.consent_submit(
        request("/oauth/consent", cookies={_consent_cookie(transaction_id): csrf}, form=form)
    )
    assert response.status_code == 413


async def test_the_callback_needs_an_approved_sign_in_and_its_cookie(provider):
    transaction_id, csrf = await start(provider)
    cookie = _consent_cookie(transaction_id)
    query = {"state": transaction_id, "code": "lightdash-code"}
    # Not approved yet, as with a Lightdash link sent before the consent page.
    assert (await provider.lightdash_callback(request("/oauth/lightdash/callback", query, {cookie: csrf}))).status_code == 400

    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    await provider.store.put("transaction", transaction_id, transaction.model_copy(update={"approved": True}))
    for cookies in ({}, {cookie: "wrong"}, {cookie: "é"}):
        response = await provider.lightdash_callback(request("/oauth/lightdash/callback", query, cookies))
        assert response.status_code == 400
        assert "location" not in response.headers
    # The refused callbacks didn't use the sign-in up.
    assert await provider.store.get("transaction", transaction_id, Transaction)
    assert (
        await provider.lightdash_callback(request("/oauth/lightdash/callback", {"state": "unknown"}, {cookie: csrf}))
    ).status_code == 400


@respx.mock
async def test_lightdash_errors_reach_the_client_as_standard_codes(provider):
    for error, forwarded in [
        ("access_denied", "access_denied"),
        ("temporarily_unavailable", "temporarily_unavailable"),
        ("invalid_client", "server_error"),
        ("<script>", "server_error"),
        (None, "server_error"),
    ]:
        transaction_id, csrf = await start(provider)
        transaction = await provider.store.get("transaction", transaction_id, Transaction)
        await provider.store.put("transaction", transaction_id, transaction.model_copy(update={"approved": True}))
        query = {"state": transaction_id} | ({"error": error} if error else {})
        response = await provider.lightdash_callback(
            request("/oauth/lightdash/callback", query, {_consent_cookie(transaction_id): csrf})
        )
        assert response.status_code == 302
        assert parse_qs(urlparse(response.headers["location"]).query)["error"] == [forwarded]


@pytest.mark.parametrize(
    "uri",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox",
        "file:///etc/passwd",
        "blob:https://evil.example/x",
        "http://evil.example/callback",
        "http://192.168.1.10/callback",
        "https://good.example@evil.example/callback",
        "https://user:password@evil.example/callback",
        "myapp://user@host/callback",
        "http://localhost:9999/callback#fragment",
        "https://example.com/" + "x" * 3000,
    ],
)
async def test_registration_refuses_unsafe_redirect_uris(provider, uri):
    with pytest.raises(RegistrationError) as error:
        await provider.register_client(client(uri))
    assert error.value.error == "invalid_redirect_uri"
    assert await provider.get_client("client") is None


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost:9999/callback",
        "http://127.0.0.1/callback",
        "http://[::1]:3000/callback",
        "https://claude.ai/api/mcp/auth_callback",
        "myapp://oauth/done",
        "com.example.app:/oauth2redirect",
    ],
)
async def test_registration_accepts_loopback_https_and_app_redirect_uris(provider, uri):
    await provider.register_client(client(uri))
    assert await provider.get_client("client")


async def test_redirect_hosts_restrict_https_redirect_uris(provider):
    provider.settings.redirect_hosts = ["dex.example.com"]
    with pytest.raises(RegistrationError):
        await provider.register_client(client("https://claude.ai/api/mcp/auth_callback"))
    await provider.register_client(client("https://dex.example.com/callback", "http://localhost:9999/callback", "myapp://done"))


async def test_registration_keeps_what_redis_stores_small(provider):
    for oversized in [
        client(client_name="x" * 201),
        client(*[f"http://localhost:{port}/callback" for port in range(11)]),
        client(grant_types=["authorization_code", *("x" * 100 for _ in range(100))]),
    ]:
        with pytest.raises(RegistrationError):
            await provider.register_client(oversized)
    assert await provider.get_client("client") is None

    await provider.register_client(client(logo_uri="https://example.com/logo.png", contacts=["admin@example.com"]))
    stored = await provider.get_client("client")
    assert (stored.client_name, stored.logo_uri, stored.contacts) == ("App", None, None)


async def test_authorize_refuses_oversized_requests(provider):
    for oversized in [params(code_challenge="x" * 4000), params(code_challenge="x" * 42 + "!"), params(state="x" * 1025)]:
        with pytest.raises(AuthorizeError) as error:
            await provider.authorize(client(), oversized)
        assert error.value.error == "invalid_request"
    assert not await provider.store._redis.keys("lightdash-mcp:transaction:*")


@respx.mock
async def test_a_failed_lightdash_sign_in_returns_to_the_client(provider):
    transaction_id, csrf = await start(provider)
    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    await provider.store.put("transaction", transaction_id, transaction.model_copy(update={"approved": True}))
    respx.post(f"{LIGHTDASH}/api/v1/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "only"}))
    response = await provider.lightdash_callback(
        request("/oauth/lightdash/callback", {"state": transaction_id, "code": "c"}, {_consent_cookie(transaction_id): csrf})
    )
    assert parse_qs(urlparse(response.headers["location"]).query)["error"] == ["server_error"]
