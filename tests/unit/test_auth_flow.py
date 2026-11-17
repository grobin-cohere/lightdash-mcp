"""The sign-in flow's refusals: registration, /authorize, the consent page and the Lightdash
callback."""

from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
import respx
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import Response

from lightdash_mcp.auth.provider import (
    MAX_STATE,
    LightdashOAuthProvider,
    Transaction,
    _consent_cookie,
)

from .conftest import LIGHTDASH, REDIRECT, TOKEN_URL, token_response

USER_URL = f"{LIGHTDASH}/api/v1/user"
CONSENT = "/oauth/consent"
CALLBACK = "/oauth/lightdash/callback"


def request(
    path: str,
    query: dict | None = None,
    cookies: dict | None = None,
    form: dict | None = None,
) -> Request:
    headers = []
    has_form = form is not None
    body = urlencode(form or {}).encode()

    if cookies:
        pairs = [f"{name}={value}" for name, value in cookies.items()]
        headers.append((b"cookie", "; ".join(pairs).encode()))

    if has_form:
        headers += [
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode()),
        ]

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    method = "POST" if has_form else "GET"
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": urlencode(query or {}).encode(),
        "headers": headers,
    }

    return Request(scope, receive)


def client(*redirect_uris: str, **fields) -> OAuthClientInformationFull:
    fields = {
        "client_id": "client",
        "client_name": "App",
        "redirect_uris": list(redirect_uris or [REDIRECT]),
        **fields,
    }

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


def query_of(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


async def start(provider: LightdashOAuthProvider) -> tuple[str, str]:
    """A registered client's /authorize. Returns the transaction ID and its CSRF token."""
    await provider.register_client(client())
    location = await provider.authorize(client(), params())
    transaction_id = query_of(location)["transaction"][0]
    transaction = await provider.store.get("transaction", transaction_id, Transaction)

    return transaction_id, transaction.csrf


async def approve(provider: LightdashOAuthProvider, transaction_id: str) -> None:
    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    approved = transaction.model_copy(update={"approved": True})

    await provider.store.put("transaction", transaction_id, approved)


async def submit_consent(
    provider: LightdashOAuthProvider,
    transaction_id: str,
    csrf: str | None,
    cookies: dict,
    action: str = "allow",
) -> Response:
    form = {"transaction": transaction_id, "action": action}

    if csrf:
        form["csrf"] = csrf

    return await provider.consent_submit(request(CONSENT, cookies=cookies, form=form))


async def test_the_consent_form_needs_the_csrf_token_and_the_cookie(provider):
    transaction_id, csrf = await start(provider)
    cookie = _consent_cookie(transaction_id)
    refused = [
        (None, {cookie: csrf}),
        ("wrong", {cookie: csrf}),
        # compare_digest raises TypeError on a non-ASCII str: it must be a 400, not a 500.
        ("é" * 43, {cookie: csrf}),
        (csrf, {}),
        (csrf, {cookie: "wrong"}),
        (csrf, {cookie: "é"}),
        (csrf, {_consent_cookie("another transaction"): csrf}),
    ]

    for form_csrf, cookies in refused:
        response = await submit_consent(provider, transaction_id, form_csrf, cookies)
        transaction = await provider.store.get("transaction", transaction_id, Transaction)

        assert response.status_code == 400, (form_csrf, cookies)
        assert not transaction.approved

    allowed = await submit_consent(provider, transaction_id, csrf, {cookie: csrf})

    assert allowed.status_code == 303
    assert allowed.headers["location"].startswith(f"{LIGHTDASH}/api/v1/oauth/authorize?")


async def test_a_second_load_of_the_consent_page_keeps_the_first_one_working(provider):
    transaction_id, csrf = await start(provider)
    cookies = {_consent_cookie(transaction_id): csrf}

    # A prefetch, or a second tab.
    for _ in range(2):
        page = await provider.consent_page(request(CONSENT, {"transaction": transaction_id}))

        assert f'name="csrf" value="{csrf}"' in page.body.decode()

    response = await submit_consent(provider, transaction_id, csrf, cookies)

    assert response.status_code == 303


async def test_a_large_consent_form_is_refused(provider):
    transaction_id, csrf = await start(provider)
    cookies = {_consent_cookie(transaction_id): csrf}
    form = {
        "transaction": transaction_id,
        "csrf": csrf,
        "action": "allow",
        "padding": "x" * 100_000,
    }

    response = await provider.consent_submit(request(CONSENT, cookies=cookies, form=form))

    assert response.status_code == 413


async def test_the_callback_needs_an_approved_sign_in_and_its_cookie(provider):
    transaction_id, csrf = await start(provider)
    cookie = _consent_cookie(transaction_id)
    query = {"state": transaction_id, "code": "lightdash-code"}

    # Not approved yet, as with a Lightdash link sent before the consent page.
    early = await provider.lightdash_callback(request(CALLBACK, query, {cookie: csrf}))

    assert early.status_code == 400

    await approve(provider, transaction_id)

    for cookies in ({}, {cookie: "wrong"}, {cookie: "é"}):
        response = await provider.lightdash_callback(request(CALLBACK, query, cookies))

        assert response.status_code == 400
        assert "location" not in response.headers

    # The refused callbacks didn't use the sign-in up.
    transaction = await provider.store.get("transaction", transaction_id, Transaction)

    assert transaction

    unknown = request(CALLBACK, {"state": "unknown"}, {cookie: csrf})
    response = await provider.lightdash_callback(unknown)

    assert response.status_code == 400


@respx.mock
async def test_lightdash_errors_reach_the_client_as_standard_codes(provider):
    errors = [
        ("access_denied", "access_denied"),
        ("temporarily_unavailable", "temporarily_unavailable"),
        ("invalid_client", "server_error"),
        ("<script>", "server_error"),
        (None, "server_error"),
    ]

    for error, forwarded in errors:
        transaction_id, csrf = await start(provider)
        await approve(provider, transaction_id)
        cookies = {_consent_cookie(transaction_id): csrf}
        query = {"state": transaction_id}

        if error:
            query["error"] = error

        response = await provider.lightdash_callback(request(CALLBACK, query, cookies))

        assert response.status_code == 302
        assert query_of(response.headers["location"])["error"] == [forwarded]


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

    registered = await provider.get_client("client")
    assert error.value.error == "invalid_redirect_uri"
    assert registered is None


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

    registered = await provider.get_client("client")
    assert registered


async def test_redirect_hosts_restrict_https_redirect_uris(provider):
    provider.settings.redirect_hosts = ["dex.example.com"]
    unlisted = client("https://claude.ai/api/mcp/auth_callback")
    listed = client(
        "https://dex.example.com/callback",
        "http://localhost:9999/callback",
        "myapp://done",
    )

    with pytest.raises(RegistrationError):
        await provider.register_client(unlisted)

    await provider.register_client(listed)


async def test_registration_keeps_what_redis_stores_small(provider):
    many_redirect_uris = [f"http://localhost:{port}/callback" for port in range(11)]
    long_grant_types = ["x" * 100] * 100
    oversized = [
        client(client_name="x" * 201),
        client(*many_redirect_uris),
        client(grant_types=["authorization_code", *long_grant_types]),
    ]
    with_extras = client(logo_uri="https://example.com/logo.png", contacts=["admin@example.com"])

    for too_big in oversized:
        with pytest.raises(RegistrationError):
            await provider.register_client(too_big)

    registered = await provider.get_client("client")
    assert registered is None

    await provider.register_client(with_extras)

    stored = await provider.get_client("client")
    assert stored.client_name == "App"
    assert stored.logo_uri is None
    assert stored.contacts is None


async def test_authorize_refuses_oversized_requests(provider):
    refused = [
        params(code_challenge="x" * 4000),
        params(code_challenge="x" * 42 + "!"),
        params(state="x" * 1025),
    ]

    for authorization in refused:
        with pytest.raises(AuthorizeError) as error:
            await provider.authorize(client(), authorization)

        assert error.value.error == "invalid_request"

    transactions = await provider.store._redis.keys("lightdash-mcp:transaction:*")
    assert not transactions


@respx.mock
async def test_a_failed_lightdash_sign_in_returns_to_the_client(provider):
    transaction_id, csrf = await start(provider)
    await approve(provider, transaction_id)
    without_refresh_token = httpx.Response(200, json={"access_token": "only"})
    respx.post(TOKEN_URL).mock(return_value=without_refresh_token)
    query = {"state": transaction_id, "code": "c"}
    cookies = {_consent_cookie(transaction_id): csrf}

    response = await provider.lightdash_callback(request(CALLBACK, query, cookies))

    assert query_of(response.headers["location"])["error"] == ["server_error"]


async def test_the_consent_page_escapes_the_client_name_and_cannot_be_framed(provider):
    await provider.register_client(client(client_name='<script>x</script>"'))
    location = await provider.authorize(client(), params())
    transaction_id = query_of(location)["transaction"][0]

    page = await provider.consent_page(request(CONSENT, {"transaction": transaction_id}))

    body = page.body.decode()
    cookie = page.headers["set-cookie"].lower()
    assert "<script>x</script>" not in body
    assert "&lt;script&gt;x&lt;/script&gt;&quot;" in body
    assert page.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert page.headers["cache-control"] == "no-store"
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "path=/oauth" in cookie


async def test_a_denied_consent_returns_to_the_client(provider):
    transaction_id, csrf = await start(provider)
    cookie = _consent_cookie(transaction_id)

    response = await submit_consent(provider, transaction_id, csrf, {cookie: csrf}, "deny")

    assert response.status_code == 302

    location = urlparse(response.headers["location"])
    returned_to = f"{location.scheme}://{location.netloc}{location.path}"
    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    deleted = response.headers["set-cookie"].lower()
    assert returned_to == REDIRECT
    assert parse_qs(location.query) == {"error": ["access_denied"], "state": ["client-state"]}
    assert transaction is None
    assert deleted.startswith(f'{cookie}="";')
    assert "max-age=0" in deleted
    assert "path=/oauth" in deleted


async def test_the_consent_page_expires_with_its_client(provider):
    transaction_id, _ = await start(provider)
    await provider.store.delete("client", "client")

    page = await provider.consent_page(request(CONSENT, {"transaction": transaction_id}))

    assert page.status_code == 400
    assert "Sign-in expired" in page.body.decode()
    assert "set-cookie" not in page.headers


@respx.mock
async def test_a_callback_works_once(provider):
    transaction_id, csrf = await start(provider)
    cookies = {_consent_cookie(transaction_id): csrf}
    await submit_consent(provider, transaction_id, csrf, cookies)
    user = httpx.Response(200, json={"results": {"userUuid": "user"}})
    respx.post(TOKEN_URL).mock(return_value=token_response())
    respx.get(USER_URL).mock(return_value=user)
    query = {"state": transaction_id, "code": "lightdash-code"}

    first = await provider.lightdash_callback(request(CALLBACK, query, cookies))
    replayed = await provider.lightdash_callback(request(CALLBACK, query, cookies))

    grants = await provider.store._redis.keys("lightdash-mcp:grant:*")
    assert first.status_code == 302
    assert "code" in query_of(first.headers["location"])
    assert replayed.status_code == 400
    assert "Sign-in expired" in replayed.body.decode()
    assert len(grants) == 1


@pytest.mark.parametrize(
    "user",
    [
        httpx.Response(500),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"results": {}}),
        httpx.Response(200, json=[]),
    ],
)
@respx.mock
async def test_a_sign_in_without_a_lightdash_user_returns_to_the_client(provider, user):
    transaction_id, csrf = await start(provider)
    await approve(provider, transaction_id)
    respx.post(TOKEN_URL).mock(return_value=token_response())
    respx.get(USER_URL).mock(return_value=user)
    query = {"state": transaction_id, "code": "lightdash-code"}
    cookies = {_consent_cookie(transaction_id): csrf}
    callback = request(CALLBACK, query, cookies)

    response = await provider.lightdash_callback(callback)

    grants = await provider.store._redis.keys("lightdash-mcp:grant:*")
    assert response.status_code == 302
    assert query_of(response.headers["location"])["error"] == ["server_error"]
    assert not grants


async def test_authorize_refuses_an_oversized_resource(provider):
    resource = "https://mcp.example.com/" + "x" * MAX_STATE

    with pytest.raises(AuthorizeError) as error:
        await provider.authorize(client(), params(resource=resource))

    transactions = await provider.store._redis.keys("lightdash-mcp:transaction:*")
    assert error.value.error == "invalid_request"
    assert not transactions
