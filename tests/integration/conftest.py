"""Runs against the local Lightdash from `make dev` (http://localhost:8080) and Redis (db 15).

The server runs in a thread on PUBLIC_PORT. Sign-in goes through the whole chain: client
registration, authorize, consent page, Lightdash login and consent, callback, token.

CI (`dagger check`) sets INTEGRATION_LIGHTDASH_URL and INTEGRATION_REDIS_URL to its own
services. Then the tests wait for Lightdash to start, and fail instead of skipping when it
doesn't.
"""

import html
import os
import re
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import httpx2
import pytest
import uvicorn
from cryptography.fernet import Fernet
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from redis.asyncio import Redis

from lightdash_mcp.auth.provider import _challenge
from lightdash_mcp.config import Settings
from lightdash_mcp.server import asgi_app

LIGHTDASH = os.environ.get("INTEGRATION_LIGHTDASH_URL", "http://localhost:8080")
REDIS_URL = os.environ.get("INTEGRATION_REDIS_URL", "redis://localhost:6379/15")
REQUIRED = "INTEGRATION_LIGHTDASH_URL" in os.environ
# Seconds. A fresh Lightdash seeds its demo data and migrates before it answers.
STARTUP_TIMEOUT = 900
STARTUP_INTERVAL = 5
PUBLIC_PORT = 8765
PUBLIC = f"http://localhost:{PUBLIC_PORT}"
CLIENT_REDIRECT = "http://localhost:9999/callback"
PASSWORD = "demo_password!"
ADMIN = "demo@lightdash.com"
EDITOR = "demo2@lightdash.com"
VIEWER = "demo3@lightdash.com"

SERVER_START_CHECKS = 100
SERVER_START_INTERVAL = 0.05

CONSENT_FIELD = re.compile(r'name="(transaction|csrf)" value="([^"]*)"')
HIDDEN_INPUT = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')
REFRESH_URL = re.compile(r'url=([^"]+)"')


def is_lightdash_running() -> bool:
    try:
        response = httpx.get(f"{LIGHTDASH}/api/v1/health", timeout=3)
    except httpx.HTTPError:
        return False

    return response.is_success


def wait_for_lightdash() -> None:
    """Exits the test run when Lightdash doesn't start in STARTUP_TIMEOUT seconds."""
    deadline = time.monotonic() + STARTUP_TIMEOUT

    while not is_lightdash_running():
        if time.monotonic() > deadline:
            message = f"Lightdash at {LIGHTDASH} didn't start in {STARTUP_TIMEOUT} seconds"
            pytest.exit(message, returncode=1)

        time.sleep(STARTUP_INTERVAL)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if REQUIRED:
        wait_for_lightdash()
        return

    if is_lightdash_running():
        return

    skip = pytest.mark.skip(reason="Lightdash is not running: make dev")
    integration_items = [item for item in items if "integration" in str(item.path)]

    for item in integration_items:
        item.add_marker(skip)


@pytest.fixture(scope="session")
def settings() -> Settings:
    registration = {
        "client_name": "lightdash-mcp-tests",
        "redirect_uris": [f"{PUBLIC}/oauth/lightdash/callback"],
        "scope": "read write",
    }
    registered = httpx.post(f"{LIGHTDASH}/api/v1/oauth/register", json=registration).json()

    return Settings(
        _env_file=None,
        lightdash_url=LIGHTDASH,
        lightdash_client_id=registered["client_id"],
        lightdash_client_secret=registered["client_secret"],
        public_url=PUBLIC,
        fernet_key=Fernet.generate_key().decode(),
        redis_url=REDIS_URL,
        port=PUBLIC_PORT,
    )


def wait_until_started(instance: uvicorn.Server) -> None:
    for _ in range(SERVER_START_CHECKS):
        if instance.started:
            return

        time.sleep(SERVER_START_INTERVAL)


@pytest.fixture(scope="session")
def server(settings: Settings):
    app = asgi_app(settings, Redis.from_url(settings.redis_url))
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=PUBLIC_PORT,
        log_level="warning",
    )
    instance = uvicorn.Server(config)
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    wait_until_started(instance)

    yield PUBLIC

    instance.should_exit = True
    thread.join(5)


def register_client(server: str, name: str = "test client") -> dict[str, Any]:
    response = httpx.post(
        f"{server}/register",
        json={
            "client_name": name,
            "redirect_uris": [CLIENT_REDIRECT],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    response.raise_for_status()

    return response.json()


def start(
    browser: httpx.Client,
    server: str,
    client: dict[str, Any],
    verifier: str,
) -> httpx.Response:
    """The MCP client's /authorize, opened in the browser. Returns the consent page."""
    authorize = browser.get(
        f"{server}/authorize",
        params={
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": CLIENT_REDIRECT,
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
            "state": "client-state",
            "resource": f"{server}/mcp",
        },
    )

    return browser.get(authorize.headers["location"])


def allow(browser: httpx.Client, consent: httpx.Response) -> httpx.Response:
    """Clicks Continue on the consent page. Returns the redirect to Lightdash."""
    fields = dict(CONSENT_FIELD.findall(consent.text))

    return browser.post(consent.url, data={**fields, "action": "allow"})


def lightdash_sign_in(browser: httpx.Client, email: str, to_lightdash: httpx.Response) -> str:
    """Signs in to Lightdash and approves.

    Returns the callback URL Lightdash sends the browser to.
    """
    login = browser.post(
        f"{LIGHTDASH}/api/v1/login",
        json={"email": email, "password": PASSWORD},
    )
    login.raise_for_status()

    page = browser.get(to_lightdash.headers["location"])
    hidden = {name: html.unescape(value) for name, value in HIDDEN_INPUT.findall(page.text)}
    redirect = browser.post(
        f"{LIGHTDASH}/api/v1/oauth/authorize",
        data={**hidden, "approve": "true"},
    )
    callback_url = REFRESH_URL.search(redirect.text).group(1)

    return html.unescape(callback_url)


def authorize(server: str, email: str, client: dict[str, Any]) -> tuple[str, str]:
    """The MCP client's authorization, with the user's clicks done over HTTP.

    Returns the code and PKCE verifier.
    """
    verifier = secrets.token_urlsafe(48)

    with httpx.Client(follow_redirects=False, timeout=30) as browser:
        consent = start(browser, server, client, verifier)
        to_lightdash = allow(browser, consent)
        callback_url = lightdash_sign_in(browser, email, to_lightdash)
        to_client = browser.get(callback_url)

    query = parse_qs(urlparse(to_client.headers["location"]).query)
    assert query["state"] == ["client-state"], query

    return query["code"][0], verifier


def exchange(
    server: str,
    client: dict[str, Any],
    code: str,
    verifier: str,
) -> httpx.Response:
    return httpx.post(
        f"{server}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CLIENT_REDIRECT,
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "code_verifier": verifier,
            "resource": f"{server}/mcp",
        },
    )


def sign_in(server: str, email: str, client: dict[str, Any] | None = None) -> dict[str, Any]:
    """Registration, authorization and token exchange. Returns the token response."""
    client = client or register_client(server)
    code, verifier = authorize(server, email, client)
    token = exchange(server, client, code, verifier)
    token.raise_for_status()

    return {**token.json(), "client": client}


async def call(
    server: str,
    access_token: str,
    tool: str,
    arguments: dict[str, Any] | None = None,
):
    headers = {"Authorization": f"Bearer {access_token}"}
    http = httpx2.AsyncClient(headers=headers, timeout=120)
    transport = streamable_http_client(f"{server}/mcp", http_client=http)

    async with Client(transport) as client:
        return await client.call_tool(tool, arguments or {})


@pytest.fixture(scope="session")
def admin(server: str) -> dict[str, Any]:
    return sign_in(server, ADMIN)


@pytest.fixture(scope="session")
def viewer(server: str) -> dict[str, Any]:
    return sign_in(server, VIEWER)


@pytest.fixture(scope="session")
def lightdash_admin() -> httpx.Client:
    """Lightdash REST as the admin, with a session cookie, to set up and check test data."""
    client = httpx.Client(base_url=LIGHTDASH, timeout=60)
    login = client.post("/api/v1/login", json={"email": ADMIN, "password": PASSWORD})
    login.raise_for_status()

    return client


@pytest.fixture(scope="session")
def project_uuid(lightdash_admin: httpx.Client) -> str:
    projects = lightdash_admin.get("/api/v1/org/projects").json()["results"]

    return projects[0]["projectUuid"]


@pytest.fixture(scope="session")
def tool(server: str):
    """Calls a tool as the holder of an access token."""

    async def run(token: dict[str, Any], name: str, arguments: dict[str, Any] | None = None):
        return await call(server, token["access_token"], name, arguments)

    return run
