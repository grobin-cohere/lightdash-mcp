import base64
import binascii
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlparse

import uvicorn
from mcp.server.auth.handlers.token import TokenErrorResponse
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialWithJitterBackoff
from redis.exceptions import LockError, RedisError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from lightdash_mcp.auth.audit import clip, clip_arguments, record
from lightdash_mcp.auth.provider import (
    FORM_LIMIT,
    GRANT_BUSY,
    RETRY_ERROR,
    SCOPE,
    LightdashOAuthProvider,
    read_body,
)
from lightdash_mcp.auth.store import REDIS_RETRIES, REDIS_TIMEOUT, Store
from lightdash_mcp.config import Settings
from lightdash_mcp.tools import access, code, content, data, schedulers

SHUTDOWN_TIMEOUT = 3
RETRY_AFTER = 5  # seconds, for a /revoke that Redis or the grant's lock kept from finishing
RETRY_BACKOFF_BASE = 0.01  # seconds before Redis's retry, with jitter
RETRY_BACKOFF_CAP = 1  # second
UNAVAILABLE = "This server's storage didn't answer. Try again in a moment."
# As the SDK's token endpoint answers.
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
INSTRUCTIONS = (
    "Query Lightdash data, and administer it: access, content and deliveries. "
    "Every call runs as the signed-in Lightdash user, with their permissions."
)
LOOPBACK_ALLOWED_HOSTS = ("127.0.0.1:*", "localhost:*", "[::1]:*")
LOOPBACK_ALLOWED_ORIGINS = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")
CREDENTIAL_PATHS = ("/token", "/revoke")
CREDENTIAL_NAMES = ("client_id", "client_secret")
BASIC_PREFIX = "Basic "


def main() -> None:
    settings = Settings()
    settings.check()
    app = asgi_app(settings)

    # Ctrl+C is a normal stop: no traceback. MCP clients keep a stream open, so a stop waits for
    # them at most SHUTDOWN_TIMEOUT seconds instead of until they disconnect.
    try:
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            timeout_graceful_shutdown=SHUTDOWN_TIMEOUT,
        )
    except KeyboardInterrupt:
        pass


def asgi_app(settings: Settings, redis: Redis | None = None) -> ASGIApp:
    server = create_server(settings, redis)
    app = server.streamable_http_app(
        transport_security=transport_security(settings),
        host=settings.host,
    )
    app.add_middleware(TryAgain)

    return BasicAuthClientId(app)


def create_server(settings: Settings, redis: Redis | None = None) -> MCPServer:
    redis = redis or _connect_redis(settings)
    store = Store(redis, settings.fernet_key)
    provider = LightdashOAuthProvider(settings, store)

    @asynccontextmanager
    async def lifespan(_: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await _close(provider, store)

    async def health(_: Request) -> JSONResponse:
        """Up when Redis answers. Lightdash being down doesn't make this server unhealthy."""
        try:
            await store.ping()
        except RedisError:
            return JSONResponse({"status": "Redis unreachable"}, status_code=503)

        return JSONResponse({"status": "ok"})

    server = MCPServer(
        name="lightdash-mcp",
        instructions=INSTRUCTIONS,
        auth_server_provider=provider,
        auth=_auth_settings(settings),
        lifespan=lifespan,
        middleware=[audit],
    )
    server.custom_route("/health", methods=["GET"])(health)
    server.custom_route("/oauth/consent", methods=["GET"])(provider.consent_page)
    server.custom_route("/oauth/consent", methods=["POST"])(provider.consent_submit)
    server.custom_route("/oauth/lightdash/callback", methods=["GET"])(provider.lightdash_callback)

    for tools in (access, content, schedulers, data, code):
        tools.register(server, provider)

    return server


def _connect_redis(settings: Settings) -> Redis:
    backoff = ExponentialWithJitterBackoff(base=RETRY_BACKOFF_BASE, cap=RETRY_BACKOFF_CAP)

    return Redis.from_url(
        settings.redis_url,
        socket_timeout=REDIS_TIMEOUT,
        socket_connect_timeout=REDIS_TIMEOUT,
        # Explicit: without it, from_url's connections don't retry at all.
        retry=Retry(backoff, retries=REDIS_RETRIES),
    )


async def _close(provider: LightdashOAuthProvider, store: Store) -> None:
    """Close the shared HTTP client, then Redis, even when closing the HTTP client fails."""
    try:
        await provider.http.aclose()
    finally:
        await store.close()


def _auth_settings(settings: Settings) -> AuthSettings:
    registration = ClientRegistrationOptions(
        enabled=True,
        valid_scopes=[SCOPE],
        default_scopes=[SCOPE],
    )

    return AuthSettings(
        issuer_url=settings.public_url,
        resource_server_url=f"{settings.public_url}/mcp",
        # Tokens are only issued by this server, for this server.
        validate_token_resource=False,
        client_registration_options=registration,
        revocation_options=RevocationOptions(enabled=True),
    )


async def audit(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    """Log every tool call: who, which tool, with which arguments, and whether it failed."""
    if ctx.method != "tools/call" or not ctx.params:
        return await call_next(ctx)

    call_failed = True  # unless the call returns a result without an error

    try:
        result = await call_next(ctx)
        call_failed = _is_error(result)
        return result
    finally:
        _record_tool_call(ctx.params, call_failed)


def _is_error(result: HandlerResult) -> bool:
    # The result comes as the wire dict, or as a model if a handler returns one.
    if isinstance(result, dict):
        return bool(result.get("isError"))

    return bool(getattr(result, "is_error", False))


def _record_tool_call(params: Mapping[str, Any], call_failed: bool) -> None:
    token = get_access_token()
    user = token.subject if token else None
    tool = clip(params.get("name"))
    arguments = clip_arguments(params.get("arguments") or {})

    record(
        "tool_call",
        user=user,
        tool=tool,
        arguments=arguments,
        error=call_failed,
    )


def transport_security(settings: Settings) -> TransportSecuritySettings:
    """The SDK's localhost defaults, plus PUBLIC_URL's host so requests through a tunnel are
    accepted."""
    public = urlparse(settings.public_url)
    public_origin = f"{public.scheme}://{public.netloc}"

    return TransportSecuritySettings(
        allowed_hosts=[*LOOPBACK_ALLOWED_HOSTS, public.netloc],
        allowed_origins=[*LOOPBACK_ALLOWED_ORIGINS, public_origin],
    )


class TryAgain:
    """Answer Redis failing, or a grant's lock staying busy, in /token or /revoke with an error the
    client can retry.

    The SDK catches only TokenError, and only around the exchanges, which answer a busy lock
    themselves. Redis also runs in the client lookup, the token loads (also from the SDK's Bearer
    middleware) and /token's reuse check of a refresh token. Added as the app's outermost
    middleware, inside its 500 handler, to see all of them. Other paths keep their 500.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        is_credentials_path = scope["type"] == "http" and scope["path"] in CREDENTIAL_PATHS

        if not is_credentials_path:
            return await self.app(scope, receive, send)

        has_response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal has_response_started
            is_start = message["type"] == "http.response.start"
            has_response_started = has_response_started or is_start
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except RedisError as error:  # LockError too
            if has_response_started:
                raise

            response = _try_again(scope["path"], error)
            await response(scope, receive, send)


def _try_again(path: str, error: RedisError) -> Response:
    is_lock_busy = isinstance(error, LockError)

    if not is_lock_busy:
        record("storage_failed", logging.WARNING, path=path, error=type(error).__name__)

    if path == "/token":
        description = GRANT_BUSY if is_lock_busy else UNAVAILABLE
        content = TokenErrorResponse(error=RETRY_ERROR, error_description=description)
        return PydanticJSONResponse(content, status_code=400, headers=NO_STORE)

    # RFC 7009 section 2.2.1: on a 503 the client assumes the token still works, and may try again
    # later. RFC 7009 defines no body for it, and temporarily_unavailable isn't a token endpoint
    # code.
    headers = {**NO_STORE, "Retry-After": str(RETRY_AFTER)}
    return Response(status_code=503, headers=headers)


class BasicAuthClientId:
    """Copy the client ID and secret of a Basic `Authorization` header into a /token or /revoke
    form that lacks them.

    RFC 6749 section 2.3.1 lets a `client_secret_basic` client send its credentials only in the
    header, as Dex does. The MCP SDK's token endpoint also requires `client_id` in the form, and
    its revocation endpoint `client_id` and `client_secret`, and they refuse those requests
    without them. The SDK still checks the secret, from the header for a `client_secret_basic`
    client.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        is_credentials_request = (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"] in CREDENTIAL_PATHS
        )

        if not is_credentials_request:
            return await self.app(scope, receive, send)

        headers = dict(scope["headers"])
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        credentials = _basic_credentials(authorization)

        if not credentials:
            return await self.app(scope, receive, send)

        # Read before the SDK's own body limit applies, so limited here too.
        body = await read_body(Request(scope, receive), FORM_LIMIT)

        if body is None:
            too_large = Response("Request body too large", status_code=413)
            return await too_large(scope, receive, send)

        missing = _missing_credentials(body, credentials)

        if missing:
            body = _add_to_form(body, missing)
            headers[b"content-length"] = str(len(body)).encode()
            scope = {**scope, "headers": list(headers.items())}

        await self.app(scope, _replay(body, receive), send)


def _basic_credentials(authorization: str) -> tuple[str, str] | None:
    if not authorization.startswith(BASIC_PREFIX):
        return None

    encoded = authorization.removeprefix(BASIC_PREFIX)

    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except binascii.Error, UnicodeDecodeError:
        return None

    client_id, separator, secret = decoded.partition(":")

    if not separator or not client_id:
        return None

    return unquote(client_id), unquote(secret)


def _missing_credentials(body: bytes, credentials: tuple[str, str]) -> dict[str, str]:
    form = parse_qs(body.decode("utf-8", "replace"))
    named_credentials = zip(CREDENTIAL_NAMES, credentials)

    return {name: value for name, value in named_credentials if name not in form}


def _add_to_form(body: bytes, fields: dict[str, str]) -> bytes:
    separator = b"&" if body else b""
    encoded_fields = urlencode(fields).encode()

    return body + separator + encoded_fields


def _replay(body: bytes, receive: Receive) -> Receive:
    was_replayed = False

    async def replay() -> Message:
        nonlocal was_replayed

        if was_replayed:
            return await receive()

        was_replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return replay


if __name__ == "__main__":
    main()
