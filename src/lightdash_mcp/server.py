import base64
import binascii
from collections.abc import AsyncIterator
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
from redis.exceptions import LockError, RedisError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from lightdash_mcp.auth.audit import clip, clip_arguments, record
from lightdash_mcp.auth.provider import FORM_LIMIT, GRANT_BUSY, RETRY_ERROR, SCOPE, LightdashOAuthProvider, read_body
from lightdash_mcp.auth.store import Store
from lightdash_mcp.config import Settings
from lightdash_mcp.tools import access, code, content, data, schedulers

SHUTDOWN_TIMEOUT = 3
REDIS_TIMEOUT = 5  # seconds: a Redis that stops answering fails a request instead of hanging it
RETRY_AFTER = 5  # seconds, for a /revoke that found the grant's lock busy
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}  # as the SDK's token endpoint answers


async def audit(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    """Log every tool call: who, which tool, with which arguments, and whether it failed."""
    if ctx.method != "tools/call" or not ctx.params:
        return await call_next(ctx)
    failed = True  # unless the call returns a result without an error
    try:
        result = await call_next(ctx)
        # The result comes as the wire dict, or as a model if a handler returns one.
        failed = bool(result.get("isError") if isinstance(result, dict) else getattr(result, "is_error", False))
        return result
    finally:
        token = get_access_token()
        record(
            "tool_call",
            user=token.subject if token else None,
            tool=clip(ctx.params.get("name")),
            arguments=clip_arguments(ctx.params.get("arguments") or {}),
            error=failed,
        )


def create_server(settings: Settings, redis: Redis | None = None) -> MCPServer:
    redis = redis or Redis.from_url(settings.redis_url, socket_timeout=REDIS_TIMEOUT, socket_connect_timeout=REDIS_TIMEOUT)
    store = Store(redis, settings.fernet_key)
    provider = LightdashOAuthProvider(settings, store)

    @asynccontextmanager
    async def lifespan(_: MCPServer) -> AsyncIterator[None]:
        try:
            yield
        finally:
            try:
                await provider.http.aclose()
            finally:
                await store.close()

    server = MCPServer(
        name="lightdash-mcp",
        instructions="Query Lightdash data, and administer it: access, content and deliveries. "
        "Every call runs as the signed-in Lightdash user, with their permissions.",
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=settings.public_url,
            resource_server_url=f"{settings.public_url}/mcp",
            # Tokens are only issued by this server, for this server.
            validate_token_resource=False,
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        ),
        lifespan=lifespan,
        middleware=[audit],
    )

    async def health(_: Request) -> JSONResponse:
        """Up when Redis answers. Lightdash being down doesn't make this server unhealthy."""
        try:
            await store.ping()
        except RedisError:
            return JSONResponse({"status": "Redis unreachable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    server.custom_route("/health", methods=["GET"])(health)
    server.custom_route("/oauth/consent", methods=["GET"])(provider.consent_page)
    server.custom_route("/oauth/consent", methods=["POST"])(provider.consent_submit)
    server.custom_route("/oauth/lightdash/callback", methods=["GET"])(provider.lightdash_callback)
    for tools in (access, content, schedulers, data, code):
        tools.register(server, provider)
    return server


class BasicAuthClientId:
    """Copy the client ID and secret of a Basic `Authorization` header into a /token or /revoke form that lacks them.

    RFC 6749 section 2.3.1 lets a `client_secret_basic` client send its credentials only in the header, as Dex
    does. The MCP SDK's token endpoint also requires `client_id` in the form, and its revocation
    endpoint `client_id` and `client_secret`, and they refuse those requests without them. The SDK still checks
    the secret, from the header for a `client_secret_basic` client.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in ("/token", "/revoke"):
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        credentials = _basic_credentials(headers.get(b"authorization", b"").decode("latin-1"))
        if not credentials:
            return await self.app(scope, receive, send)
        # Read before the SDK's own body limit applies, so limited here too.
        body = await read_body(Request(scope, receive), FORM_LIMIT)
        if body is None:
            return await Response("Request body too large", status_code=413)(scope, receive, send)
        form = parse_qs(body.decode("utf-8", "replace"))
        missing = {name: value for name, value in zip(("client_id", "client_secret"), credentials) if name not in form}
        if missing:
            body += (b"&" if body else b"") + urlencode(missing).encode()
            headers[b"content-length"] = str(len(body)).encode()
            scope = {**scope, "headers": list(headers.items())}
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


def _basic_credentials(authorization: str) -> tuple[str, str] | None:
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
    except binascii.Error, UnicodeDecodeError:
        return None
    client_id, separator, secret = decoded.partition(":")
    return (unquote(client_id), unquote(secret)) if separator and client_id else None


async def busy(request: Request, error: Exception) -> Response:
    """A grant's lock stayed busy where the SDK catches no error: in /revoke, and in /token's reuse check of a refresh
    token, which ends the grant. The exchanges themselves answer a busy lock with a TokenError."""
    if request.url.path == "/token":
        content = TokenErrorResponse(error=RETRY_ERROR, error_description=GRANT_BUSY)
        return PydanticJSONResponse(content, status_code=400, headers=NO_STORE)
    if request.url.path == "/revoke":
        # RFC 7009 section 2.2.1: on a 503 the client assumes the token still works, and may try again later.
        return Response(status_code=503, headers={**NO_STORE, "Retry-After": str(RETRY_AFTER)})
    raise error


def asgi_app(settings: Settings, redis: Redis | None = None) -> ASGIApp:
    app = create_server(settings, redis).streamable_http_app(transport_security=transport_security(settings), host=settings.host)
    app.add_exception_handler(LockError, busy)
    return BasicAuthClientId(app)


def transport_security(settings: Settings) -> TransportSecuritySettings:
    """The SDK's localhost defaults, plus PUBLIC_URL's host so requests through a tunnel are accepted."""
    public = urlparse(settings.public_url)
    return TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", public.netloc],
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*", f"{public.scheme}://{public.netloc}"],
    )


def main() -> None:
    settings = Settings()
    settings.check()
    app = asgi_app(settings)
    # Ctrl+C is a normal stop: no traceback. MCP clients keep a stream open, so a stop waits for them
    # at most SHUTDOWN_TIMEOUT seconds instead of until they disconnect.
    try:
        uvicorn.run(app, host=settings.host, port=settings.port, timeout_graceful_shutdown=SHUTDOWN_TIMEOUT)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
