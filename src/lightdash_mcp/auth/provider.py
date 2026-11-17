"""LightdashOAuthProvider: the MCP server's own OAuth server, proxying sign-in to Lightdash.

MCP clients register here and get this server's tokens. Each sign-in is a grant that holds
the user's Lightdash tokens, encrypted in Redis. Tools call Lightdash with the grant's token,
refreshed under a lock so a rotated refresh token is never used twice.
"""

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import time
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import parse_qsl, urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, BaseModel, Field
from redis.exceptions import LockError, RedisError
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from lightdash_mcp.auth import pages
from lightdash_mcp.auth.audit import clip, record
from lightdash_mcp.auth.store import LOCK_TIMEOUT, REDIS_COMMAND_TIMEOUT, Store, digest
from lightdash_mcp.config import LOOPBACK_HOSTS, Settings

SCOPE = "lightdash"
LIGHTDASH_SCOPE = "read write"
TRANSACTION_TTL = 10 * 60
CODE_TTL = 5 * 60
ACCESS_TTL = 60 * 60
REFRESH_TTL = 14 * 24 * 60 * 60  # Lightdash's refresh-token lifetime
GRANT_LIFETIME = 90 * 24 * 60 * 60  # then the user signs in again, however often the client refreshes
REFRESH_MARGIN = 60
# A refresh ends while it still holds the grant's lock: under it, Redis takes the lock, reads the grant, saves the new
# Lightdash tokens and writes the new tokens (or ends the grant: two commands too).
REFRESH_TIMEOUT = LOCK_TIMEOUT - 4 * REDIS_COMMAND_TIMEOUT
CLIENT_TTL = 30 * 24 * 60 * 60  # renewed on each token exchange: registration is open, so unused clients must expire
CONSENT_COOKIE = "lightdash_mcp_consent"  # one per transaction, suffixed with its digest
FORM_LIMIT = 64 * 1024  # bytes of a form body: /token, /revoke and the consent page

# Registration and /authorize are open to anyone, and what they get is kept in Redis: keep it small.
MAX_CLIENT_NAME = 200
MAX_REDIRECT_URIS = 10
MAX_REDIRECT_URI = 2000
MAX_CLIENT_RECORD = 8 * 1024
MAX_STATE = 1024
UNUSED_CLIENT_FIELDS = (
    "client_uri",
    "logo_uri",
    "contacts",
    "tos_uri",
    "policy_uri",
    "jwks_uri",
    "jwks",
    "software_id",
    "software_version",
)
S256_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
# Script and local-content schemes: never a place to send an authorization code.
BLOCKED_SCHEMES = ("javascript", "data", "vbscript", "file", "blob")
# Lightdash errors the client can act on. The others are about this server's request to Lightdash.
FORWARDED_ERRORS = ("access_denied", "temporarily_unavailable")
# The token endpoint's answer to a failure the client can retry, with the same refresh token or code. RFC 6749 has no
# server_error for it, and the SDK accepts no code outside RFC 6749's: invalid_request is the one that says nothing
# about the grant or the client. invalid_grant would end the client's session, invalid_client its registration.
RETRY_ERROR = "invalid_request"
GRANT_BUSY = "Another request is refreshing or ending this sign-in. Try again in a moment."


class SignInRequired(Exception):
    """The user's Lightdash sign-in ended: they must reconnect."""


class RefreshFailed(Exception):
    """Lightdash couldn't refresh the sign-in for now. The grant is kept: try again later."""


class Transaction(BaseModel):
    """A pending authorization, from the client's request to the Lightdash callback."""

    client_id: str
    params: AuthorizationParams
    verifier: str
    csrf: str
    approved: bool = False


class Grant(BaseModel):
    """One sign-in: the user's Lightdash tokens and this server's current code and tokens for it."""

    client_id: str
    subject: str
    access_token: str
    refresh_token: str
    expires_at: float
    created_at: float = Field(default_factory=time.time)
    code_digest: str = ""
    access_digest: str = ""
    refresh_digest: str = ""


class LightdashTokens(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: float = ACCESS_TTL


class Code(AuthorizationCode):
    grant_id: str


class Access(AccessToken):
    grant_id: str


class Refresh(RefreshToken):
    grant_id: str


class Rotated(BaseModel):
    """A refresh token already exchanged: presented again, it was copied."""

    client_id: str
    grant_id: str


def _consent_cookie(transaction_id: str) -> str:
    return f"{CONSENT_COOKIE}_{digest(transaction_id)[:16]}"


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class LightdashOAuthProvider:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        # Shared by every user's Lightdash client, which set their own timeout. It keeps no cookies: one set
        # by a response to one user would go out with the next user's requests.
        self.http = httpx.AsyncClient(
            base_url=settings.lightdash_url, timeout=30, cookies=CookieJar(DefaultCookiePolicy(allowed_domains=[]))
        )

    # Client registration

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self.store.get("client", client_id, OAuthClientInformationFull)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if len(client_info.client_name or "") > MAX_CLIENT_NAME:
            raise RegistrationError("invalid_client_metadata", f"client_name is longer than {MAX_CLIENT_NAME} characters")
        redirect_uris = client_info.redirect_uris or []
        if len(redirect_uris) > MAX_REDIRECT_URIS:
            raise RegistrationError("invalid_redirect_uri", f"At most {MAX_REDIRECT_URIS} redirect URIs")
        for uri in redirect_uris:
            if problem := self._redirect_problem(uri):
                raise RegistrationError("invalid_redirect_uri", f"{clip(str(uri))}: {problem}")
        client = client_info.model_copy(update=dict.fromkeys(UNUSED_CLIENT_FIELDS))
        if len(client.model_dump_json()) > MAX_CLIENT_RECORD:
            raise RegistrationError("invalid_client_metadata", "Client metadata is too large")
        await self.store.put("client", client.client_id, client, CLIENT_TTL)
        record(
            "client_registered",
            client_id=client.client_id,
            client_name=client.client_name,
            redirect_uris=[clip(str(uri)) for uri in redirect_uris],
        )

    def _redirect_problem(self, uri: AnyUrl) -> str | None:
        """Why a client may not register this redirect URI, if it may not (RFC 8252 for native apps)."""
        if len(str(uri)) > MAX_REDIRECT_URI:
            return f"longer than {MAX_REDIRECT_URI} characters"
        if uri.username is not None or uri.password is not None:
            return "a user name or password in a redirect URI hides its real host"
        if uri.fragment is not None:
            return "a redirect URI can't have a fragment"
        if uri.scheme == "http" and uri.host not in LOOPBACK_HOSTS:
            return "http is allowed for localhost, 127.0.0.1 and [::1] only: use https"
        if uri.scheme == "https" and self.settings.redirect_hosts and uri.host not in self.settings.redirect_hosts:
            return "this server accepts https redirect URIs on the hosts in REDIRECT_HOSTS only"
        if uri.scheme in BLOCKED_SCHEMES:
            return f"{uri.scheme}: URIs are not allowed"
        return None

    # Authorization: client -> consent page -> Lightdash -> callback -> client

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not S256_CHALLENGE.match(params.code_challenge):
            raise AuthorizeError("invalid_request", "code_challenge must be an S256 challenge: 43 base64url characters")
        if len(params.state or "") > MAX_STATE or len(params.resource or "") > MAX_STATE:
            raise AuthorizeError("invalid_request", f"state and resource are limited to {MAX_STATE} characters")
        transaction_id = secrets.token_urlsafe(32)
        # The CSRF token is made once: a prefetch or a second tab of the consent page must not change it.
        transaction = Transaction(
            client_id=client.client_id, params=params, verifier=secrets.token_urlsafe(48), csrf=secrets.token_urlsafe(32)
        )
        await self.store.put("transaction", transaction_id, transaction, TRANSACTION_TTL)
        return f"{self.settings.public_url}/oauth/consent?{urlencode({'transaction': transaction_id})}"

    async def consent_page(self, request: Request) -> Response:
        transaction_id = request.query_params.get("transaction", "")
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        client = transaction and await self.get_client(transaction.client_id)
        # Once approved, the consent page no longer opens: its cookie names the only browser that can finish the sign-in.
        if not transaction or transaction.approved or not client:
            return pages.expired()

        redirect_uri = transaction.params.redirect_uri
        response = pages.consent(
            client.client_name or client.client_id,
            str(redirect_uri),
            self._redirect_warning(redirect_uri),
            transaction_id,
            transaction.csrf,
        )
        response.set_cookie(
            _consent_cookie(transaction_id),
            transaction.csrf,
            max_age=TRANSACTION_TTL,
            path="/oauth",
            httponly=True,
            samesite="lax",
            secure=self._secure(request),
        )
        return response

    def _redirect_warning(self, uri: AnyUrl) -> str | None:
        if uri.scheme not in ("http", "https"):
            return "This address opens an app on this device. Continue only if you started this sign-in from that app."
        if uri.host in LOOPBACK_HOSTS or uri.host in self.settings.redirect_hosts:
            return None
        return (
            f"This address is a website, not an app on this computer: whoever runs {uri.host} gets access to Lightdash "
            "as you. Continue only if you started this sign-in and trust that site."
        )

    def _secure(self, request: Request) -> bool:
        """Behind a tunnel or proxy the request may look like plain HTTP: PUBLIC_URL says what browsers use."""
        return self.settings.public_url.startswith("https://") or request.url.scheme == "https"

    async def consent_submit(self, request: Request) -> Response:
        body = await read_body(request, FORM_LIMIT)
        if body is None:
            return pages.page("Request too large", "<p>Start again from your MCP client.</p>", status=413)
        form = dict(parse_qsl(body.decode("utf-8", "replace")))
        transaction_id = form.get("transaction", "")
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        if (
            not transaction
            or not _same(transaction.csrf, form.get("csrf", ""))
            or not _same(transaction.csrf, request.cookies.get(_consent_cookie(transaction_id), ""))
        ):
            return pages.expired()

        allowed = form.get("action") == "allow"
        record("consent", client_id=transaction.client_id, decision="allow" if allowed else "deny")
        if not allowed:
            await self.store.delete("transaction", transaction_id)
            response = _redirect_to_client(transaction, error="access_denied")
            response.delete_cookie(_consent_cookie(transaction_id), path="/oauth", secure=self._secure(request))
            return response

        transaction.approved = True
        await self.store.put("transaction", transaction_id, transaction, TRANSACTION_TTL)

        query = {
            "response_type": "code",
            "client_id": self.settings.lightdash_client_id,
            "redirect_uri": self.settings.callback_url,
            "scope": LIGHTDASH_SCOPE,
            "state": transaction_id,
            "code_challenge": _challenge(transaction.verifier),
            "code_challenge_method": "S256",
        }
        # The consent cookie stays until the callback: it ties the sign-in to this browser.
        return RedirectResponse(f"{self.settings.lightdash_url}/api/v1/oauth/authorize?{urlencode(query)}", 303)

    async def lightdash_callback(self, request: Request) -> Response:
        transaction_id = request.query_params.get("state", "")
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        # Only the browser that approved the consent page can finish the sign-in, so a Lightdash link
        # taken from someone else's consent can't send this user's code to their client.
        if (
            not transaction
            or not transaction.approved
            or not _same(transaction.csrf, request.cookies.get(_consent_cookie(transaction_id), ""))
            or not await self.store.pop("transaction", transaction_id, Transaction)
        ):
            return pages.expired("Start again from your MCP client, in this browser.")

        response = await self._finish_sign_in(transaction, request.query_params.get("code"), request.query_params.get("error"))
        response.delete_cookie(_consent_cookie(transaction_id), path="/oauth", secure=self._secure(request))
        return response

    async def _finish_sign_in(self, transaction: Transaction, code: str | None, error: str | None) -> Response:
        if error or not code:
            return _redirect_to_client(transaction, error=error if error in FORWARDED_ERRORS else "server_error")
        try:
            grant = await self._sign_in_to_lightdash(transaction, code)
        except httpx.HTTPError, ValueError, KeyError, TypeError:
            record("sign_in_failed", logging.WARNING, client_id=transaction.client_id)
            return _redirect_to_client(transaction, error="server_error", description="Lightdash sign-in failed")

        grant_id, code = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
        grant.code_digest = digest(code)
        params = transaction.params
        await self.store.write(
            put=[
                # Kept for REFRESH_TTL once the client exchanges its code (_issue), so an unused sign-in expires soon.
                ("grant", grant_id, grant, TRANSACTION_TTL),
                (
                    "code",
                    digest(code),
                    Code(
                        code=code,
                        scopes=params.scopes or [],
                        expires_at=time.time() + CODE_TTL,
                        client_id=transaction.client_id,
                        code_challenge=params.code_challenge,
                        redirect_uri=params.redirect_uri,
                        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                        resource=params.resource,
                        subject=grant.subject,
                        grant_id=grant_id,
                    ),
                    CODE_TTL,
                ),
            ]
        )
        record("grant_created", grant=grant_id, subject=grant.subject, client_id=grant.client_id)
        return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state), 302)

    async def _sign_in_to_lightdash(self, transaction: Transaction, code: str) -> Grant:
        response = await self.http.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.callback_url,
                "client_id": self.settings.lightdash_client_id,
                "client_secret": self.settings.lightdash_client_secret,
                "code_verifier": transaction.verifier,
            },
        )
        response.raise_for_status()
        tokens = LightdashTokens.model_validate_json(response.content)
        user = await self.http.get("/api/v1/user", headers={"Authorization": f"Bearer {tokens.access_token}"})
        user.raise_for_status()
        return Grant(
            client_id=transaction.client_id,
            subject=user.json()["results"]["userUuid"],
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_at=time.time() + tokens.expires_in,
        )

    # Tokens. Each one is valid only while its grant points back to it, so a record copied in Redis is refused.

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> Code | None:
        code = await self.store.get("code", digest(authorization_code), Code)
        if not code or not _same(code.code, authorization_code) or code.client_id != client.client_id:
            return None
        grant = await self.store.get("grant", code.grant_id, Grant)
        return code if grant and grant.code_digest == digest(authorization_code) and grant.client_id == client.client_id else None

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: Code) -> OAuthToken:
        grant_id = authorization_code.grant_id
        try:
            async with self.store.lock("grant", grant_id):
                if not await self.store.pop("code", digest(authorization_code.code), Code):
                    raise TokenError("invalid_grant", "Authorization code already used")
                grant = await self.store.get("grant", grant_id, Grant)
                if not grant or grant.code_digest != digest(authorization_code.code):
                    raise TokenError("invalid_grant", "Sign-in ended")
                tokens = await self._issue(grant_id, grant, authorization_code.scopes, authorization_code.resource)
        except LockError:
            # Only taking the lock raises it (Store.lock), so nothing under it has run: the code isn't used yet.
            raise TokenError(RETRY_ERROR, GRANT_BUSY) from None
        await self._renew_client(client)
        return tokens

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> Refresh | None:
        token_digest = digest(refresh_token)
        token = await self.store.get("refresh", token_digest, Refresh)
        if token and _same(token.token, refresh_token) and token.client_id == client.client_id:
            grant = await self.store.get("grant", token.grant_id, Grant)
            return token if grant and grant.refresh_digest == token_digest and grant.client_id == client.client_id else None
        rotated = await self.store.get("rotated", token_digest, Rotated)
        if rotated and rotated.client_id == client.client_id:
            # A refresh token works once: seen again after its exchange, it was copied. End the sign-in for every copy.
            await self.end_grant(rotated.grant_id, "refresh_token_reused", revoke_upstream=True)
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: Refresh, scopes: list[str]
    ) -> OAuthToken:
        # Under the grant's lock from start to end, so a revocation waits for it, and the old refresh token is
        # replaced only when the new tokens are written: on any failure, the client can retry with it.
        grant_id = refresh_token.grant_id
        try:
            async with self.store.lock("grant", grant_id):
                grant = await self.store.get("grant", grant_id, Grant)
                if not grant or grant.refresh_digest != digest(refresh_token.token):
                    raise TokenError("invalid_grant", "Refresh token already used")
                try:
                    # Keeps the Lightdash sign-in alive as long as the client's, and catches a revoked one now.
                    await self._refresh_lightdash(grant_id, grant)
                except SignInRequired:
                    raise TokenError("invalid_grant", "Lightdash sign-in ended") from None
                except RefreshFailed as error:
                    raise TokenError(RETRY_ERROR, str(error)) from None
                tokens = await self._issue(grant_id, grant, scopes or refresh_token.scopes, refresh_token.resource)
        except LockError:
            raise TokenError(RETRY_ERROR, GRANT_BUSY) from None
        await self._renew_client(client)
        return tokens

    async def _renew_client(self, client: OAuthClientInformationFull) -> None:
        """Extends the client registration's expiry. The tokens are issued by then: a Redis failure only skips it."""
        try:
            await self.store.touch("client", client.client_id, CLIENT_TTL)
        except RedisError:
            pass

    async def load_access_token(self, token: str) -> Access | None:
        access = await self.store.get("access", digest(token), Access)
        if not access or not _same(access.token, token) or (access.expires_at and access.expires_at < time.time()):
            return None
        grant = await self.store.get("grant", access.grant_id, Grant)
        return access if grant and grant.access_digest == digest(token) and grant.client_id == access.client_id else None

    async def revoke_token(self, token: Access | Refresh) -> None:
        try:
            await self.end_grant(token.grant_id, "revoked", revoke_upstream=True, revoked=token)
        except LockError:  # only taking the lock raises it (Store.lock): nothing is revoked
            record("revoke_busy", logging.WARNING, grant=token.grant_id, subject=token.subject, client_id=token.client_id)
            raise

    async def _issue(self, grant_id: str, grant: Grant, scopes: list[str], resource: str | None) -> OAuthToken:
        """New tokens for the grant, written with it in one step. The caller holds the grant's lock."""
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        common = {"client_id": grant.client_id, "scopes": scopes, "resource": resource, "subject": grant.subject}
        access_ttl, refresh_ttl = _grant_ttl(grant, self.settings.access_token_ttl), _grant_ttl(grant)
        now = int(time.time())
        put: list[tuple[str, str, BaseModel, int]] = [
            (
                "access",
                digest(access),
                Access(token=access, expires_at=now + access_ttl, grant_id=grant_id, **common),
                access_ttl,
            ),
            (
                "refresh",
                digest(refresh),
                Refresh(token=refresh, expires_at=now + refresh_ttl, grant_id=grant_id, **common),
                refresh_ttl,
            ),
        ]
        if grant.refresh_digest:
            put.append(("rotated", grant.refresh_digest, Rotated(client_id=grant.client_id, grant_id=grant_id), REFRESH_TTL))
        delete = [("access", grant.access_digest), ("refresh", grant.refresh_digest)]
        grant.access_digest, grant.refresh_digest = digest(access), digest(refresh)
        put.append(("grant", grant_id, grant, refresh_ttl))
        await self.store.write(put, delete)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=access_ttl,
            refresh_token=refresh,
            scope=" ".join(scopes) or None,
        )

    # Lightdash tokens

    async def lightdash_token(self, grant_id: str, refused: str | None = None) -> str:
        """The grant's Lightdash access token, refreshed first if it is about to expire or Lightdash `refused` it.

        Requests refused with the same token refresh it once: the others get the token it was replaced with.
        """
        grant = await self.store.get("grant", grant_id, Grant)
        if not grant:
            raise SignInRequired
        if _usable(grant, refused):
            return grant.access_token

        async with self.store.lock("grant", grant_id):
            grant = await self.store.get("grant", grant_id, Grant)
            if not grant:
                raise SignInRequired
            if _usable(grant, refused):
                return grant.access_token  # refreshed meanwhile by another request
            return await self._refresh_lightdash(grant_id, grant)

    async def _refresh_lightdash(self, grant_id: str, grant: Grant) -> str:
        """Refreshes the grant's Lightdash tokens and saves them. The caller holds the grant's lock."""
        # Its TTL ends the grant at its lifetime, give or take a second: past it, don't renew it upstream.
        if time.time() >= grant.created_at + GRANT_LIFETIME:
            await self._end_grant(grant_id, "lifetime_ended")
            raise SignInRequired
        try:
            async with asyncio.timeout(REFRESH_TIMEOUT):
                response = await self.http.post(
                    "/api/v1/oauth/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": grant.refresh_token,
                        "client_id": self.settings.lightdash_client_id,
                        "client_secret": self.settings.lightdash_client_secret,
                    },
                )
        except TimeoutError:
            raise self._refresh_failed(grant_id, grant, "Lightdash didn't answer in time while refreshing your sign-in") from None
        except httpx.HTTPError:
            raise self._refresh_failed(grant_id, grant, "Couldn't reach Lightdash to refresh your sign-in") from None
        # Only a refused grant ends the sign-in. Other errors, such as invalid_client, are the server's.
        if response.status_code in (400, 401) and _oauth_error(response) == "invalid_grant":
            await self._end_grant(grant_id, "lightdash_refused_refresh")
            raise SignInRequired
        if not response.is_success:
            raise self._refresh_failed(grant_id, grant, f"Lightdash error {response.status_code} while refreshing your sign-in")
        try:
            tokens = LightdashTokens.model_validate_json(response.content)
        except ValueError:
            raise self._refresh_failed(grant_id, grant, "Lightdash answered the refresh of your sign-in with no token") from None

        grant.access_token, grant.refresh_token = tokens.access_token, tokens.refresh_token
        grant.expires_at = time.time() + tokens.expires_in
        # Saved before use: Lightdash has already rotated the old refresh token.
        await self.store.put("grant", grant_id, grant, _grant_ttl(grant))
        return grant.access_token

    def _refresh_failed(self, grant_id: str, grant: Grant, reason: str) -> RefreshFailed:
        record("refresh_failed", logging.WARNING, grant=grant_id, subject=grant.subject, client_id=grant.client_id, reason=reason)
        return RefreshFailed(f"{reason}. Try again in a moment.")

    async def end_grant(
        self, grant_id: str, reason: str, revoke_upstream: bool = False, revoked: Access | Refresh | None = None
    ) -> None:
        # Under the grant's lock, so a refresh or token exchange in flight can't put the grant back.
        async with self.store.lock("grant", grant_id):
            grant = await self._end_grant(grant_id, reason, revoked)
        if grant and revoke_upstream:
            await self._revoke_upstream(grant_id, grant)

    async def _end_grant(self, grant_id: str, reason: str, revoked: Access | Refresh | None = None) -> Grant | None:
        """Ends the grant and its tokens in one step, so a Redis failure leaves the grant whole or ended, and logs the
        `revoked` token that ends it. The caller holds the grant's lock."""
        grant = await self.store.get("grant", grant_id, Grant)
        if not grant:
            return None
        ended, *_ = await self.store.write(
            delete=[("grant", grant_id), ("access", grant.access_digest), ("refresh", grant.refresh_digest)]
        )
        if not ended:
            return None  # ended meanwhile, by a request that took the lock once it expired
        if revoked:
            # Logged once its grant is gone, from then on the token no longer loads, and only by the request that ended it.
            record("token_revoked", grant=grant_id, subject=revoked.subject, client_id=revoked.client_id)
        record("grant_ended", grant=grant_id, subject=grant.subject, client_id=grant.client_id, reason=reason)
        return grant

    async def _revoke_upstream(self, grant_id: str, grant: Grant) -> None:
        """Revokes the grant's Lightdash refresh token. This server's tokens are gone either way: a failure is logged."""
        try:
            response = await self.http.post(
                "/api/v1/oauth/revoke",
                data={
                    "token": grant.refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id": self.settings.lightdash_client_id,
                    "client_secret": self.settings.lightdash_client_secret,
                },
            )
        except httpx.HTTPError as error:
            failure: str | int = type(error).__name__
        else:
            if response.is_success:
                return
            failure = response.status_code
        record("lightdash_revoke_failed", logging.WARNING, grant=grant_id, subject=grant.subject, failure=failure)


async def read_body(request: Request, limit: int) -> bytes | None:
    """The request body, or None when it is longer than `limit` bytes. Read in chunks: nothing larger is buffered."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return None
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _usable(grant: Grant, refused: str | None) -> bool:
    return grant.access_token != refused and grant.expires_at - time.time() > REFRESH_MARGIN


def _grant_ttl(grant: Grant, ttl: int = REFRESH_TTL) -> int:
    """`ttl`, cut short by the end of the grant's lifetime."""
    return int(min(ttl, grant.created_at + GRANT_LIFETIME - time.time()))


def _same(stored: str, given: str) -> bool:
    """Compared as bytes: compare_digest refuses a str with non-ASCII characters, which a client can send."""
    return secrets.compare_digest(stored.encode(), given.encode())


def _oauth_error(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


def _redirect_to_client(transaction: Transaction, error: str, description: str | None = None) -> Response:
    url = construct_redirect_uri(
        str(transaction.params.redirect_uri), error=error, error_description=description, state=transaction.params.state
    )
    return RedirectResponse(url, 302)
