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
# Then the user signs in again, however often the client refreshes.
GRANT_LIFETIME = 90 * 24 * 60 * 60
REFRESH_MARGIN = 60
# A refresh ends while it still holds the grant's lock: under it, Redis takes the lock, reads the
# grant, saves the new Lightdash tokens and writes the new tokens (or ends the grant: two commands
# too).
REFRESH_REDIS_COMMANDS = 4
REFRESH_TIMEOUT = LOCK_TIMEOUT - REFRESH_REDIS_COMMANDS * REDIS_COMMAND_TIMEOUT
# Renewed on each token exchange: registration is open, so unused clients must expire.
CLIENT_TTL = 30 * 24 * 60 * 60
CONSENT_COOKIE = "lightdash_mcp_consent"  # one per transaction, suffixed with its digest
CONSENT_COOKIE_DIGEST_LENGTH = 16
CONSENT_COOKIE_PATH = "/oauth"
FORM_LIMIT = 64 * 1024  # bytes of a form body: /token, /revoke and the consent page
HTTP_TIMEOUT = 30
LIGHTDASH_TOKEN_PATH = "/api/v1/oauth/token"
TOKEN_BYTES = 32
VERIFIER_BYTES = 48
GRANT_ID_BYTES = 16
WEB_SCHEMES = ("http", "https")
TOKEN_ERROR_STATUSES = (400, 401)

# Registration and /authorize are open to anyone, and what they get is kept in Redis:
# keep it small.
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
# Lightdash errors the client can act on. The others are about this server's request to
# Lightdash.
FORWARDED_ERRORS = ("access_denied", "temporarily_unavailable")
# The token endpoint's answer to a failure the client can retry, with the same refresh token or
# code. RFC 6749 has no server_error for it, and the SDK accepts no code outside RFC 6749's:
# invalid_request is the one that says nothing about the grant or the client. invalid_grant would
# end the client's session, invalid_client its registration.
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
    """One sign-in: the user's Lightdash tokens and this server's current code and tokens for
    it."""

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
    suffix = digest(transaction_id)[:CONSENT_COOKIE_DIGEST_LENGTH]
    return f"{CONSENT_COOKIE}_{suffix}"


def _challenge(verifier: str) -> str:
    verifier_hash = hashlib.sha256(verifier.encode()).digest()
    encoded = base64.urlsafe_b64encode(verifier_hash)
    return encoded.rstrip(b"=").decode()


class LightdashOAuthProvider:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        # Shared by every user's Lightdash client, which set their own timeout. It keeps no
        # cookies: one set by a response to one user would go out with the next user's requests.
        self.http = httpx.AsyncClient(
            base_url=settings.lightdash_url,
            timeout=HTTP_TIMEOUT,
            cookies=CookieJar(DefaultCookiePolicy(allowed_domains=[])),
        )

    # Client registration

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self.store.get("client", client_id, OAuthClientInformationFull)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        client_name = client_info.client_name or ""
        if len(client_name) > MAX_CLIENT_NAME:
            raise RegistrationError(
                "invalid_client_metadata",
                f"client_name is longer than {MAX_CLIENT_NAME} characters",
            )

        redirect_uris = client_info.redirect_uris or []
        if len(redirect_uris) > MAX_REDIRECT_URIS:
            raise RegistrationError(
                "invalid_redirect_uri",
                f"At most {MAX_REDIRECT_URIS} redirect URIs",
            )

        for uri in redirect_uris:
            if problem := self._redirect_problem(uri):
                raise RegistrationError("invalid_redirect_uri", f"{clip(str(uri))}: {problem}")

        cleared_fields = dict.fromkeys(UNUSED_CLIENT_FIELDS)
        client = client_info.model_copy(update=cleared_fields)
        record_size = len(client.model_dump_json())
        if record_size > MAX_CLIENT_RECORD:
            raise RegistrationError("invalid_client_metadata", "Client metadata is too large")

        await self.store.put("client", client.client_id, client, CLIENT_TTL)
        clipped_uris = [clip(str(uri)) for uri in redirect_uris]
        record(
            "client_registered",
            client_id=client.client_id,
            client_name=client.client_name,
            redirect_uris=clipped_uris,
        )

    def _redirect_problem(self, uri: AnyUrl) -> str | None:
        """Why a client may not register this redirect URI, if it may not (RFC 8252 for native
        apps)."""
        if len(str(uri)) > MAX_REDIRECT_URI:
            return f"longer than {MAX_REDIRECT_URI} characters"

        if uri.username is not None or uri.password is not None:
            return "a user name or password in a redirect URI hides its real host"

        if uri.fragment is not None:
            return "a redirect URI can't have a fragment"

        if uri.scheme == "http" and uri.host not in LOOPBACK_HOSTS:
            return "http is allowed for localhost, 127.0.0.1 and [::1] only: use https"

        if uri.scheme == "https" and not self._is_allowed_https_host(uri.host):
            return "this server accepts https redirect URIs on the hosts in REDIRECT_HOSTS only"

        if uri.scheme in BLOCKED_SCHEMES:
            return f"{uri.scheme}: URIs are not allowed"

        return None

    def _is_allowed_https_host(self, host: str | None) -> bool:
        """REDIRECT_HOSTS, when set, lists the only hosts an https redirect URI may use."""
        allowed_hosts = self.settings.redirect_hosts
        if not allowed_hosts:
            return True

        return host in allowed_hosts

    # Authorization: client -> consent page -> Lightdash -> callback -> client

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if not S256_CHALLENGE.match(params.code_challenge):
            raise AuthorizeError(
                "invalid_request",
                "code_challenge must be an S256 challenge: 43 base64url characters",
            )

        state_length = len(params.state or "")
        resource_length = len(params.resource or "")
        if state_length > MAX_STATE or resource_length > MAX_STATE:
            raise AuthorizeError(
                "invalid_request",
                f"state and resource are limited to {MAX_STATE} characters",
            )

        transaction_id = secrets.token_urlsafe(TOKEN_BYTES)
        # The CSRF token is made once: a prefetch or a second tab of the consent page must not
        # change it.
        transaction = Transaction(
            client_id=client.client_id,
            params=params,
            verifier=secrets.token_urlsafe(VERIFIER_BYTES),
            csrf=secrets.token_urlsafe(TOKEN_BYTES),
        )
        await self.store.put("transaction", transaction_id, transaction, TRANSACTION_TTL)

        query = urlencode({"transaction": transaction_id})
        return f"{self.settings.public_url}/oauth/consent?{query}"

    async def consent_page(self, request: Request) -> Response:
        transaction_id = request.query_params.get("transaction", "")
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        if not transaction:
            return pages.expired()

        client = await self.get_client(transaction.client_id)
        # Once approved, the consent page no longer opens: its cookie names the only browser
        # that can finish the sign-in.
        if transaction.approved or not client:
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
            path=CONSENT_COOKIE_PATH,
            httponly=True,
            samesite="lax",
            secure=self._is_secure(request),
        )
        return response

    def _redirect_warning(self, uri: AnyUrl) -> str | None:
        if uri.scheme not in WEB_SCHEMES:
            return (
                "This address opens an app on this device. "
                "Continue only if you started this sign-in from that app."
            )

        if uri.host in LOOPBACK_HOSTS or uri.host in self.settings.redirect_hosts:
            return None

        return (
            f"This address is a website, not an app on this computer: whoever runs {uri.host} "
            "gets access to Lightdash as you. "
            "Continue only if you started this sign-in and trust that site."
        )

    def _is_secure(self, request: Request) -> bool:
        """Behind a tunnel or proxy the request may look like plain HTTP: PUBLIC_URL says what
        browsers use."""
        has_https_public_url = self.settings.public_url.startswith("https://")
        return has_https_public_url or request.url.scheme == "https"

    async def consent_submit(self, request: Request) -> Response:
        body = await read_body(request, FORM_LIMIT)
        if body is None:
            return pages.page(
                "Request too large",
                "<p>Start again from your MCP client.</p>",
                status=413,
            )

        form_text = body.decode("utf-8", "replace")
        form = dict(parse_qsl(form_text))
        transaction_id = form.get("transaction", "")
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        if not transaction:
            return pages.expired()

        has_form_csrf = _matches(transaction.csrf, form.get("csrf", ""))
        has_cookie_csrf = _has_consent_cookie(request, transaction_id, transaction.csrf)
        if not has_form_csrf or not has_cookie_csrf:
            return pages.expired()

        is_allowed = form.get("action") == "allow"
        decision = "allow" if is_allowed else "deny"
        record("consent", client_id=transaction.client_id, decision=decision)
        if not is_allowed:
            await self.store.delete("transaction", transaction_id)
            response = _redirect_to_client(transaction, error="access_denied")
            self._delete_consent_cookie(response, request, transaction_id)
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
        authorize_url = f"{self.settings.lightdash_url}/api/v1/oauth/authorize?{urlencode(query)}"
        # The consent cookie stays until the callback: it ties the sign-in to this browser.
        return RedirectResponse(authorize_url, 303)

    def _delete_consent_cookie(
        self, response: Response, request: Request, transaction_id: str
    ) -> None:
        response.delete_cookie(
            _consent_cookie(transaction_id),
            path=CONSENT_COOKIE_PATH,
            secure=self._is_secure(request),
        )

    async def lightdash_callback(self, request: Request) -> Response:
        transaction_id = request.query_params.get("state", "")
        transaction = await self._claim_approved_transaction(request, transaction_id)
        if not transaction:
            return pages.expired("Start again from your MCP client, in this browser.")

        lightdash_code = request.query_params.get("code")
        error = request.query_params.get("error")
        response = await self._finish_sign_in(transaction, lightdash_code, error)
        self._delete_consent_cookie(response, request, transaction_id)
        return response

    async def _claim_approved_transaction(
        self, request: Request, transaction_id: str
    ) -> Transaction | None:
        """The transaction, removed from Redis, if this browser approved it: else None."""
        transaction = await self.store.get("transaction", transaction_id, Transaction)
        if not transaction or not transaction.approved:
            return None

        # Only the browser that approved the consent page can finish the sign-in, so a Lightdash
        # link taken from someone else's consent can't send this user's code to their client.
        if not _has_consent_cookie(request, transaction_id, transaction.csrf):
            return None

        if not await self.store.pop("transaction", transaction_id, Transaction):
            return None

        return transaction

    async def _finish_sign_in(
        self, transaction: Transaction, lightdash_code: str | None, error: str | None
    ) -> Response:
        if error or not lightdash_code:
            forwarded_error = error if error in FORWARDED_ERRORS else "server_error"
            return _redirect_to_client(transaction, error=forwarded_error)

        try:
            grant = await self._sign_in_to_lightdash(transaction, lightdash_code)
        except httpx.HTTPError, ValueError, KeyError, TypeError:
            record("sign_in_failed", logging.WARNING, client_id=transaction.client_id)
            return _redirect_to_client(
                transaction,
                error="server_error",
                description="Lightdash sign-in failed",
            )

        grant_id = secrets.token_urlsafe(GRANT_ID_BYTES)
        code = secrets.token_urlsafe(TOKEN_BYTES)
        code_digest = digest(code)
        grant.code_digest = code_digest
        params = transaction.params
        code_record = Code(
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
        )
        await self.store.write(
            put=[
                # Kept for REFRESH_TTL once the client exchanges its code (_issue), so an unused
                # sign-in expires soon.
                ("grant", grant_id, grant, TRANSACTION_TTL),
                ("code", code_digest, code_record, CODE_TTL),
            ]
        )
        record("grant_created", grant=grant_id, subject=grant.subject, client_id=grant.client_id)

        redirect_uri = construct_redirect_uri(
            str(params.redirect_uri),
            code=code,
            state=params.state,
        )
        return RedirectResponse(redirect_uri, 302)

    async def _sign_in_to_lightdash(self, transaction: Transaction, lightdash_code: str) -> Grant:
        token_request = {
            "grant_type": "authorization_code",
            "code": lightdash_code,
            "redirect_uri": self.settings.callback_url,
            "client_id": self.settings.lightdash_client_id,
            "client_secret": self.settings.lightdash_client_secret,
            "code_verifier": transaction.verifier,
        }
        response = await self.http.post(LIGHTDASH_TOKEN_PATH, data=token_request)
        response.raise_for_status()
        tokens = LightdashTokens.model_validate_json(response.content)

        auth_headers = {"Authorization": f"Bearer {tokens.access_token}"}
        user = await self.http.get("/api/v1/user", headers=auth_headers)
        user.raise_for_status()
        subject = user.json()["results"]["userUuid"]

        return Grant(
            client_id=transaction.client_id,
            subject=subject,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_at=time.time() + tokens.expires_in,
        )

    # Tokens. Each one is valid only while its grant points back to it, so a record copied in
    # Redis is refused.

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Code | None:
        code_digest = digest(authorization_code)
        code = await self.store.get("code", code_digest, Code)
        if not code:
            return None

        is_client_code = (
            _matches(code.code, authorization_code) and code.client_id == client.client_id
        )
        if not is_client_code:
            return None

        grant = await self._load_client_grant(code.grant_id, client.client_id)
        if not grant or grant.code_digest != code_digest:
            return None

        return code

    async def _load_client_grant(self, grant_id: str, client_id: str) -> Grant | None:
        """The grant, if it belongs to the client."""
        grant = await self.store.get("grant", grant_id, Grant)
        if not grant or grant.client_id != client_id:
            return None

        return grant

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: Code
    ) -> OAuthToken:
        try:
            tokens = await self._redeem_code(authorization_code)
        except LockError:
            # Only taking the lock raises it (Store.lock), so nothing under it has run: the code
            # isn't used yet.
            raise TokenError(RETRY_ERROR, GRANT_BUSY) from None

        await self._renew_client(client)
        return tokens

    async def _redeem_code(self, authorization_code: Code) -> OAuthToken:
        grant_id = authorization_code.grant_id
        code_digest = digest(authorization_code.code)

        async with self.store.lock("grant", grant_id):
            if not await self.store.pop("code", code_digest, Code):
                raise TokenError("invalid_grant", "Authorization code already used")

            grant = await self.store.get("grant", grant_id, Grant)

            if not grant or grant.code_digest != code_digest:
                raise TokenError("invalid_grant", "Sign-in ended")

            return await self._issue(
                grant_id,
                grant,
                authorization_code.scopes,
                authorization_code.resource,
            )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Refresh | None:
        token_digest = digest(refresh_token)
        token = await self.store.get("refresh", token_digest, Refresh)
        if token and _is_issued_token(token, refresh_token, client.client_id):
            grant = await self._load_client_grant(token.grant_id, client.client_id)
            is_current = grant is not None and grant.refresh_digest == token_digest
            return token if is_current else None

        rotated = await self.store.get("rotated", token_digest, Rotated)
        if rotated and rotated.client_id == client.client_id:
            # A refresh token works once: seen again after its exchange, it was copied. End the
            # sign-in for every copy.
            await self.end_grant(rotated.grant_id, "refresh_token_reused", revoke_upstream=True)

        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: Refresh, scopes: list[str]
    ) -> OAuthToken:
        try:
            tokens = await self._rotate_refresh_token(refresh_token, scopes)
        except LockError:
            raise TokenError(RETRY_ERROR, GRANT_BUSY) from None

        await self._renew_client(client)
        return tokens

    async def _rotate_refresh_token(self, refresh_token: Refresh, scopes: list[str]) -> OAuthToken:
        # Under the grant's lock from start to end, so a revocation waits for it, and the old
        # refresh token is replaced only when the new tokens are written: on any failure, the
        # client can retry with it.
        grant_id = refresh_token.grant_id

        async with self.store.lock("grant", grant_id):
            grant = await self.store.get("grant", grant_id, Grant)

            if not grant or grant.refresh_digest != digest(refresh_token.token):
                raise TokenError("invalid_grant", "Refresh token already used")

            # Keeps the Lightdash sign-in alive as long as the client's, and catches a revoked
            # one now.
            try:
                await self._refresh_lightdash(grant_id, grant)
            except SignInRequired:
                raise TokenError("invalid_grant", "Lightdash sign-in ended") from None
            except RefreshFailed as error:
                raise TokenError(RETRY_ERROR, str(error)) from None

            granted_scopes = scopes or refresh_token.scopes
            return await self._issue(grant_id, grant, granted_scopes, refresh_token.resource)

    async def _renew_client(self, client: OAuthClientInformationFull) -> None:
        """Extends the client registration's expiry. The tokens are issued by then: a Redis
        failure only skips it."""
        try:
            await self.store.touch("client", client.client_id, CLIENT_TTL)
        except RedisError:
            pass

    async def load_access_token(self, token: str) -> Access | None:
        access_digest = digest(token)
        access = await self.store.get("access", access_digest, Access)
        if not access or not _matches(access.token, token):
            return None

        if access.expires_at and access.expires_at < time.time():
            return None

        grant = await self._load_client_grant(access.grant_id, access.client_id)
        if not grant or grant.access_digest != access_digest:
            return None

        return access

    async def revoke_token(self, token: Access | Refresh) -> None:
        try:
            await self.end_grant(token.grant_id, "revoked", revoke_upstream=True, revoked=token)
        except LockError:  # only taking the lock raises it (Store.lock): nothing is revoked
            record(
                "revoke_busy",
                logging.WARNING,
                grant=token.grant_id,
                subject=token.subject,
                client_id=token.client_id,
            )
            raise

    async def _issue(
        self, grant_id: str, grant: Grant, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        """New tokens for the grant, written with it in one step. The caller holds the grant's
        lock."""
        access_token = secrets.token_urlsafe(TOKEN_BYTES)
        refresh_token = secrets.token_urlsafe(TOKEN_BYTES)
        access_digest = digest(access_token)
        refresh_digest = digest(refresh_token)
        shared_fields = {
            "client_id": grant.client_id,
            "scopes": scopes,
            "resource": resource,
            "subject": grant.subject,
        }
        access_ttl = _grant_ttl(grant, self.settings.access_token_ttl)
        refresh_ttl = _grant_ttl(grant)
        now = int(time.time())
        access = Access(
            token=access_token,
            expires_at=now + access_ttl,
            grant_id=grant_id,
            **shared_fields,
        )
        refresh = Refresh(
            token=refresh_token,
            expires_at=now + refresh_ttl,
            grant_id=grant_id,
            **shared_fields,
        )
        put: list[tuple[str, str, BaseModel, int]] = [
            ("access", access_digest, access, access_ttl),
            ("refresh", refresh_digest, refresh, refresh_ttl),
        ]

        if grant.refresh_digest:
            rotated = Rotated(client_id=grant.client_id, grant_id=grant_id)
            put.append(("rotated", grant.refresh_digest, rotated, REFRESH_TTL))

        delete = [("access", grant.access_digest), ("refresh", grant.refresh_digest)]
        grant.access_digest = access_digest
        grant.refresh_digest = refresh_digest
        put.append(("grant", grant_id, grant, refresh_ttl))
        await self.store.write(put, delete)

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=access_ttl,
            refresh_token=refresh_token,
            scope=" ".join(scopes) or None,
        )

    # Lightdash tokens

    async def lightdash_token(self, grant_id: str, refused: str | None = None) -> str:
        """The grant's Lightdash access token, refreshed first if it is about to expire or
        Lightdash `refused` it.

        Requests refused with the same token refresh it once: the others get the token it was
        replaced with.
        """
        grant = await self.store.get("grant", grant_id, Grant)
        if not grant:
            raise SignInRequired

        if _is_usable(grant, refused):
            return grant.access_token

        async with self.store.lock("grant", grant_id):
            grant = await self.store.get("grant", grant_id, Grant)
            if not grant:
                raise SignInRequired

            if _is_usable(grant, refused):
                return grant.access_token  # refreshed meanwhile by another request

            return await self._refresh_lightdash(grant_id, grant)

    async def _refresh_lightdash(self, grant_id: str, grant: Grant) -> str:
        """Refreshes the grant's Lightdash tokens and saves them. The caller holds the grant's
        lock."""
        # Its TTL ends the grant at its lifetime, give or take a second: past it, don't renew it
        # upstream.
        if time.time() >= _lifetime_end(grant):
            await self._end_grant(grant_id, "lifetime_ended")
            raise SignInRequired

        refresh_request = {
            "grant_type": "refresh_token",
            "refresh_token": grant.refresh_token,
            "client_id": self.settings.lightdash_client_id,
            "client_secret": self.settings.lightdash_client_secret,
        }
        try:
            async with asyncio.timeout(REFRESH_TIMEOUT):
                response = await self.http.post(LIGHTDASH_TOKEN_PATH, data=refresh_request)
        except TimeoutError:
            reason = "Lightdash didn't answer in time while refreshing your sign-in"
            raise self._refresh_failed(grant_id, grant, reason) from None
        except httpx.HTTPError:
            reason = "Couldn't reach Lightdash to refresh your sign-in"
            raise self._refresh_failed(grant_id, grant, reason) from None

        # Only a refused grant ends the sign-in. Other errors, such as invalid_client, are the
        # server's.
        is_token_error_status = response.status_code in TOKEN_ERROR_STATUSES
        if is_token_error_status and _oauth_error(response) == "invalid_grant":
            await self._end_grant(grant_id, "lightdash_refused_refresh")
            raise SignInRequired

        if not response.is_success:
            reason = f"Lightdash error {response.status_code} while refreshing your sign-in"
            raise self._refresh_failed(grant_id, grant, reason)

        try:
            tokens = LightdashTokens.model_validate_json(response.content)
        except ValueError:
            reason = "Lightdash answered the refresh of your sign-in with no token"
            raise self._refresh_failed(grant_id, grant, reason) from None

        grant.access_token = tokens.access_token
        grant.refresh_token = tokens.refresh_token
        grant.expires_at = time.time() + tokens.expires_in
        # Saved before use: Lightdash has already rotated the old refresh token.
        await self.store.put("grant", grant_id, grant, _grant_ttl(grant))

        return grant.access_token

    def _refresh_failed(self, grant_id: str, grant: Grant, reason: str) -> RefreshFailed:
        record(
            "refresh_failed",
            logging.WARNING,
            grant=grant_id,
            subject=grant.subject,
            client_id=grant.client_id,
            reason=reason,
        )
        return RefreshFailed(f"{reason}. Try again in a moment.")

    async def end_grant(
        self,
        grant_id: str,
        reason: str,
        revoke_upstream: bool = False,
        revoked: Access | Refresh | None = None,
    ) -> None:
        # Under the grant's lock, so a refresh or token exchange in flight can't put the grant
        # back.
        async with self.store.lock("grant", grant_id):
            grant = await self._end_grant(grant_id, reason, revoked)

        if grant and revoke_upstream:
            await self._revoke_upstream(grant_id, grant)

    async def _end_grant(
        self, grant_id: str, reason: str, revoked: Access | Refresh | None = None
    ) -> Grant | None:
        """Ends the grant and its tokens in one step, so a Redis failure leaves the grant whole or
        ended, and logs the `revoked` token that ends it. The caller holds the grant's lock."""
        grant = await self.store.get("grant", grant_id, Grant)

        if not grant:
            return None

        removed_counts = await self.store.write(
            delete=[
                ("grant", grant_id),
                ("access", grant.access_digest),
                ("refresh", grant.refresh_digest),
            ]
        )
        was_grant_removed = removed_counts[0] > 0

        if not was_grant_removed:
            return None  # ended meanwhile, by a request that took the lock once it expired

        if revoked:
            # Logged once its grant is gone, from then on the token no longer loads, and only by
            # the request that ended it.
            record(
                "token_revoked",
                grant=grant_id,
                subject=revoked.subject,
                client_id=revoked.client_id,
            )

        record(
            "grant_ended",
            grant=grant_id,
            subject=grant.subject,
            client_id=grant.client_id,
            reason=reason,
        )
        return grant

    async def _revoke_upstream(self, grant_id: str, grant: Grant) -> None:
        """Revokes the grant's Lightdash refresh token. This server's tokens are gone either way:
        a failure is logged."""
        failure = await self._request_revocation(grant)
        if failure is None:
            return

        record(
            "lightdash_revoke_failed",
            logging.WARNING,
            grant=grant_id,
            subject=grant.subject,
            failure=failure,
        )

    async def _request_revocation(self, grant: Grant) -> str | int | None:
        """Why Lightdash didn't revoke the grant's refresh token, or None when it did."""
        revoke_request = {
            "token": grant.refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": self.settings.lightdash_client_id,
            "client_secret": self.settings.lightdash_client_secret,
        }
        try:
            response = await self.http.post("/api/v1/oauth/revoke", data=revoke_request)
        except httpx.HTTPError as error:
            return type(error).__name__

        if response.is_success:
            return None

        return response.status_code


async def read_body(request: Request, limit: int) -> bytes | None:
    """The request body, or None when it is longer than `limit` bytes. Read in chunks: nothing
    larger is buffered."""
    declared_length = request.headers.get("content-length", "")
    if declared_length.isdigit() and int(declared_length) > limit:
        return None

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None

        chunks.append(chunk)

    return b"".join(chunks)


def _has_consent_cookie(request: Request, transaction_id: str, csrf: str) -> bool:
    """Whether the request comes from the browser that opened the transaction's consent page."""
    cookie = request.cookies.get(_consent_cookie(transaction_id), "")
    return _matches(csrf, cookie)


def _is_issued_token(token: Refresh, presented: str, client_id: str) -> bool:
    return _matches(token.token, presented) and token.client_id == client_id


def _is_usable(grant: Grant, refused: str | None) -> bool:
    seconds_left = grant.expires_at - time.time()
    return grant.access_token != refused and seconds_left > REFRESH_MARGIN


def _lifetime_end(grant: Grant) -> float:
    return grant.created_at + GRANT_LIFETIME


def _grant_ttl(grant: Grant, ttl: int = REFRESH_TTL) -> int:
    """`ttl`, cut short by the end of the grant's lifetime."""
    seconds_left = _lifetime_end(grant) - time.time()
    return int(min(ttl, seconds_left))


def _matches(stored: str, given: str) -> bool:
    """Compared as bytes: compare_digest refuses a str with non-ASCII characters, which a client
    can send."""
    return secrets.compare_digest(stored.encode(), given.encode())


def _oauth_error(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None

    if not isinstance(body, dict):
        return None

    return body.get("error")


def _redirect_to_client(
    transaction: Transaction, error: str, description: str | None = None
) -> Response:
    url = construct_redirect_uri(
        str(transaction.params.redirect_uri),
        error=error,
        error_description=description,
        state=transaction.params.state,
    )
    return RedirectResponse(url, 302)
