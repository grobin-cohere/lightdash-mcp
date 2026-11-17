from collections.abc import Awaitable, Callable
from typing import Any

import httpx

TIMEOUT = 60
MAX_ERROR_LENGTH = 300  # characters of a Lightdash error kept in the message


class LightdashError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class LightdashClient:
    """Thin async wrapper over the Lightdash REST API, called as the signed-in user.

    Paths are absolute from the site root (`/api/v1/...`, `/api/v2/...`). `http` is shared by every
    user's client, so calls reuse its connections to Lightdash.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        access_token: str,
        refresh: Callable[[str], Awaitable[str]] | None = None,
    ) -> None:
        self._http = http
        self._token = access_token
        self._refresh = refresh

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self._send(method, path, **kwargs)
        is_refused = response.status_code == httpx.codes.UNAUTHORIZED

        # The token can expire during a long call, such as a query: refresh it and retry once.
        # `refresh` gets the refused token, so concurrent calls refused with the same token
        # refresh it once.
        if is_refused and self._refresh:
            self._token = await self._refresh(self._token)
            response = await self._send(method, path, **kwargs)

        if not response.is_success:
            raise LightdashError(response.status_code, _error_message(response))

        if not response.content:
            return None

        body = response.json()
        has_results = isinstance(body, dict) and "results" in body

        if has_results:
            return body["results"]

        return body

    async def get(self, path: str, **params: Any) -> Any:
        given = {name: value for name, value in params.items() if value is not None}
        return await self.request("GET", path, params=given)

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._token}"}
        return await self._http.request(
            method,
            path,
            headers=headers,
            timeout=TIMEOUT,
            **kwargs,
        )


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:MAX_ERROR_LENGTH] or response.reason_phrase

    error = body.get("error") if isinstance(body, dict) else None

    if isinstance(error, dict):
        return error.get("message") or error.get("name") or response.reason_phrase

    return str(error or body)[:MAX_ERROR_LENGTH]
