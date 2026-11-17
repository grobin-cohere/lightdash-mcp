import re
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from typing import Annotated, Any

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field
from redis.exceptions import LockError

from lightdash_mcp.auth.provider import (
    Access,
    LightdashOAuthProvider,
    RefreshFailed,
    SignInRequired,
)
from lightdash_mcp.lightdash import LightdashClient, LightdashError

RECONNECT = "Your Lightdash sign-in has ended. Reconnect this MCP server to sign in again."
UNREACHABLE = "Couldn't reach Lightdash. Try again in a moment."
BUSY = "Another request is refreshing your Lightdash sign-in. Try again in a moment."

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
DESTRUCTIVE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=True,
    open_world_hint=False,
)

# Arguments that go into Lightdash URL paths: a `../` or `?` in one would reach another endpoint.
UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
SLUG = r"[a-z0-9][a-z0-9-]*"
Uuid = Annotated[str, Field(pattern=f"^{UUID}$")]
Name = Annotated[str, Field(pattern=r"^[\w-]+$")]
Slug = Annotated[str, Field(pattern=f"^{SLUG}$")]
ChartRef = Annotated[str, Field(pattern=f"^{SLUG}$|^{UUID}$")]


async def resolve_chart(client: LightdashClient, project_uuid: str, chart: str) -> str:
    """The UUID of a chart of the project, given by UUID or by slug."""
    if re.fullmatch(UUID, chart):
        return chart

    found = await client.get(f"/api/v1/saved/{chart}")
    if found.get("projectUuid") != project_uuid:
        raise ToolError(f"No chart with slug {chart} in this project.")

    return found["uuid"]


@asynccontextmanager
async def lightdash(provider: LightdashOAuthProvider) -> AsyncIterator[LightdashClient]:
    """A Lightdash client acting as the signed-in user, with Lightdash errors turned into
    tool errors."""
    token = get_access_token()
    if not isinstance(token, Access):
        raise ToolError("Not signed in.")

    def refresh(refused: str) -> Awaitable[str]:
        return provider.lightdash_token(token.grant_id, refused)

    # One mapping for the first token, the refresh after a 401, and the tool's own calls.
    try:
        lightdash_token = await provider.lightdash_token(token.grant_id)
        yield LightdashClient(provider.http, lightdash_token, refresh)
    except SignInRequired:
        raise ToolError(RECONNECT) from None
    except RefreshFailed as error:
        raise ToolError(str(error)) from None
    except LockError:
        raise ToolError(BUSY) from None
    except LightdashError as error:
        raise _to_tool_error(error) from None
    except httpx.HTTPError:
        raise ToolError(UNREACHABLE) from None


def pick(item: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: item.get(key) for key in keys}


def full_name(item: dict[str, Any]) -> str:
    parts = (item.get("firstName"), item.get("lastName"))
    return " ".join(part for part in parts if part)


def _to_tool_error(error: LightdashError) -> ToolError:
    if error.status == 401:
        # Refused again with a freshly refreshed token: not about the sign-in, which Lightdash
        # just renewed.
        return ToolError(f"Lightdash refused this request (401): {error.message}")

    if error.status == 403:
        return ToolError(
            f"Permission denied: your Lightdash role doesn't allow this. {error.message}"
        )

    if error.status == 404:
        return ToolError(f"Not found: {error.message}")

    return ToolError(f"Lightdash error {error.status}: {error.message}")
