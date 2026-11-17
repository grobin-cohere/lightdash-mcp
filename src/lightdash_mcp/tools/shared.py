"""Helpers shared by the tools modules: pattern checks and paginated lists."""

from typing import Any

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import TypeAdapter, ValidationError

from lightdash_mcp.lightdash import LightdashClient

PAGE_SIZE = 100
MAX_PAGES = 100


def conforms(kind: Any, value: Any) -> bool:
    """Whether a value passes an argument type such as Slug or Name, checked as tool arguments are."""
    try:
        TypeAdapter(kind).validate_python(value, strict=True)
    except ValidationError:
        return False
    return True


def space_slug(space: dict[str, Any]) -> str:
    """The spaceSlug that content as code gives a space: its path, such as parent/child, from the ltree path
    parent.child (getContentAsCodePathFromLtreePath in Lightdash)."""
    return space["path"].replace("_", "-").replace(".", "/")


async def every_page(ld: LightdashClient, path: str, **params: Any) -> list[dict[str, Any]]:
    """Every item of a paginated Lightdash list (`{"data": [...], "pagination": {...}}`)."""
    items: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        results = await ld.get(path, pageSize=PAGE_SIZE, page=page, **params)
        items += results["data"]
        if page >= (results.get("pagination") or {}).get("totalPageCount", 0):
            return items
    raise ToolError(f"More than {MAX_PAGES * PAGE_SIZE} results: narrow the search.")
