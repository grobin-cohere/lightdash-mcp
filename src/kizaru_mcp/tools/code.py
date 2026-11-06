"""Content as code: charts and dashboards in the format that `lightdash download` writes and `lightdash upload` reads."""

import re
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from kizaru_mcp.auth.provider import LightdashOAuthProvider
from kizaru_mcp.lightdash import LightdashClient
from kizaru_mcp.tools.common import DESTRUCTIVE, READ, Uuid, lightdash
from kizaru_mcp.tools.data import _explore, _fields

Kind = Literal["charts", "dashboards"]

# Slugs go into Lightdash URL paths, like the Uuid and Name arguments.
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
Slug = Annotated[str, Field(pattern=SLUG.pattern)]

CHART_KEYS = ("name", "slug", "spaceSlug", "tableName", "metricQuery", "chartConfig")
DASHBOARD_KEYS = ("name", "slug", "spaceSlug", "tiles")


def _require(item: dict[str, Any], keys: tuple[str, ...], kind: str) -> None:
    missing = [key for key in keys if item.get(key) in (None, "")]
    if missing:
        raise ToolError(f"The {kind} needs {', '.join(missing)}. Read one with get_{kind}_code to see the format.")
    if not isinstance(item["slug"], str) or not SLUG.match(item["slug"]):
        raise ToolError(f"Invalid slug {item['slug']!r}: use lowercase letters, digits and hyphens, such as my-team-ci-health.")


async def _read(ld: LightdashClient, project_uuid: str, kind: Kind, slugs: list[str]) -> dict[str, Any]:
    return await ld.get(f"/api/v1/projects/{project_uuid}/code/{kind}", ids=slugs)


async def _existing(ld: LightdashClient, project_uuid: str, kind: Kind, slug: str) -> dict[str, Any] | None:
    found = (await _read(ld, project_uuid, kind, [slug]))[kind]
    return found[0] if found else None


def _field_ids(value: Any) -> set[str]:
    """Every field a filter group refers to, nested and/or groups included."""
    if isinstance(value, dict):
        own = {value["target"]["fieldId"]} if isinstance(value.get("target"), dict) and "fieldId" in value["target"] else set()
        return own.union(*(_field_ids(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_field_ids(v) for v in value))
    return set()


async def check_chart(ld: LightdashClient, project_uuid: str, chart: dict[str, Any]) -> None:
    """Fail before saving when the chart refers to fields its explore doesn't have."""
    query = chart["metricQuery"]
    if not isinstance(query, dict):
        raise ToolError("metricQuery must be an object.")
    explore = query.get("exploreName") or chart["tableName"]
    if not isinstance(explore, str) or not re.match(r"^[\w-]+$", explore):
        raise ToolError(f"Invalid explore {explore!r}.")
    found = await _explore(ld, project_uuid, explore)
    known = set(_fields(found, "dimensions")) | set(_fields(found, "metrics"))
    known |= {calc["name"] for calc in query.get("tableCalculations") or []}
    known |= {dim["id"] for dim in query.get("customDimensions") or [] if "id" in dim}
    known |= {f"{m['table']}_{m['name']}" for m in query.get("additionalMetrics") or [] if "table" in m and "name" in m}
    used = {*(query.get("dimensions") or []), *(query.get("metrics") or [])}
    used |= {sort["fieldId"] for sort in query.get("sorts") or []}
    used |= _field_ids(query.get("filters") or {})
    unknown = sorted(used - known)
    if unknown:
        raise ToolError(f"Unknown fields in {explore}: {', '.join(unknown)}. See get_explore.")


async def check_dashboard(ld: LightdashClient, project_uuid: str, dashboard: dict[str, Any]) -> list[str]:
    """Fail when a tile is malformed. Return the chart slugs its tiles show that don't exist yet: Lightdash would
    save those tiles empty, so saving fails until they exist, but a dry run only reports them."""
    tiles = dashboard["tiles"]
    if not isinstance(tiles, list):
        raise ToolError("tiles must be a list.")
    for n, tile in enumerate(tiles):
        missing = [key for key in ("type", "x", "y", "w", "h", "properties") if not isinstance(tile, dict) or key not in tile]
        if missing:
            raise ToolError(f"Tile {n} needs {', '.join(missing)}.")
        if tile["type"] == "saved_chart" and not (tile["properties"] or {}).get("chartSlug"):
            raise ToolError(f"Tile {n} is a saved_chart tile without properties.chartSlug.")
    slugs = sorted({t["properties"]["chartSlug"] for t in tiles if t["type"] == "saved_chart"})
    if not slugs:
        return []
    return sorted((await _read(ld, project_uuid, "charts", slugs)).get("missingIds") or [])


async def _space_exists(ld: LightdashClient, project_uuid: str, space_slug: str) -> bool:
    spaces = await ld.get(f"/api/v1/projects/{project_uuid}/spaces")
    return any(space.get("slug") == space_slug for space in spaces)


async def preview(ld: LightdashClient, project_uuid: str, kind: Kind, item: dict[str, Any]) -> dict[str, Any]:
    existing = await _existing(ld, project_uuid, kind, item["slug"])
    summary: dict[str, Any] = {"slug": item["slug"], "name": item["name"], "space": item["spaceSlug"]}
    if existing:
        summary |= {
            "replaces": {"name": existing.get("name"), "space": existing.get("spaceSlug"), "updatedAt": existing.get("updatedAt")}
        }
    if not await _space_exists(ld, project_uuid, item["spaceSlug"]):
        summary["newSpace"] = "Lightdash creates this space, visible only to you and admins until you share it."
    singular = kind[:-1]
    return {
        "wouldUpdate" if existing else "wouldCreate": summary,
        "next": f"Nothing is saved yet. Call save_{singular} again with dry_run=false to save this {singular}.",
    }


async def save(ld: LightdashClient, project_uuid: str, kind: Kind, item: dict[str, Any], lightdash_url: str) -> dict[str, Any]:
    body = item | {"skipSpaceCreate": False, "publicSpaceCreate": False}
    results = await ld.request("POST", f"/api/v1/projects/{project_uuid}/code/{kind}/{item['slug']}", json=body)
    saved = results[kind][0]
    uuid = saved["data"]["uuid"]
    errors = (await ld.request("POST", f"/api/v1/projects/{project_uuid}/validate/{kind[:-1]}/{uuid}", json={}))["errors"]
    page = "saved" if kind == "charts" else "dashboards"
    return {
        "action": saved["action"],
        "uuid": uuid,
        "url": f"{lightdash_url}/projects/{project_uuid}/{page}/{uuid}",
        "validationErrors": [{"field": e.get("fieldName"), "error": e.get("error")} for e in errors],
        **({"warnings": results["warnings"]} if results.get("warnings") else {}),
    }


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def get_chart_code(project_uuid: Uuid, slug: Slug) -> dict[str, Any]:
        """Read a saved chart as code, in the format save_chart takes: its explore, fields, filters, sorts and
        chart configuration. Use it to change a chart, or as an example before writing a new one.
        Find slugs with search_content."""
        async with lightdash(provider) as ld:
            chart = await _existing(ld, project_uuid, "charts", slug)
        if chart is None:
            raise ToolError(f"No chart with slug {slug} in this project.")
        return chart

    @server.tool(annotations=READ)
    async def get_dashboard_code(project_uuid: Uuid, slug: Slug) -> dict[str, Any]:
        """Read a dashboard as code, in the format save_dashboard takes: its tiles with their position and the
        slug of each chart, its tabs and its filters."""
        async with lightdash(provider) as ld:
            dashboard = await _existing(ld, project_uuid, "dashboards", slug)
        if dashboard is None:
            raise ToolError(f"No dashboard with slug {slug} in this project.")
        return dashboard

    @server.tool(annotations=DESTRUCTIVE)
    async def save_chart(project_uuid: Uuid, chart: dict[str, Any], dry_run: bool = True) -> dict[str, Any]:
        """Create a chart, or replace the chart with the same slug, from chart code: name, slug, spaceSlug,
        tableName (the explore), metricQuery (exploreName, dimensions, metrics, filters, sorts, limit,
        tableCalculations) and chartConfig, as get_chart_code returns them. Fields must exist in the explore:
        see get_explore. A spaceSlug that doesn't exist yet creates a space only you and admins can see.
        dry_run, on by default, checks the chart and says whether it would create or replace one.
        Pass dry_run=false to save; the result has the chart's URL and Lightdash's validation errors."""
        _require(chart, CHART_KEYS, "chart")
        async with lightdash(provider) as ld:
            await check_chart(ld, project_uuid, chart)
            if dry_run:
                return await preview(ld, project_uuid, "charts", chart)
            return await save(ld, project_uuid, "charts", {"version": 1, **chart}, provider.settings.lightdash_url)

    @server.tool(annotations=DESTRUCTIVE)
    async def save_dashboard(project_uuid: Uuid, dashboard: dict[str, Any], dry_run: bool = True) -> dict[str, Any]:
        """Create a dashboard, or replace the dashboard with the same slug, from dashboard code: name, slug,
        spaceSlug and tiles, as get_dashboard_code returns them. A tile has type (saved_chart, markdown),
        x, y, w and h on a 36-column grid, and properties: chartSlug for a saved chart, title and content for
        markdown. tabs and filters are optional. Its charts must be saved, with save_chart and dry_run=false,
        before the dashboard itself can be saved; a dry run lists the ones that aren't yet.
        dry_run, on by default, checks the dashboard and says whether it would create or replace one.
        Pass dry_run=false to save; the result has the dashboard's URL."""
        _require(dashboard, DASHBOARD_KEYS, "dashboard")
        item = {"version": 1, "tabs": [], "filters": {"dimensions": [], "metrics": [], "tableCalculations": []}, **dashboard}
        async with lightdash(provider) as ld:
            missing = await check_dashboard(ld, project_uuid, item)
            if dry_run:
                result = await preview(ld, project_uuid, "dashboards", item)
                if missing:
                    result["chartsNotSavedYet"] = missing
                    result["next"] = (
                        f"Nothing is saved yet. Save {', '.join(missing)} with save_chart and dry_run=false, "
                        "then call save_dashboard with dry_run=false."
                    )
                return result
            if missing:
                raise ToolError(
                    f"No chart with slug {', '.join(missing)} in this project yet. Save it with save_chart and dry_run=false first."
                )
            return await save(ld, project_uuid, "dashboards", item, provider.settings.lightdash_url)
