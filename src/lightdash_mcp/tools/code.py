"""Content as code: charts and dashboards in the format that `lightdash download` writes and `lightdash upload` reads."""

from typing import Any, Literal

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient, LightdashError
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, Name, Slug, Uuid, lightdash
from lightdash_mcp.tools.data import explore_fields, load_explore
from lightdash_mcp.tools.shared import conforms, space_slug

Kind = Literal["charts", "dashboards"]

CHART_KEYS = ("name", "slug", "spaceSlug", "tableName", "metricQuery", "chartConfig")
DASHBOARD_KEYS = ("name", "slug", "spaceSlug", "tiles")

# Optional keys that Lightdash resets when an upload leaves them out (CoderService.upsertChart and upsertDashboard
# default tableConfig and filters to empty ones): on replace, the ones the caller didn't give keep their value.
KEPT: dict[Kind, tuple[str, ...]] = {
    "charts": ("description", "tableConfig", "pivotConfig", "parameters"),
    "dashboards": ("description", "tabs", "filters", "config", "parameters"),
}
# Keys that change on every download or upload, left out of the changes a dry run lists.
UNCOMPARED = {"version", "updatedAt", "downloadedAt", "contentType"}


def _require(item: dict[str, Any], keys: tuple[str, ...], kind: str) -> None:
    missing = [key for key in keys if item.get(key) in (None, "")]
    if missing:
        raise ToolError(
            f"The {kind} needs {', '.join(missing)}. Read one with get_{kind}_code to see the format."
        )
    if not conforms(Slug, item["slug"]):
        raise ToolError(
            f"Invalid slug {item['slug']!r}: use lowercase letters, digits and hyphens, such as my-team-ci-health."
        )


async def _read(
    ld: LightdashClient, project_uuid: str, kind: Kind, slugs: list[str]
) -> dict[str, Any]:
    return await ld.get(f"/api/v1/projects/{project_uuid}/code/{kind}", ids=slugs)


async def _existing(
    ld: LightdashClient, project_uuid: str, kind: Kind, slug: str
) -> dict[str, Any] | None:
    found = (await _read(ld, project_uuid, kind, [slug]))[kind]
    return found[0] if found else None


def keep_existing(
    kind: Kind, item: dict[str, Any], existing: dict[str, Any] | None
) -> dict[str, Any]:
    kept = (
        {key: existing[key] for key in KEPT[kind] if key in existing and key not in item}
        if existing
        else {}
    )
    return kept | item


def _field_ids(value: Any) -> set[str]:
    """Every field a filter group refers to, nested and/or groups included."""
    if isinstance(value, dict):
        target = value.get("target")
        own = (
            {target["fieldId"]}
            if isinstance(target, dict) and isinstance(target.get("fieldId"), str)
            else set()
        )
        return own.union(*(_field_ids(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_field_ids(v) for v in value))
    return set()


def _entries(query: dict[str, Any], key: str, *fields: str) -> list[dict[str, Any]]:
    entries = query.get(key) or []
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) and all(isinstance(entry.get(field), str) for field in fields)
        for entry in entries
    ):
        raise ToolError(f"Each of metricQuery.{key} needs {' and '.join(fields)}.")
    return entries


def _field_list(query: dict[str, Any], key: str) -> list[str]:
    values = query.get(key) or []
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ToolError(f"metricQuery.{key} must be a list of field IDs.")
    return values


async def check_chart(ld: LightdashClient, project_uuid: str, chart: dict[str, Any]) -> None:
    """Fail before saving when the chart is malformed or refers to fields its explore doesn't have."""
    query = chart["metricQuery"]
    if not isinstance(query, dict):
        raise ToolError("metricQuery must be an object.")
    explore = query.get("exploreName") or chart["tableName"]
    if not conforms(Name, explore):
        raise ToolError(f"Invalid explore {explore!r}.")
    found = await load_explore(ld, project_uuid, explore)
    # Hidden fields are only left out of the sidebar: a chart can use them.
    known = {
        *explore_fields(found, "dimensions", include_hidden=True),
        *explore_fields(found, "metrics", include_hidden=True),
    }
    known |= {calc["name"] for calc in _entries(query, "tableCalculations", "name")}
    known |= {dim["id"] for dim in _entries(query, "customDimensions", "id")}
    known |= {
        f"{m['table']}_{m['name']}" for m in _entries(query, "additionalMetrics", "table", "name")
    }
    used = {*_field_list(query, "dimensions"), *_field_list(query, "metrics")}
    used |= {sort["fieldId"] for sort in _entries(query, "sorts", "fieldId")}
    used |= _field_ids(query.get("filters") or {})
    unknown = sorted(used - known)
    if unknown:
        raise ToolError(f"Unknown fields in {explore}: {', '.join(unknown)}. See get_explore.")


async def check_dashboard(
    ld: LightdashClient, project_uuid: str, dashboard: dict[str, Any]
) -> list[str]:
    """Fail when a tile is malformed. Return the chart slugs its tiles show that don't exist yet: Lightdash would
    save those tiles empty, so saving fails until they exist, but a dry run only reports them."""
    tiles = dashboard["tiles"]
    if not isinstance(tiles, list):
        raise ToolError("tiles must be a list.")
    for n, tile in enumerate(tiles):
        missing = [
            key
            for key in ("type", "x", "y", "w", "h", "properties")
            if not isinstance(tile, dict) or key not in tile
        ]
        if missing:
            raise ToolError(f"Tile {n} needs {', '.join(missing)}.")
        if not isinstance(tile["properties"], dict):
            raise ToolError(f"Tile {n} properties must be an object.")
        if tile["type"] == "saved_chart" and not isinstance(
            tile["properties"].get("chartSlug"), str
        ):
            raise ToolError(f"Tile {n} is a saved_chart tile without properties.chartSlug.")
    slugs = sorted({t["properties"]["chartSlug"] for t in tiles if t["type"] == "saved_chart"})
    if not slugs:
        return []
    return sorted((await _read(ld, project_uuid, "charts", slugs)).get("missingIds") or [])


async def _space_exists(ld: LightdashClient, project_uuid: str, slug: str) -> bool:
    spaces = await ld.get(f"/api/v1/projects/{project_uuid}/spaces")
    return any(space_slug(space) == slug for space in spaces)


def _counts(dashboard: dict[str, Any]) -> dict[str, int]:
    filters = dashboard.get("filters") or {}
    return {
        "tiles": len(dashboard.get("tiles") or []),
        "tabs": len(dashboard.get("tabs") or []),
        "filters": sum(
            len(filters.get(key) or []) for key in ("dimensions", "metrics", "tableCalculations")
        ),
    }


async def preview(
    ld: LightdashClient,
    project_uuid: str,
    kind: Kind,
    item: dict[str, Any],
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "slug": item["slug"],
        "name": item["name"],
        "space": item["spaceSlug"],
    }
    if existing:
        summary["replaces"] = {
            "name": existing.get("name"),
            "space": existing.get("spaceSlug"),
            "updatedAt": existing.get("updatedAt"),
        }
        summary["changes"] = sorted(
            key for key in item if key not in UNCOMPARED and item[key] != existing.get(key)
        )
        if kind == "dashboards":
            summary |= {"before": _counts(existing), "after": _counts(item)}
    if not await _space_exists(ld, project_uuid, item["spaceSlug"]):
        summary["newSpace"] = (
            "Lightdash creates this space, visible only to you and admins until you share it."
        )
    singular = kind[:-1]
    return {
        "wouldUpdate" if existing else "wouldCreate": summary,
        "next": f"Nothing is saved yet. Call save_{singular} again with dry_run=false to save this {singular}.",
    }


async def save(
    ld: LightdashClient, project_uuid: str, kind: Kind, item: dict[str, Any], lightdash_url: str
) -> dict[str, Any]:
    # Without force, Lightdash skips a chart update whose name, description and slug are unchanged and whose
    # updatedAt isn't newer (PromoteService.isChartUpdated). Dashboards always update and ignore it.
    body = item | {"skipSpaceCreate": False, "publicSpaceCreate": False, "force": True}
    results = await ld.request(
        "POST", f"/api/v1/projects/{project_uuid}/code/{kind}/{item['slug']}", json=body
    )
    saved = results[kind][0]
    uuid = saved["data"]["uuid"]
    singular = kind[:-1]
    page = "saved" if kind == "charts" else "dashboards"
    result = {
        "action": saved["action"],
        "uuid": uuid,
        "url": f"{lightdash_url}/projects/{project_uuid}/{page}/{uuid}",
        **({"warnings": results["warnings"]} if results.get("warnings") else {}),
    }
    # The content is saved by now: a validation failure is reported, not raised.
    try:
        validation = await ld.request(
            "POST", f"/api/v1/projects/{project_uuid}/validate/{singular}/{uuid}", json={}
        )
    except LightdashError as error:
        if error.status == 401:
            raise
        result["validationFailed"] = (
            f"The {singular} is saved, but Lightdash couldn't validate it: {error.message}"
        )
    except httpx.HTTPError:
        result["validationFailed"] = (
            f"The {singular} is saved, but Lightdash didn't answer its validation."
        )
    else:
        result["validationErrors"] = [
            {"field": e.get("fieldName"), "error": e.get("error")} for e in validation["errors"]
        ]
    return result


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
        slug of each chart, its tabs and its filters. Find slugs with search_content."""
        async with lightdash(provider) as ld:
            dashboard = await _existing(ld, project_uuid, "dashboards", slug)
        if dashboard is None:
            raise ToolError(f"No dashboard with slug {slug} in this project.")
        return dashboard

    @server.tool(annotations=DESTRUCTIVE)
    async def save_chart(
        project_uuid: Uuid, chart: dict[str, Any], dry_run: bool = True
    ) -> dict[str, Any]:
        """Create a chart, or replace the chart with the same slug, from chart code: name, slug, spaceSlug,
        tableName (the explore), metricQuery (exploreName, dimensions, metrics, filters, sorts, limit,
        tableCalculations) and chartConfig, as get_chart_code returns them. Fields must exist in the explore:
        see get_explore. spaceSlug is a space's path, such as parent/child: see list_spaces. One that doesn't
        exist yet creates a space only you and admins can see. On replace, description, tableConfig,
        pivotConfig and parameters left out keep their current value.
        dry_run, on by default, checks the chart and says whether it would create or replace one, and what changes.
        Pass dry_run=false to save; the result has the chart's URL and Lightdash's validation errors."""
        _require(chart, CHART_KEYS, "chart")
        async with lightdash(provider) as ld:
            await check_chart(ld, project_uuid, chart)
            existing = await _existing(ld, project_uuid, "charts", chart["slug"])
            item = keep_existing("charts", {"version": 1, **chart}, existing)
            if dry_run:
                return await preview(ld, project_uuid, "charts", item, existing)
            return await save(ld, project_uuid, "charts", item, provider.settings.lightdash_url)

    @server.tool(annotations=DESTRUCTIVE)
    async def save_dashboard(
        project_uuid: Uuid, dashboard: dict[str, Any], dry_run: bool = True
    ) -> dict[str, Any]:
        """Create a dashboard, or replace the dashboard with the same slug, from dashboard code: name, slug,
        spaceSlug and tiles, as get_dashboard_code returns them. A tile has type (saved_chart, markdown),
        x, y, w and h on a 36-column grid, and properties: chartSlug for a saved chart, title and content for
        markdown. tabs and filters are optional; on replace, the ones left out, and description, config and
        parameters, keep their current value. Its charts must be saved, with save_chart and dry_run=false,
        before the dashboard itself can be saved; a dry run lists the ones that aren't yet.
        dry_run, on by default, checks the dashboard and says whether it would create or replace one, and what
        changes, with the tile, tab and filter counts before and after. Pass dry_run=false to save; the result has
        the dashboard's URL."""
        _require(dashboard, DASHBOARD_KEYS, "dashboard")
        async with lightdash(provider) as ld:
            missing = await check_dashboard(ld, project_uuid, dashboard)
            existing = await _existing(ld, project_uuid, "dashboards", dashboard["slug"])
            item = {
                "tabs": [],
                **keep_existing("dashboards", {"version": 1, **dashboard}, existing),
            }
            if dry_run:
                result = await preview(ld, project_uuid, "dashboards", item, existing)
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
