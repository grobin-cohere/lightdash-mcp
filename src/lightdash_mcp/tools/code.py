"""Content as code: charts and dashboards in the format that `lightdash download` writes and
`lightdash upload` reads."""

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

CHART_KEYS = (
    "name",
    "slug",
    "spaceSlug",
    "tableName",
    "metricQuery",
    "chartConfig",
)
DASHBOARD_KEYS = (
    "name",
    "slug",
    "spaceSlug",
    "tiles",
)
TILE_KEYS = (
    "type",
    "x",
    "y",
    "w",
    "h",
    "properties",
)
FILTER_KINDS = ("dimensions", "metrics", "tableCalculations")
SAVED_CHART = "saved_chart"

# Optional keys that Lightdash resets when an upload leaves them out (CoderService.upsertChart and
# upsertDashboard default tableConfig and filters to empty ones): on replace, the ones the caller
# didn't give keep their value.
KEPT: dict[Kind, tuple[str, ...]] = {
    "charts": (
        "description",
        "tableConfig",
        "pivotConfig",
        "parameters",
    ),
    "dashboards": (
        "description",
        "tabs",
        "filters",
        "config",
        "parameters",
    ),
}
# Keys that change on every download or upload, left out of the changes a dry run lists.
UNCOMPARED = {
    "version",
    "updatedAt",
    "downloadedAt",
    "contentType",
}


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def get_chart_code(project_uuid: Uuid, slug: Slug) -> dict[str, Any]:
        """Read a saved chart as code, in the format save_chart takes: its explore, fields, filters,
        sorts and chart configuration. Use it to change a chart, or as an example before writing a
        new one.
        Find slugs with search_content."""
        async with lightdash(provider) as client:
            chart = await _existing(
                client,
                project_uuid,
                "charts",
                slug,
            )

        if chart is None:
            raise ToolError(f"No chart with slug {slug} in this project.")

        return chart

    @server.tool(annotations=READ)
    async def get_dashboard_code(project_uuid: Uuid, slug: Slug) -> dict[str, Any]:
        """Read a dashboard as code, in the format save_dashboard takes: its tiles with their
        position and the slug of each chart, its tabs and its filters. Find slugs with
        search_content."""
        async with lightdash(provider) as client:
            dashboard = await _existing(
                client,
                project_uuid,
                "dashboards",
                slug,
            )

        if dashboard is None:
            raise ToolError(f"No dashboard with slug {slug} in this project.")

        return dashboard

    @server.tool(annotations=DESTRUCTIVE)
    async def save_chart(
        project_uuid: Uuid, chart: dict[str, Any], dry_run: bool = True
    ) -> dict[str, Any]:
        """Create a chart, or replace the chart with the same slug, from chart code: name, slug,
        spaceSlug, tableName (the explore), metricQuery (exploreName, dimensions, metrics, filters,
        sorts, limit, tableCalculations) and chartConfig, as get_chart_code returns them. Fields
        must exist in the explore: see get_explore. spaceSlug is a space's path, such as
        parent/child: see list_spaces. One that doesn't exist yet creates a space only you and
        admins can see. On replace, description, tableConfig, pivotConfig and parameters left out
        keep their current value.
        dry_run, on by default, checks the chart and says whether it would create or replace one,
        and what changes.
        Pass dry_run=false to save; the result has the chart's URL and Lightdash's validation
        errors."""
        _require(chart, CHART_KEYS, "chart")

        async with lightdash(provider) as client:
            await check_chart(client, project_uuid, chart)
            existing = await _existing(
                client,
                project_uuid,
                "charts",
                chart["slug"],
            )
            item = keep_existing("charts", {"version": 1, **chart}, existing)

            if dry_run:
                return await preview(
                    client,
                    project_uuid,
                    "charts",
                    item,
                    existing,
                )

            return await save(
                client,
                project_uuid,
                "charts",
                item,
                provider.settings.lightdash_url,
            )

    @server.tool(annotations=DESTRUCTIVE)
    async def save_dashboard(
        project_uuid: Uuid, dashboard: dict[str, Any], dry_run: bool = True
    ) -> dict[str, Any]:
        """Create a dashboard, or replace the dashboard with the same slug, from dashboard code:
        name, slug, spaceSlug and tiles, as get_dashboard_code returns them. A tile has type
        (saved_chart, markdown), x, y, w and h on a 36-column grid, and properties: chartSlug for a
        saved chart, title and content for markdown. tabs and filters are optional; on replace, the
        ones left out, and description, config and parameters, keep their current value. Its
        charts must be saved, with save_chart and dry_run=false, before the dashboard itself can be
        saved; a dry run lists the ones that aren't yet.
        dry_run, on by default, checks the dashboard and says whether it would create or replace
        one, and what changes, with the tile, tab and filter counts before and after. Pass
        dry_run=false to save; the result has the dashboard's URL."""
        _require(dashboard, DASHBOARD_KEYS, "dashboard")

        async with lightdash(provider) as client:
            missing = await check_dashboard(client, project_uuid, dashboard)
            existing = await _existing(
                client,
                project_uuid,
                "dashboards",
                dashboard["slug"],
            )
            kept = keep_existing("dashboards", {"version": 1, **dashboard}, existing)
            item = {"tabs": [], **kept}

            if dry_run:
                result = await preview(
                    client,
                    project_uuid,
                    "dashboards",
                    item,
                    existing,
                )
                return _with_missing_charts(result, missing)

            if missing:
                raise ToolError(
                    f"No chart with slug {', '.join(missing)} in this project yet. "
                    "Save it with save_chart and dry_run=false first."
                )

            return await save(
                client,
                project_uuid,
                "dashboards",
                item,
                provider.settings.lightdash_url,
            )


async def _existing(
    client: LightdashClient,
    project_uuid: str,
    kind: Kind,
    slug: str,
) -> dict[str, Any] | None:
    found = await _read(
        client,
        project_uuid,
        kind,
        [slug],
    )
    items = found[kind]

    return items[0] if items else None


async def _read(
    client: LightdashClient,
    project_uuid: str,
    kind: Kind,
    slugs: list[str],
) -> dict[str, Any]:
    return await client.get(f"/api/v1/projects/{project_uuid}/code/{kind}", ids=slugs)


def _require(item: dict[str, Any], keys: tuple[str, ...], kind: str) -> None:
    missing = [key for key in keys if item.get(key) in (None, "")]

    if missing:
        raise ToolError(
            f"The {kind} needs {', '.join(missing)}. "
            f"Read one with get_{kind}_code to see the format."
        )

    if not conforms(Slug, item["slug"]):
        raise ToolError(
            f"Invalid slug {item['slug']!r}: use lowercase letters, digits and hyphens, "
            "such as my-team-ci-health."
        )


async def check_chart(client: LightdashClient, project_uuid: str, chart: dict[str, Any]) -> None:
    """Fail before saving when the chart is malformed or refers to fields its explore doesn't
    have."""
    query = chart["metricQuery"]

    if not isinstance(query, dict):
        raise ToolError("metricQuery must be an object.")

    explore = query.get("exploreName") or chart["tableName"]

    if not conforms(Name, explore):
        raise ToolError(f"Invalid explore {explore!r}.")

    found = await load_explore(client, project_uuid, explore)
    known = _known_fields(found, query)
    used = _used_fields(query)
    unknown = sorted(used - known)

    if unknown:
        raise ToolError(f"Unknown fields in {explore}: {', '.join(unknown)}. See get_explore.")


def _known_fields(explore: dict[str, Any], query: dict[str, Any]) -> set[str]:
    # Hidden fields are only left out of the sidebar: a chart can use them.
    dimensions = explore_fields(explore, "dimensions", include_hidden=True)
    metrics = explore_fields(explore, "metrics", include_hidden=True)
    calculations = _entries(query, "tableCalculations", "name")
    custom_dimensions = _entries(query, "customDimensions", "id")
    additional_metrics = _entries(
        query,
        "additionalMetrics",
        "table",
        "name",
    )

    known = {*dimensions, *metrics}
    known |= {calculation["name"] for calculation in calculations}
    known |= {dimension["id"] for dimension in custom_dimensions}
    known |= {f"{metric['table']}_{metric['name']}" for metric in additional_metrics}

    return known


def _entries(query: dict[str, Any], key: str, *fields: str) -> list[dict[str, Any]]:
    entries = query.get(key) or []
    is_valid = isinstance(entries, list) and all(
        _has_string_fields(entry, fields) for entry in entries
    )

    if not is_valid:
        raise ToolError(f"Each of metricQuery.{key} needs {' and '.join(fields)}.")

    return entries


def _has_string_fields(entry: Any, fields: tuple[str, ...]) -> bool:
    if not isinstance(entry, dict):
        return False

    return all(isinstance(entry.get(field), str) for field in fields)


def _used_fields(query: dict[str, Any]) -> set[str]:
    dimensions = _field_list(query, "dimensions")
    metrics = _field_list(query, "metrics")
    sorts = _entries(query, "sorts", "fieldId")

    used = {*dimensions, *metrics}
    used |= {sort["fieldId"] for sort in sorts}
    used |= _field_ids(query.get("filters") or {})

    return used


def _field_list(query: dict[str, Any], key: str) -> list[str]:
    values = query.get(key) or []
    is_valid = isinstance(values, list) and all(isinstance(value, str) for value in values)

    if not is_valid:
        raise ToolError(f"metricQuery.{key} must be a list of field IDs.")

    return values


def _field_ids(value: Any) -> set[str]:
    """Every field a filter group refers to, nested and/or groups included."""
    if isinstance(value, dict):
        own = _target_field_id(value)
        nested = [_field_ids(child) for child in value.values()]
        return own.union(*nested)

    if isinstance(value, list):
        nested = [_field_ids(child) for child in value]
        return set().union(*nested)

    return set()


def _target_field_id(rule: dict[str, Any]) -> set[str]:
    target = rule.get("target")
    has_field_id = isinstance(target, dict) and isinstance(target.get("fieldId"), str)

    if not has_field_id:
        return set()

    return {target["fieldId"]}


def keep_existing(
    kind: Kind, item: dict[str, Any], existing: dict[str, Any] | None
) -> dict[str, Any]:
    kept: dict[str, Any] = {}

    if existing:
        kept = {key: existing[key] for key in KEPT[kind] if key in existing and key not in item}

    return kept | item


async def preview(
    client: LightdashClient,
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

    space_exists = await _space_exists(client, project_uuid, item["spaceSlug"])

    if not space_exists:
        summary["newSpace"] = (
            "Lightdash creates this space, visible only to you and admins until you share it."
        )

    singular = kind[:-1]
    outcome = "wouldUpdate" if existing else "wouldCreate"

    return {
        outcome: summary,
        "next": (
            f"Nothing is saved yet. Call save_{singular} again with dry_run=false "
            f"to save this {singular}."
        ),
    }


def _counts(dashboard: dict[str, Any]) -> dict[str, int]:
    filters = dashboard.get("filters") or {}
    filter_count = sum(len(filters.get(kind) or []) for kind in FILTER_KINDS)

    return {
        "tiles": len(dashboard.get("tiles") or []),
        "tabs": len(dashboard.get("tabs") or []),
        "filters": filter_count,
    }


async def _space_exists(client: LightdashClient, project_uuid: str, slug: str) -> bool:
    spaces = await client.get(f"/api/v1/projects/{project_uuid}/spaces")
    return any(space_slug(space) == slug for space in spaces)


async def save(
    client: LightdashClient,
    project_uuid: str,
    kind: Kind,
    item: dict[str, Any],
    lightdash_url: str,
) -> dict[str, Any]:
    # Without force, Lightdash skips a chart update whose name, description and slug are unchanged
    # and whose updatedAt isn't newer (PromoteService.isChartUpdated). Dashboards always update and
    # ignore it.
    body = item | {"skipSpaceCreate": False, "publicSpaceCreate": False, "force": True}
    path = f"/api/v1/projects/{project_uuid}/code/{kind}/{item['slug']}"
    results = await client.request("POST", path, json=body)
    saved = results[kind][0]
    uuid = saved["data"]["uuid"]
    page = "saved" if kind == "charts" else "dashboards"
    result = {
        "action": saved["action"],
        "uuid": uuid,
        "url": f"{lightdash_url}/projects/{project_uuid}/{page}/{uuid}",
    }

    if results.get("warnings"):
        result["warnings"] = results["warnings"]

    # The content is saved by now: a validation failure is reported, not raised.
    singular = kind[:-1]
    result |= await _validate(
        client,
        project_uuid,
        singular,
        uuid,
    )
    return result


async def _validate(
    client: LightdashClient,
    project_uuid: str,
    singular: str,
    uuid: str,
) -> dict[str, Any]:
    path = f"/api/v1/projects/{project_uuid}/validate/{singular}/{uuid}"

    try:
        validation = await client.request("POST", path, json={})
    except LightdashError as error:
        if error.status == 401:
            raise

        message = f"The {singular} is saved, but Lightdash couldn't validate it: {error.message}"
        return {"validationFailed": message}
    except httpx.HTTPError:
        message = f"The {singular} is saved, but Lightdash didn't answer its validation."
        return {"validationFailed": message}

    errors = [
        {"field": problem.get("fieldName"), "error": problem.get("error")}
        for problem in validation["errors"]
    ]
    return {"validationErrors": errors}


async def check_dashboard(
    client: LightdashClient, project_uuid: str, dashboard: dict[str, Any]
) -> list[str]:
    """Fail when a tile is malformed. Return the chart slugs its tiles show that don't exist yet:
    Lightdash would save those tiles empty, so saving fails until they exist, but a dry run only
    reports them."""
    tiles = dashboard["tiles"]

    if not isinstance(tiles, list):
        raise ToolError("tiles must be a list.")

    for index, tile in enumerate(tiles):
        _check_tile(index, tile)

    chart_tiles = [tile for tile in tiles if tile["type"] == SAVED_CHART]
    slugs = sorted({tile["properties"]["chartSlug"] for tile in chart_tiles})

    if not slugs:
        return []

    found = await _read(
        client,
        project_uuid,
        "charts",
        slugs,
    )
    missing = found.get("missingIds") or []

    return sorted(missing)


def _check_tile(index: int, tile: Any) -> None:
    missing = [key for key in TILE_KEYS if not isinstance(tile, dict) or key not in tile]

    if missing:
        raise ToolError(f"Tile {index} needs {', '.join(missing)}.")

    properties = tile["properties"]

    if not isinstance(properties, dict):
        raise ToolError(f"Tile {index} properties must be an object.")

    has_chart_slug = isinstance(properties.get("chartSlug"), str)

    if tile["type"] == SAVED_CHART and not has_chart_slug:
        raise ToolError(f"Tile {index} is a saved_chart tile without properties.chartSlug.")


def _with_missing_charts(result: dict[str, Any], missing: list[str]) -> dict[str, Any]:
    if not missing:
        return result

    next_step = (
        f"Nothing is saved yet. Save {', '.join(missing)} with save_chart and dry_run=false, "
        "then call save_dashboard with dry_run=false."
    )

    return result | {"chartsNotSavedYet": missing, "next": next_step}
