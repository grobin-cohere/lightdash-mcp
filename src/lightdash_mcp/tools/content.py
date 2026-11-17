"""Content: finding charts and dashboards, reading dashboards, unused content, validation errors,
moving and deleting."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, WRITE, Uuid, lightdash
from lightdash_mcp.tools.shared import every_page

ContentType = Literal["chart", "dashboard", "space"]

CHARTS_AND_DASHBOARDS = ("chart", "dashboard")
MAX_VALIDATION_POLLS = 120
VALIDATION_POLL_INTERVAL = 1
JOB_FINISHED = ("completed", "error")


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def search_content(
        project_uuid: Uuid,
        search: str | None = None,
        content_type: Literal["chart", "dashboard"] | None = None,
    ) -> list[dict[str, Any]]:
        """Find charts and dashboards by name, or list them all without search.
        Run a chart with run_chart, and open a dashboard with get_dashboard."""
        async with lightdash(provider) as client:
            items = await _content(
                client,
                project_uuid,
                search=search,
                contentTypes=content_type or CHARTS_AND_DASHBOARDS,
            )

        return [_search_result(item) for item in items]

    @server.tool(annotations=READ)
    async def get_dashboard(dashboard_uuid: Uuid) -> dict[str, Any]:
        """Show a dashboard's filters and tiles in layout order: its charts, to run with run_chart
        and the dashboard's UUID, and its text."""
        async with lightdash(provider) as client:
            dashboard = await client.get(f"/api/v1/dashboards/{dashboard_uuid}")

        tabs = sorted(dashboard.get("tabs") or [], key=lambda tab: tab["order"])
        tab_names = {tab["uuid"]: tab["name"] for tab in tabs}
        tab_positions = {tab["uuid"]: position for position, tab in enumerate(tabs)}
        tiles = sorted(
            dashboard["tiles"],
            key=lambda tile: _layout_position(tile, tab_positions),
        )
        filters = dashboard.get("filters") or {}
        dashboard_filters = [*filters.get("dimensions", []), *filters.get("metrics", [])]

        return {
            "name": dashboard["name"],
            "slug": dashboard.get("slug"),
            "description": dashboard.get("description"),
            "projectUuid": dashboard["projectUuid"],
            "space": dashboard.get("spaceName"),
            "filters": [_filter_summary(rule) for rule in dashboard_filters],
            "tiles": [_tile(tile, tab_names) for tile in tiles],
        }

    @server.tool(annotations=READ)
    async def find_unused_content(
        project_uuid: Uuid,
        unused_days: int = 90,
        content_type: Literal["chart", "dashboard"] | None = None,
    ) -> list[dict[str, Any]]:
        """Find charts and dashboards nobody has viewed in `unused_days` days, never-viewed first.
        Content created within that window is left out, and so is viewed content whose last view
        date Lightdash doesn't record."""
        async with lightdash(provider) as client:
            items = await _content(
                client,
                project_uuid,
                contentTypes=content_type or CHARTS_AND_DASHBOARDS,
            )

        return unused_content(items, unused_days)

    @server.tool(annotations=READ)
    async def list_validation_errors(
        project_uuid: Uuid, revalidate: bool = False
    ) -> list[dict[str, Any]]:
        """List broken charts and dashboards: fields that no longer exist, bad configurations.
        Results come from the last validation run; set revalidate to run a fresh one first."""
        async with lightdash(provider) as client:
            if revalidate:
                await _revalidate(client, project_uuid)

            errors = await client.get(f"/api/v1/projects/{project_uuid}/validate")

        return [_validation_error(error) for error in errors]

    @server.tool(annotations=WRITE)
    async def move_content(
        project_uuid: Uuid,
        content_type: ContentType,
        uuid: Uuid,
        target_space_uuid: Uuid,
    ) -> str:
        """Move a chart, dashboard or space into another space."""
        async with lightdash(provider) as client:
            item = await _item(
                client,
                project_uuid,
                content_type,
                uuid,
            )
            body = {
                "item": _payload(item),
                "action": {"type": "move", "targetSpaceUuid": target_space_uuid},
            }
            await client.request("POST", f"/api/v2/content/{project_uuid}/move", json=body)

        return f'Moved {content_type} "{item["name"]}".'

    @server.tool(annotations=DESTRUCTIVE)
    async def delete_content(
        project_uuid: Uuid,
        content_type: ContentType,
        uuid: Uuid,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Delete a chart, dashboard or space. A space is deleted with everything in it.
        dry_run, on by default, shows what would be deleted. Pass dry_run=false to delete."""
        async with lightdash(provider) as client:
            item = await _item(
                client,
                project_uuid,
                content_type,
                uuid,
            )
            impact: dict[str, Any] = {"item": _summary(item)}

            if content_type == "space":
                path = f"/api/v1/projects/{project_uuid}/spaces/{uuid}/delete-impact"
                found = await client.get(path)
                impact["includes"] = _names_by_kind(found)

            if dry_run:
                return {"wouldDelete": impact}

            body = {"item": _payload(item), "action": {"type": "delete"}}
            await client.request("POST", f"/api/v2/content/{project_uuid}/delete", json=body)

        return {"deleted": impact}


async def _content(
    client: LightdashClient, project_uuid: str, **params: Any
) -> list[dict[str, Any]]:
    return await every_page(
        client,
        "/api/v2/content",
        projectUuids=project_uuid,
        **params,
    )


def _search_result(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **_summary(item),
        "description": item.get("description"),
        "views": item.get("views"),
        "lastUpdatedAt": item.get("lastUpdatedAt"),
    }


def _summary(item: dict[str, Any]) -> dict[str, Any]:
    space = item.get("space") or {}
    return {
        "contentType": item["contentType"],
        "uuid": item["uuid"],
        "slug": item.get("slug"),
        "name": item["name"],
        "space": space.get("name"),
    }


def _layout_position(tile: dict[str, Any], tab_positions: dict[str, int]) -> tuple[int, int, int]:
    tab_position = tab_positions.get(tile.get("tabUuid"), 0)
    return (tab_position, tile["y"], tile["x"])


def _filter_summary(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "fieldId": rule["target"]["fieldId"],
        "operator": rule["operator"],
        "values": rule.get("values"),
        "disabled": rule.get("disabled", False),
    }


def _tile(tile: dict[str, Any], tabs: dict[str, str]) -> dict[str, Any]:
    properties = tile["properties"]
    summary = {
        "type": tile["type"],
        "title": properties.get("title") or properties.get("chartName"),
    }

    if tabs:
        summary["tab"] = tabs.get(tile.get("tabUuid"))

    if tile["type"] == "saved_chart":
        summary |= {
            "chartUuid": properties.get("savedChartUuid"),
            "chartSlug": properties.get("chartSlug"),
            "chartKind": properties.get("lastVersionChartKind"),
        }
    elif tile["type"] == "markdown":
        summary["content"] = properties.get("content")

    return summary


def unused_content(items: list[dict[str, Any]], unused_days: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC) - timedelta(days=unused_days)

    def is_before_cutoff(value: str) -> bool:
        return datetime.fromisoformat(value) < cutoff

    def is_unused(item: dict[str, Any]) -> bool:
        if not is_before_cutoff(item["createdAt"]):
            return False

        if item.get("lastViewedAt"):
            return is_before_cutoff(item["lastViewedAt"])

        # Lightdash leaves lastViewedAt null for some content it counts views of (ContentModel), so
        # null alone doesn't mean never viewed.
        return not item.get("views")

    unused = filter(is_unused, items)
    never_viewed_first = sorted(unused, key=_view_order)

    return [_unused_summary(item) for item in never_viewed_first]


def _view_order(item: dict[str, Any]) -> tuple[str, str]:
    last_viewed = item.get("lastViewedAt") or ""
    return (last_viewed, item["createdAt"])


def _unused_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **_summary(item),
        "views": item.get("views"),
        "lastViewedAt": item.get("lastViewedAt"),
        "createdAt": item["createdAt"],
        "lastUpdatedAt": item.get("lastUpdatedAt"),
    }


async def _revalidate(client: LightdashClient, project_uuid: str) -> None:
    job = await client.request("POST", f"/api/v1/projects/{project_uuid}/validate")
    status = await _wait_for_job(client, job["jobId"])

    if status != "completed":
        raise ToolError(f"Validation did not complete (status: {status}).")


async def _wait_for_job(client: LightdashClient, job_id: str) -> str:
    """The job's status once it finishes, or its last status after MAX_VALIDATION_POLLS polls."""
    path = f"/api/v1/schedulers/job/{job_id}/status"

    for _ in range(MAX_VALIDATION_POLLS):
        job = await client.get(path)
        status = job["status"]

        if status in JOB_FINISHED:
            return status

        await asyncio.sleep(VALIDATION_POLL_INTERVAL)

    return status


def _validation_error(error: dict[str, Any]) -> dict[str, Any]:
    broken_uuid = error.get("chartUuid") or error.get("dashboardUuid") or error.get("tableName")
    return {
        "source": error.get("source"),
        "name": error.get("name"),
        "uuid": broken_uuid,
        "errorType": error.get("errorType"),
        "error": error.get("error"),
        "fieldName": error.get("fieldName"),
        "views": error.get("chartViews", error.get("dashboardViews")),
        "lastUpdatedBy": error.get("lastUpdatedBy"),
    }


async def _item(
    client: LightdashClient,
    project_uuid: str,
    content_type: ContentType,
    uuid: str,
) -> dict[str, Any]:
    # Check the UUID rather than trust the filter: deleting the wrong space deletes
    # everything in it.
    items = await _content(
        client,
        project_uuid,
        uuids=uuid,
        contentTypes=content_type,
    )
    matching = (
        found
        for found in items
        if found["uuid"] == uuid.lower() and found["contentType"] == content_type
    )
    item = next(matching, None)

    if item is None:
        raise ToolError(f"No {content_type} {uuid} in this project.")

    return item


def _payload(item: dict[str, Any]) -> dict[str, Any]:
    payload = {"contentType": item["contentType"], "uuid": item["uuid"]}

    if item["contentType"] == "chart":
        payload["source"] = item["source"]

    return payload


def _names_by_kind(impact: dict[str, Any]) -> dict[str, list[Any]]:
    listed = {kind: items for kind, items in impact.items() if isinstance(items, list) and items}
    return {kind: _names(items) for kind, items in listed.items()}


def _names(items: list[dict[str, Any]]) -> list[Any]:
    return [item.get("name") for item in items]
