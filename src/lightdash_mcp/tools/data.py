"""Data: explores, their fields, metric queries on the semantic layer, and saved charts."""

import asyncio
import contextlib
import uuid
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient
from lightdash_mcp.tools.common import READ, ChartRef, Name, Uuid, lightdash, resolve_chart

Operator = Literal[
    "isNull",
    "notNull",
    "equals",
    "notEquals",
    "startsWith",
    "endsWith",
    "include",
    "doesNotInclude",
    "lessThan",
    "lessThanOrEqual",
    "greaterThan",
    "greaterThanOrEqual",
    "inThePast",
    "notInThePast",
    "inTheNext",
    "inTheCurrent",
    "notInTheCurrent",
    "inBetween",
    "notInBetween",
]

MAX_ROWS = 2500  # Lightdash's default largest results page
QUERY_TIMEOUT = 120
CANCEL_TIMEOUT = 10
POLL_INTERVAL = 0.5
RUNNING = ("pending", "queued", "executing")


class Filter(BaseModel):
    field_id: str
    operator: Operator
    values: list[Any] = []
    settings: dict[str, Any] | None = None


class Sort(BaseModel):
    field_id: str
    descending: bool = False


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def list_explores(project_uuid: Uuid) -> list[dict[str, Any]]:
        """List the explores of a project: the tables you can query, with what each one holds.
        Tables that the project's tables configuration hides are left out, as in Lightdash."""
        async with lightdash(provider) as client:
            return await _explores(client, project_uuid)

    @server.tool(annotations=READ)
    async def get_explore(project_uuid: Uuid, explore: Name) -> dict[str, Any]:
        """List an explore's dimensions and metrics, joined tables included. Their field IDs go into
        run_query.
        Date dimensions come with one field per interval, such as orders_order_date_month."""
        async with lightdash(provider) as client:
            found = await load_explore(client, project_uuid, explore)

        base = found["tables"][found["baseTable"]]
        dimensions = explore_fields(found, "dimensions").values()
        metrics = explore_fields(found, "metrics").values()

        return {
            "name": found["name"],
            "label": found.get("label"),
            "description": base.get("description"),
            "dimensions": [_summary(field) for field in dimensions],
            "metrics": [_summary(field) for field in metrics],
        }

    @server.tool(annotations=READ)
    async def run_query(
        project_uuid: Uuid,
        explore: Name,
        dimensions: list[str] | None = None,
        metrics: list[str] | None = None,
        filters: list[Filter] | None = None,
        sorts: list[Sort] | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Query an explore by field ID: group by the dimensions, aggregate the metrics, all filters
        combined with AND.
        A filter on a metric applies after aggregation. Date filters such as inThePast take values
        [n] and settings {"unitOfTime": "days"}; inBetween takes two values. Returns up to `limit`
        rows, at most 2500; truncated is true when more rows match."""
        dimensions = dimensions or []
        metrics = metrics or []
        filters = filters or []
        sorts = sorts or []

        if not dimensions and not metrics:
            raise ToolError("Give at least one dimension or metric.")

        async with lightdash(provider) as client:
            found = await load_explore(client, project_uuid, explore)
            known_dimensions = explore_fields(found, "dimensions")
            known_metrics = explore_fields(found, "metrics")
            known_fields = known_dimensions | known_metrics
            requested = _requested_fields(
                dimensions,
                metrics,
                filters,
                sorts,
            )
            unknown = [field_id for field_id in requested if field_id not in known_fields]

            if unknown:
                raise ToolError(
                    f"Unknown fields in {explore}: {', '.join(unknown)}. See get_explore."
                )

            rows = max(1, min(limit, MAX_ROWS))
            filter_groups = _filter_groups(filters, known_dimensions, known_metrics)
            query = _metric_query(
                explore,
                dimensions,
                metrics,
                filter_groups,
                sorts,
                rows,
            )
            results = await _run(
                client,
                project_uuid,
                "metric-query",
                {"query": query},
                rows,
            )

        return _table(results)

    @server.tool(annotations=READ)
    async def run_chart(
        project_uuid: Uuid, chart_uuid: ChartRef, dashboard_uuid: Uuid | None = None
    ) -> dict[str, Any]:
        """Run a saved chart as it is saved: its fields, filters, sorts and row limit. chart_uuid is
        the chart's UUID or its slug. Give dashboard_uuid to apply that dashboard's filters too, as
        people see it on the dashboard. Returns at most 2500 rows; truncated is true when there are
        more."""
        async with lightdash(provider) as client:
            chart_uuid = await resolve_chart(client, project_uuid, chart_uuid)

            if dashboard_uuid is None:
                body = {"chartUuid": chart_uuid}
                results = await _run(
                    client,
                    project_uuid,
                    "chart",
                    body,
                    MAX_ROWS,
                )
            else:
                results = await _run_on_dashboard(
                    client,
                    project_uuid,
                    chart_uuid,
                    dashboard_uuid,
                )

        return _table(results)


async def _explores(client: LightdashClient, project_uuid: str) -> list[dict[str, Any]]:
    # filtered=true applies the project's tables configuration, as Lightdash's own explore list
    # does, so the tables an admin hid in Lightdash stay hidden here too.
    explores = await client.get(f"/api/v1/projects/{project_uuid}/explores", filtered="true")
    return [_explore_summary(explore) for explore in explores]


def _explore_summary(explore: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "name": explore["name"],
        "label": explore.get("label"),
        "group": explore.get("groupLabel"),
        "description": explore.get("description"),
    }

    if explore.get("errors"):
        summary["errors"] = [error.get("message") for error in explore["errors"]]

    return summary


async def load_explore(client: LightdashClient, project_uuid: str, explore: str) -> dict[str, Any]:
    found = await client.get(f"/api/v1/projects/{project_uuid}/explores/{explore}")

    if "tables" not in found:
        raise ToolError(f"Explore {explore} has errors: {found.get('errors')}")

    return found


def explore_fields(
    explore: dict[str, Any], kind: Literal["dimensions", "metrics"], include_hidden: bool = False
) -> dict[str, dict[str, Any]]:
    tables = explore["tables"].values()
    fields = [field for table in tables for field in table[kind].values()]
    visible = [field for field in fields if include_hidden or not field.get("hidden")]
    return {_field_id(field): field for field in visible}


def _field_id(field: dict[str, Any]) -> str:
    name = field["name"].replace(".", "__")
    return f"{field['table']}_{name}"


def _summary(field: dict[str, Any]) -> dict[str, Any]:
    return {
        "fieldId": _field_id(field),
        "label": field.get("label"),
        "type": field.get("type"),
        "table": field.get("tableLabel"),
        "description": field.get("description"),
    }


def _requested_fields(
    dimensions: list[str],
    metrics: list[str],
    filters: list[Filter],
    sorts: list[Sort],
) -> list[str]:
    filter_fields = [rule.field_id for rule in filters]
    sort_fields = [sort.field_id for sort in sorts]

    return [*dimensions, *metrics, *filter_fields, *sort_fields]


def _filter_groups(
    filters: list[Filter],
    known_dimensions: dict[str, Any],
    known_metrics: dict[str, Any],
) -> dict[str, Any]:
    dimension_filters = [rule for rule in filters if rule.field_id in known_dimensions]
    metric_filters = [rule for rule in filters if rule.field_id in known_metrics]
    groups = {
        "dimensions": _filter_group(dimension_filters),
        "metrics": _filter_group(metric_filters),
    }
    return {kind: group for kind, group in groups.items() if group}


def _filter_group(filters: list[Filter]) -> dict[str, Any] | None:
    if not filters:
        return None

    rules = [_filter_rule(rule) for rule in filters]
    return {"id": str(uuid.uuid4()), "and": rules}


def _filter_rule(rule: Filter) -> dict[str, Any]:
    built = {
        "id": str(uuid.uuid4()),
        "target": {"fieldId": rule.field_id},
        "operator": rule.operator,
        "values": rule.values,
    }

    if rule.settings:
        built["settings"] = rule.settings

    return built


def _metric_query(
    explore: str,
    dimensions: list[str],
    metrics: list[str],
    filter_groups: dict[str, Any],
    sorts: list[Sort],
    rows: int,
) -> dict[str, Any]:
    return {
        "exploreName": explore,
        "dimensions": dimensions,
        "metrics": metrics,
        "filters": filter_groups,
        "sorts": [{"fieldId": sort.field_id, "descending": sort.descending} for sort in sorts],
        # One row more than returned: Lightdash counts it, so truncated is exact.
        "limit": rows + 1,
        "tableCalculations": [],
    }


async def _run(
    client: LightdashClient,
    project_uuid: str,
    endpoint: str,
    body: dict[str, Any],
    page_size: int,
) -> dict[str, Any]:
    """Start a Lightdash query, wait for it, and return its first page of results."""
    started = await client.request(
        "POST",
        f"/api/v2/projects/{project_uuid}/query/{endpoint}",
        json=body | {"context": "api"},
    )
    path = f"/api/v2/projects/{project_uuid}/query/{started['queryUuid']}"

    try:
        results = await _wait_for(client, path, page_size)
    except BaseException as error:
        # Timed out, failed to poll or cancelled by the client: don't leave the query running in
        # the warehouse.
        await _cancel(client, path)

        if isinstance(error, TimeoutError):
            raise ToolError(
                f"The query took more than {QUERY_TIMEOUT} seconds and was cancelled."
            ) from None

        raise

    if results["status"] != "ready":
        raise ToolError(f"The query failed ({results['status']}): {results.get('error')}")

    return results


async def _wait_for(client: LightdashClient, path: str, page_size: int) -> dict[str, Any]:
    async with asyncio.timeout(QUERY_TIMEOUT):
        results = await client.get(path, pageSize=page_size)

        while results["status"] in RUNNING:
            await asyncio.sleep(POLL_INTERVAL)
            results = await client.get(path, pageSize=page_size)

    return results


async def _cancel(client: LightdashClient, path: str) -> None:
    with contextlib.suppress(Exception):
        async with asyncio.timeout(CANCEL_TIMEOUT):
            await client.request("POST", f"{path}/cancel")


def _table(results: dict[str, Any]) -> dict[str, Any]:
    rows = [_raw_values(row) for row in results["rows"]]
    columns = results["columns"].items()

    return {
        "columns": {field_id: column.get("label") for field_id, column in columns},
        "rows": rows,
        "truncated": results["totalResults"] > len(rows),
    }


def _raw_values(row: dict[str, Any]) -> dict[str, Any]:
    return {field_id: cell["value"]["raw"] for field_id, cell in row.items()}


async def _run_on_dashboard(
    client: LightdashClient,
    project_uuid: str,
    chart_uuid: str,
    dashboard_uuid: str,
) -> dict[str, Any]:
    dashboard = await client.get(f"/api/v1/dashboards/{dashboard_uuid}")

    if dashboard.get("projectUuid") != project_uuid:
        raise ToolError("This dashboard is not in this project.")

    tile = _chart_tile(dashboard, chart_uuid)

    if tile is None:
        raise ToolError("This chart is not on the dashboard. See get_dashboard.")

    body = {
        "chartUuid": chart_uuid,
        "tileUuid": tile["uuid"],
        "dashboardUuid": dashboard_uuid,
        "dashboardFilters": dashboard["filters"],
        "dashboardSorts": [],
    }

    return await _run(
        client,
        project_uuid,
        "dashboard-chart",
        body,
        MAX_ROWS,
    )


def _chart_tile(dashboard: dict[str, Any], chart_uuid: str) -> dict[str, Any] | None:
    tiles = dashboard["tiles"]
    return next(
        (tile for tile in tiles if tile["properties"].get("savedChartUuid") == chart_uuid),
        None,
    )
