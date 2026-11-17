import base64
import json

import httpx
import pytest
import respx
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.lightdash import LightdashError
from lightdash_mcp.server import asgi_app, create_server
from lightdash_mcp.tools.code import (
    _require,
    check_chart,
    check_dashboard,
    keep_existing,
    preview,
    save,
)
from lightdash_mcp.tools.common import resolve_chart

from .conftest import LIGHTDASH, PROJECT

CHART_UUID = "d83eaf7e-e041-4a89-af83-e64450cfd524"
DASHBOARD_UUID = "4c2b1a09-8f7e-4d6c-9b5a-3e2f1d0c9b8a"

PROJECT_URL = f"{LIGHTDASH}/api/v1/projects/{PROJECT}"
EXPLORE_URL = f"{PROJECT_URL}/explores/orders"
SPACES_URL = f"{PROJECT_URL}/spaces"
CODE_URL = f"{PROJECT_URL}/code"
VALIDATE_URL = f"{PROJECT_URL}/validate/chart/{CHART_UUID}"
SAVED_URL = f"{LIGHTDASH}/api/v1/saved"

DEX_REDIRECT = "http://localhost:5556/dex/callback"
DEX_VERIFIER = "verifier" * 6

EXPLORE = {
    "name": "orders",
    "baseTable": "orders",
    "tables": {
        "orders": {
            "dimensions": {
                "status": {"table": "orders", "name": "status"},
                "order_date_week": {"table": "orders", "name": "order_date_week"},
            },
            "metrics": {
                "revenue": {"table": "orders", "name": "revenue"},
                "cost": {"table": "orders", "name": "cost", "hidden": True},
            },
        }
    },
}

CHART = {
    "name": "Revenue per week",
    "slug": "revenue-per-week",
    "spaceSlug": "my-team",
    "tableName": "orders",
    "metricQuery": {
        "exploreName": "orders",
        "dimensions": ["orders_order_date_week"],
        "metrics": ["orders_revenue"],
        "filters": {
            "dimensions": {
                "id": "g",
                "and": [{"id": "r", "target": {"fieldId": "orders_status"}, "operator": "equals"}],
            }
        },
        "sorts": [{"fieldId": "orders_order_date_week", "descending": False}],
        "limit": 500,
        "tableCalculations": [{"name": "revenue_share", "sql": "1"}],
    },
    "chartConfig": {"type": "cartesian", "config": {}},
}

TILE = {
    "type": "markdown",
    "x": 0,
    "y": 0,
    "w": 36,
    "h": 4,
    "properties": {"title": "Hi", "content": "Hello"},
}
CHART_TILE = {
    "type": "saved_chart",
    "x": 0,
    "y": 0,
    "w": 36,
    "h": 8,
    "properties": {"chartSlug": "revenue-per-week"},
}
DASHBOARD = {
    "name": "Sales",
    "slug": "sales",
    "spaceSlug": "my-team",
    "tiles": [TILE],
}

SPACE_CREATED = "Space my-team was created"


def results(value) -> httpx.Response:
    return httpx.Response(200, json={"results": value})


def chart_with(query_change: dict) -> dict:
    """CHART, with these keys of its metric query changed."""
    query = CHART["metricQuery"] | query_change

    return CHART | {"metricQuery": query}


def space_at(path: str) -> dict:
    return {"slug": path.split(".")[-1], "path": path}


def mock_lightdash(
    existing: list[dict] | None = None,
    spaces: list[str] = ("my_team",),
    missing: list[str] = (),
):
    respx.get(EXPLORE_URL).mock(return_value=results(EXPLORE))

    for kind in ("charts", "dashboards"):
        missing_ids = list(missing) if kind == "charts" else []
        code = {kind: existing or [], "missingIds": missing_ids}
        respx.get(f"{CODE_URL}/{kind}").mock(return_value=results(code))

    space_list = [space_at(path) for path in spaces]
    respx.get(SPACES_URL).mock(return_value=results(space_list))


def mock_upsert(action: str = "update", kind: str = "charts", warnings: list[str] = ()):
    is_chart = kind == "charts"
    slug = "revenue-per-week" if is_chart else "sales"
    uuid = CHART_UUID if is_chart else DASHBOARD_UUID
    upserted = {
        kind: [{"action": action, "data": {"uuid": uuid}}],
        "warnings": list(warnings),
    }

    return respx.post(f"{CODE_URL}/{kind}/{slug}").mock(return_value=results(upserted))


def mock_validate(
    kind: str = "chart",
    uuid: str = CHART_UUID,
    answer: httpx.Response | None = None,
):
    valid = results({"errors": []})

    return respx.post(f"{PROJECT_URL}/validate/{kind}/{uuid}").mock(return_value=answer or valid)


async def register_dex(http: httpx.AsyncClient) -> dict:
    registration = {
        "client_name": "dex",
        "redirect_uris": [DEX_REDIRECT],
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code", "refresh_token"],
    }
    response = await http.post("/register", json=registration)

    return response.json()


async def dex_token(http: httpx.AsyncClient, client_id: str, secret: str) -> httpx.Response:
    """A token request with the client credentials only in the Basic header, as Dex sends it."""
    pair = f"{client_id}:{secret}"
    credentials = base64.b64encode(pair.encode()).decode()
    form = {
        "grant_type": "authorization_code",
        "code": "unknown",
        "redirect_uri": DEX_REDIRECT,
        "code_verifier": DEX_VERIFIER,
    }

    return await http.post(
        "/token",
        headers={"Authorization": f"Basic {credentials}"},
        data=form,
    )


@respx.mock
async def test_chart_fields_must_exist_in_the_explore(client):
    mock_lightdash()

    await check_chart(client, PROJECT, CHART)  # table calculations count as fields

    profit = {"filters": {"metrics": {"and": [{"target": {"fieldId": "orders_profit"}}]}}}
    with pytest.raises(ToolError, match="Unknown fields in orders: orders_profit"):
        await check_chart(client, PROJECT, chart_with(profit))


@respx.mock
async def test_charts_can_use_hidden_fields(client):
    mock_lightdash()

    await check_chart(client, PROJECT, chart_with({"metrics": ["orders_cost"]}))


@respx.mock
@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"tableCalculations": [{"sql": "1"}]}, "Each of metricQuery.tableCalculations needs name"),
        ({"sorts": [{"descending": True}]}, "Each of metricQuery.sorts needs fieldId"),
        (
            {"additionalMetrics": [{"name": "x"}]},
            "Each of metricQuery.additionalMetrics needs table and name",
        ),
        (
            {"dimensions": [{"fieldId": "orders_status"}]},
            "metricQuery.dimensions must be a list of field IDs",
        ),
        ({"customDimensions": [{"name": "g"}]}, "Each of metricQuery.customDimensions needs id"),
        ({"customDimensions": {"id": "g"}}, "Each of metricQuery.customDimensions needs id"),
    ],
)
async def test_malformed_charts_are_refused_with_a_reason(client, change, error):
    mock_lightdash()

    with pytest.raises(ToolError, match=error):
        await check_chart(client, PROJECT, chart_with(change))


@respx.mock
async def test_the_explore_must_be_a_name_and_defaults_to_the_table(client):
    mock_lightdash()
    explore_escape = chart_with({"exploreName": "../org"})
    query_as_a_list = CHART | {"metricQuery": ["orders_revenue"]}
    query = {key: value for key, value in CHART["metricQuery"].items() if key != "exploreName"}
    without_explore = CHART | {"metricQuery": query}
    table_escape = without_explore | {"tableName": "../org"}

    with pytest.raises(ToolError, match="Invalid explore '../org'"):
        await check_chart(client, PROJECT, explore_escape)

    with pytest.raises(ToolError, match="metricQuery must be an object"):
        await check_chart(client, PROJECT, query_as_a_list)

    assert not respx.calls

    await check_chart(client, PROJECT, without_explore)

    assert respx.calls.last.request.url.path == f"/api/v1/projects/{PROJECT}/explores/orders"

    with pytest.raises(ToolError, match="Invalid explore '../org'"):
        await check_chart(client, PROJECT, table_escape)


def test_charts_need_their_keys_and_a_url_safe_slug():
    without_config = {key: value for key, value in CHART.items() if key != "chartConfig"}
    with pytest.raises(ToolError, match="needs chartConfig"):
        _require(without_config, ("name", "slug", "chartConfig"), "chart")

    for slug in ("../../org", "revenue\n", "Revenue"):
        with pytest.raises(ToolError, match="Invalid slug"):
            _require(CHART | {"slug": slug}, ("slug",), "chart")


@respx.mock
async def test_preview_says_whether_it_creates_or_replaces(client):
    mock_lightdash(spaces=[])

    created = await preview(
        client,
        PROJECT,
        "charts",
        CHART,
        None,
    )

    assert created["wouldCreate"]["slug"] == "revenue-per-week"
    assert "visible only to you" in created["wouldCreate"]["newSpace"]

    respx.reset()
    mock_lightdash()
    existing = CHART | {
        "name": "Old revenue",
        "spaceSlug": "finance",
        "updatedAt": "2026-11-01",
        "version": 1,
    }

    replaced = await preview(
        client,
        PROJECT,
        "charts",
        CHART,
        existing,
    )

    without_next = {key: value for key, value in replaced.items() if key != "next"}
    assert replaced["next"].startswith(
        "Nothing is saved yet. Call save_chart again with dry_run=false"
    )
    assert without_next == {
        "wouldUpdate": {
            "slug": "revenue-per-week",
            "name": "Revenue per week",
            "space": "my-team",
            "replaces": {"name": "Old revenue", "space": "finance", "updatedAt": "2026-11-01"},
            "changes": ["name", "spaceSlug"],
        }
    }


@respx.mock
async def test_nested_spaces_are_found_by_their_path(client):
    mock_lightdash(spaces=["finance", "finance.my_team"])

    nested_chart = CHART | {"spaceSlug": "finance/my-team"}
    top_level_chart = CHART | {"spaceSlug": "my-team"}

    nested = await preview(
        client,
        PROJECT,
        "charts",
        nested_chart,
        None,
    )
    top_level = await preview(
        client,
        PROJECT,
        "charts",
        top_level_chart,
        None,
    )

    assert "newSpace" not in nested["wouldCreate"]
    assert "newSpace" in top_level["wouldCreate"]


@respx.mock
async def test_replacing_a_dashboard_keeps_what_it_leaves_out(client):
    tile = {
        "type": "markdown",
        "x": 0,
        "y": 0,
        "w": 36,
        "h": 4,
        "properties": {"content": "Hi"},
    }
    filters = {
        "dimensions": [{"target": {"fieldId": "orders_status"}, "operator": "equals"}],
        "metrics": [],
    }
    existing = {
        "name": "Sales",
        "slug": "sales",
        "spaceSlug": "my-team",
        "tiles": [tile, tile],
        "tabs": [{"uuid": "t1", "name": "Overview", "order": 0}],
        "filters": filters,
        "description": "Weekly sales",
        "updatedAt": "2026-11-01",
    }
    given = {
        "name": "Sales",
        "slug": "sales",
        "spaceSlug": "my-team",
        "tiles": [tile],
    }

    item = keep_existing("dashboards", {"version": 1, **given}, existing)
    without_tabs = keep_existing("dashboards", given | {"tabs": []}, existing)

    assert item["tabs"] == existing["tabs"]
    assert item["filters"] == filters
    assert item["description"] == "Weekly sales"
    assert without_tabs["tabs"] == []

    mock_lightdash()

    result = await preview(
        client,
        PROJECT,
        "dashboards",
        item,
        existing,
    )

    assert result["wouldUpdate"]["changes"] == ["tiles"]
    assert result["wouldUpdate"]["before"] == {"tiles": 2, "tabs": 1, "filters": 1}
    assert result["wouldUpdate"]["after"] == {"tiles": 1, "tabs": 1, "filters": 1}


@respx.mock
async def test_save_chart_only_saves_without_a_dry_run(call_tool):
    mock_lightdash()
    upsert = mock_upsert("create", warnings=[SPACE_CREATED])
    mock_validate()
    arguments = {"project_uuid": PROJECT, "chart": CHART}

    previewed = await call_tool("save_chart", **arguments)

    assert previewed["wouldCreate"]["slug"] == "revenue-per-week"
    assert not upsert.called

    saved = await call_tool("save_chart", **arguments, dry_run=False)

    body = json.loads(upsert.calls[0].request.content)
    assert saved == {
        "action": "create",
        "uuid": CHART_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/saved/{CHART_UUID}",
        "warnings": [SPACE_CREATED],
        "validationErrors": [],
    }
    assert body["version"] == 1
    assert body["metricQuery"] == CHART["metricQuery"]


@respx.mock
async def test_save_dashboard_only_saves_without_a_dry_run(call_tool):
    mock_lightdash()
    upsert = mock_upsert("create", "dashboards", warnings=[SPACE_CREATED])
    mock_validate("dashboard", DASHBOARD_UUID)
    arguments = {"project_uuid": PROJECT, "dashboard": DASHBOARD}

    previewed = await call_tool("save_dashboard", **arguments)

    assert previewed["wouldCreate"]["slug"] == "sales"
    assert "chartsNotSavedYet" not in previewed
    assert not upsert.called

    saved = await call_tool("save_dashboard", **arguments, dry_run=False)

    body = json.loads(upsert.calls[0].request.content)
    assert saved == {
        "action": "create",
        "uuid": DASHBOARD_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/dashboards/{DASHBOARD_UUID}",
        "warnings": [SPACE_CREATED],
        "validationErrors": [],
    }
    assert body["tabs"] == []


@respx.mock
async def test_save_dashboard_needs_its_charts_saved_first(call_tool):
    mock_lightdash(missing=["revenue-per-week"])
    upsert = mock_upsert("create", "dashboards")
    arguments = {"project_uuid": PROJECT, "dashboard": DASHBOARD | {"tiles": [CHART_TILE]}}
    save_the_chart = "Nothing is saved yet. Save revenue-per-week with save_chart and dry_run=false"

    previewed = await call_tool("save_dashboard", **arguments)

    urls_read = [call.request.url for call in respx.calls]
    chart_reads = [url for url in urls_read if url.path.endswith("/code/charts")]
    assert previewed["chartsNotSavedYet"] == ["revenue-per-week"]
    assert previewed["next"].startswith(save_the_chart)
    assert [url.params.get_list("ids") for url in chart_reads] == [["revenue-per-week"]]

    with pytest.raises(ToolError, match="No chart with slug revenue-per-week in this project yet"):
        await call_tool("save_dashboard", **arguments, dry_run=False)

    assert not upsert.called


@respx.mock
async def test_replacing_a_dashboard_with_the_tool_keeps_its_tabs(call_tool):
    tabs = [{"uuid": "t1", "name": "Overview", "order": 0}]
    existing = DASHBOARD | {
        "tiles": [TILE, TILE],
        "tabs": tabs,
        "updatedAt": "2026-11-01",
    }
    mock_lightdash(existing=[existing])
    upsert = mock_upsert(kind="dashboards")
    mock_validate("dashboard", DASHBOARD_UUID)
    arguments = {"project_uuid": PROJECT, "dashboard": DASHBOARD}

    previewed = await call_tool("save_dashboard", **arguments)
    saved = await call_tool("save_dashboard", **arguments, dry_run=False)

    body = json.loads(upsert.calls[0].request.content)
    assert previewed["wouldUpdate"]["after"]["tabs"] == 1
    assert saved["action"] == "update"
    assert body["tabs"] == tabs

    # Tabs given, even none, replace the current ones.
    without_tabs = DASHBOARD | {"tabs": []}

    await call_tool("save_dashboard", project_uuid=PROJECT, dashboard=without_tabs, dry_run=False)

    body = json.loads(upsert.calls[1].request.content)
    assert body["tabs"] == []


@respx.mock
async def test_code_is_read_by_slug(call_tool):
    mock_lightdash(existing=[CHART])

    chart = await call_tool("get_chart_code", project_uuid=PROJECT, slug="revenue-per-week")

    chart_read = respx.calls.last.request.url
    assert chart == CHART
    assert chart_read.params.get_list("ids") == ["revenue-per-week"]

    respx.reset()
    mock_lightdash(existing=[DASHBOARD])

    dashboard = await call_tool("get_dashboard_code", project_uuid=PROJECT, slug="sales")

    dashboard_read = respx.calls.last.request.url
    assert dashboard == DASHBOARD
    assert dashboard_read.path.endswith("/code/dashboards")
    assert dashboard_read.params.get_list("ids") == ["sales"]

    respx.reset()
    mock_lightdash()

    with pytest.raises(ToolError, match="No chart with slug revenue-per-week in this project"):
        await call_tool("get_chart_code", project_uuid=PROJECT, slug="revenue-per-week")

    with pytest.raises(ToolError, match="No dashboard with slug sales in this project"):
        await call_tool("get_dashboard_code", project_uuid=PROJECT, slug="sales")


@respx.mock
async def test_save_raises_a_401_from_validation(client):
    upsert = mock_upsert()
    unauthorized = httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    mock_validate(answer=unauthorized)

    with pytest.raises(LightdashError) as error:
        await save(client, PROJECT, "charts", CHART, LIGHTDASH)

    assert error.value.status == 401
    assert upsert.called


@respx.mock
async def test_save_keeps_new_spaces_private_forces_the_update_and_validates(client):
    upsert = mock_upsert()
    validation = {"errors": [{"fieldName": "orders_x", "error": "no longer exists"}]}
    mock_validate(answer=results(validation))

    result = await save(
        client,
        PROJECT,
        "charts",
        CHART,
        LIGHTDASH,
    )

    body = json.loads(upsert.calls[0].request.content)
    assert body["publicSpaceCreate"] is False
    assert body["skipSpaceCreate"] is False
    # Lightdash skips a chart update whose name, description and slug are unchanged unless it
    # is forced.
    assert body["force"] is True
    assert result == {
        "action": "update",
        "uuid": CHART_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/saved/{CHART_UUID}",
        "validationErrors": [{"field": "orders_x", "error": "no longer exists"}],
    }


@respx.mock
@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (
            httpx.Response(500, json={"error": {"message": "Validation crashed"}}),
            "couldn't validate it: Validation crashed",
        ),
        (httpx.ReadTimeout("timed out"), "didn't answer its validation"),
    ],
)
async def test_save_reports_a_failed_validation_without_hiding_the_save(client, answer, reason):
    mock_upsert("create")
    respx.post(VALIDATE_URL).mock(side_effect=[answer])

    result = await save(
        client,
        PROJECT,
        "charts",
        CHART,
        LIGHTDASH,
    )

    assert result["action"] == "create"
    assert result["uuid"] == CHART_UUID
    assert reason in result["validationFailed"]
    assert "validationErrors" not in result


@respx.mock
async def test_dashboard_tiles_are_checked_and_unsaved_charts_listed(client):
    without_slug = CHART_TILE | {"properties": {}}
    markdown = {"type": "markdown", "x": 0, "y": 0, "properties": {}}
    no_slug = "Tile 0 is a saved_chart tile without properties.chartSlug"
    mock_lightdash(missing=["revenue-per-week"])

    missing = await check_dashboard(client, PROJECT, {"tiles": [CHART_TILE]})

    assert missing == ["revenue-per-week"]

    with pytest.raises(ToolError, match=no_slug):
        await check_dashboard(client, PROJECT, {"tiles": [without_slug]})

    with pytest.raises(ToolError, match="Tile 0 needs w, h"):
        await check_dashboard(client, PROJECT, {"tiles": [markdown]})


async def test_slugs_cannot_reach_other_endpoints(settings):
    server = create_server(settings)
    escapes = [
        ("get_chart_code", {"project_uuid": PROJECT, "slug": "../../org"}),
        ("run_chart", {"project_uuid": PROJECT, "chart_uuid": "../../org/users"}),
    ]

    for name, arguments in escapes:
        with pytest.raises(ToolError, match="validation error"):
            await server.call_tool(name, arguments)


async def test_token_endpoint_accepts_a_client_id_sent_only_in_the_basic_header(settings, redis):
    transport = httpx.ASGITransport(asgi_app(settings, redis))

    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as http:
        registered = await register_dex(http)
        client_id = registered["client_id"]
        accepted = await dex_token(http, client_id, registered["client_secret"])
        refused = await dex_token(http, client_id, "wrong")

    # The client is authenticated: only the made-up code is refused.
    assert accepted.status_code == 400
    assert accepted.json()["error"] == "invalid_grant"
    assert refused.status_code == 401
    assert refused.json()["error"] == "invalid_client"


@respx.mock
async def test_charts_can_be_given_by_slug_within_the_project(client):
    in_project = {"uuid": CHART_UUID, "projectUuid": PROJECT}
    in_another_project = {"uuid": CHART_UUID, "projectUuid": "another"}
    respx.get(f"{SAVED_URL}/revenue-per-week").mock(return_value=results(in_project))
    respx.get(f"{SAVED_URL}/other-project-chart").mock(return_value=results(in_another_project))

    by_uuid = await resolve_chart(client, PROJECT, CHART_UUID)
    by_slug = await resolve_chart(client, PROJECT, "revenue-per-week")

    assert by_uuid == CHART_UUID
    assert by_slug == CHART_UUID

    with pytest.raises(ToolError, match="No chart with slug other-project-chart in this project"):
        await resolve_chart(client, PROJECT, "other-project-chart")


@respx.mock
@pytest.mark.parametrize(
    ("tiles", "error"),
    [
        ({"type": "markdown"}, "tiles must be a list"),
        (["markdown"], "Tile 0 needs type, x, y, w, h, properties"),
        (
            [{"type": "markdown", "x": 0, "y": 0, "w": 36, "h": 4, "properties": "Hi"}],
            "Tile 0 properties must be an object",
        ),
    ],
)
async def test_malformed_dashboard_tiles_are_refused_with_a_reason(client, tiles, error):
    with pytest.raises(ToolError, match=error):
        await check_dashboard(client, PROJECT, {"tiles": tiles})


@respx.mock
async def test_dashboards_without_chart_tiles_do_not_look_up_charts(client):
    no_charts = results({"charts": [], "missingIds": []})
    charts = respx.get(f"{CODE_URL}/charts").mock(return_value=no_charts)
    markdown = {
        "type": "markdown",
        "x": 0,
        "y": 0,
        "w": 36,
        "h": 4,
        "properties": {},
    }

    missing = await check_dashboard(client, PROJECT, {"tiles": [markdown]})

    assert missing == []
    assert not charts.called


@respx.mock
async def test_custom_dimensions_and_additional_metrics_count_as_fields(client):
    mock_lightdash()
    custom_fields = {
        "dimensions": ["orders_order_date_week", "status_group"],
        "metrics": ["orders_revenue", "orders_margin"],
        "customDimensions": [{"id": "status_group", "name": "Status group"}],
        "additionalMetrics": [{"table": "orders", "name": "margin"}],
        "sorts": [{"fieldId": "orders_margin", "descending": True}],
    }

    await check_chart(client, PROJECT, chart_with(custom_fields))


@respx.mock
@pytest.mark.parametrize(
    ("change", "unknown"),
    [
        ({"sorts": [{"fieldId": "orders_rank", "descending": False}]}, "orders_rank"),
        (
            {
                "filters": {
                    "dimensions": {
                        "id": "outer",
                        "or": [{"id": "inner", "and": [{"target": {"fieldId": "orders_deep"}}]}],
                    }
                }
            },
            "orders_deep",
        ),
    ],
)
async def test_sorts_and_nested_filters_must_use_known_fields(client, change, unknown):
    mock_lightdash()

    with pytest.raises(ToolError, match=f"Unknown fields in orders: {unknown}\\."):
        await check_chart(client, PROJECT, chart_with(change))


def test_replacing_a_chart_keeps_its_table_and_pivot_configuration():
    table_config = {"columnOrder": ["orders_order_date_week", "orders_revenue"]}
    pivot_config = {"columns": ["orders_status"]}
    existing = CHART | {
        "description": "Weekly revenue",
        "tableConfig": table_config,
        "pivotConfig": pivot_config,
        "chartConfig": {"type": "table", "config": {}},
    }
    given_table_config = {"columnOrder": ["orders_revenue"]}
    given = CHART | {"tableConfig": given_table_config}

    kept = keep_existing("charts", CHART, existing)
    replaced = keep_existing("charts", given, existing)
    new = keep_existing("charts", CHART, None)

    assert kept["tableConfig"] == table_config
    assert kept["pivotConfig"] == pivot_config
    assert kept["description"] == "Weekly revenue"
    assert kept["chartConfig"] == CHART["chartConfig"]
    assert replaced["tableConfig"] == given_table_config
    assert new == CHART
