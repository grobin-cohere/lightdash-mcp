import base64
import json
import time

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.auth.provider import Access, Grant
from lightdash_mcp.auth.store import Store
from lightdash_mcp.config import Settings
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


def mock_lightdash(
    existing: list[dict] | None = None, spaces: list[str] = ("my_team",), missing: list[str] = ()
):
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/explores/orders").mock(
        return_value=httpx.Response(200, json={"results": EXPLORE})
    )
    for kind in ("charts", "dashboards"):
        missing_ids = list(missing) if kind == "charts" else []
        respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/{kind}").mock(
            return_value=httpx.Response(
                200, json={"results": {kind: existing or [], "missingIds": missing_ids}}
            )
        )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/spaces").mock(
        return_value=httpx.Response(
            200, json={"results": [{"slug": path.split(".")[-1], "path": path} for path in spaces]}
        )
    )


@respx.mock
async def test_chart_fields_must_exist_in_the_explore(client):
    mock_lightdash()

    await check_chart(client, PROJECT, CHART)  # table calculations count as fields

    profit = {"filters": {"metrics": {"and": [{"target": {"fieldId": "orders_profit"}}]}}}
    query = CHART["metricQuery"] | profit
    with pytest.raises(ToolError, match="Unknown fields in orders: orders_profit"):
        await check_chart(client, PROJECT, CHART | {"metricQuery": query})


@pytest.fixture
async def call():
    """Call a tool of the server as a signed-in user, and return its result."""
    redis = FakeAsyncRedis()
    settings = Settings(
        _env_file=None,
        lightdash_url=LIGHTDASH,
        lightdash_client_id="id",
        lightdash_client_secret="secret",
        fernet_key=Fernet.generate_key().decode(),
    )
    server = create_server(settings, redis)
    grant = Grant(
        client_id="client",
        subject="user",
        access_token="ld-access",
        refresh_token="ld-refresh",
        expires_at=time.time() + 3600,
    )
    await Store(redis, settings.fernet_key).put("grant", "grant", grant)
    access = Access(
        token="our-access", client_id="client", scopes=[], subject="user", grant_id="grant"
    )
    reset = auth_context_var.set(AuthenticatedUser(access))

    async def tool(name: str, arguments: dict) -> dict:
        content = (await server.call_tool(name, arguments)).structured_content
        return content["result"] if set(content) == {"result"} else content

    try:
        yield tool
    finally:
        auth_context_var.reset(reset)


@respx.mock
async def test_charts_can_use_hidden_fields(client):
    mock_lightdash()
    query = CHART["metricQuery"] | {"metrics": ["orders_cost"]}

    await check_chart(client, PROJECT, CHART | {"metricQuery": query})


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
    query = CHART["metricQuery"] | change

    with pytest.raises(ToolError, match=error):
        await check_chart(client, PROJECT, CHART | {"metricQuery": query})


@respx.mock
async def test_the_explore_must_be_a_name_and_defaults_to_the_table(client):
    mock_lightdash()
    with pytest.raises(ToolError, match="Invalid explore '../org'"):
        await check_chart(
            client,
            PROJECT,
            CHART | {"metricQuery": CHART["metricQuery"] | {"exploreName": "../org"}},
        )
    with pytest.raises(ToolError, match="metricQuery must be an object"):
        await check_chart(client, PROJECT, CHART | {"metricQuery": ["orders_revenue"]})
    assert not respx.calls

    query = {k: v for k, v in CHART["metricQuery"].items() if k != "exploreName"}
    await check_chart(client, PROJECT, CHART | {"metricQuery": query})
    assert respx.calls.last.request.url.path == f"/api/v1/projects/{PROJECT}/explores/orders"
    with pytest.raises(ToolError, match="Invalid explore '../org'"):
        await check_chart(client, PROJECT, CHART | {"tableName": "../org", "metricQuery": query})


def test_charts_need_their_keys_and_a_url_safe_slug():
    with pytest.raises(ToolError, match="needs chartConfig"):
        _require(
            {k: v for k, v in CHART.items() if k != "chartConfig"},
            ("name", "slug", "chartConfig"),
            "chart",
        )
    for slug in ("../../org", "revenue\n", "Revenue"):
        with pytest.raises(ToolError, match="Invalid slug"):
            _require(CHART | {"slug": slug}, ("slug",), "chart")


@respx.mock
async def test_preview_says_whether_it_creates_or_replaces(client):
    mock_lightdash(spaces=[])

    created = await preview(client, PROJECT, "charts", CHART, None)

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

    replaced = await preview(client, PROJECT, "charts", CHART, existing)

    assert replaced["next"].startswith(
        "Nothing is saved yet. Call save_chart again with dry_run=false"
    )
    assert {k: v for k, v in replaced.items() if k != "next"} == {
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

    nested = await preview(client, PROJECT, "charts", nested_chart, None)
    top_level = await preview(client, PROJECT, "charts", top_level_chart, None)

    assert "newSpace" not in nested["wouldCreate"]
    assert "newSpace" in top_level["wouldCreate"]


@respx.mock
async def test_replacing_a_dashboard_keeps_what_it_leaves_out(client):
    tile = {"type": "markdown", "x": 0, "y": 0, "w": 36, "h": 4, "properties": {"content": "Hi"}}
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
    given = {"name": "Sales", "slug": "sales", "spaceSlug": "my-team", "tiles": [tile]}
    item = keep_existing("dashboards", {"version": 1, **given}, existing)
    assert (item["tabs"], item["filters"], item["description"]) == (
        existing["tabs"],
        filters,
        "Weekly sales",
    )
    assert keep_existing("dashboards", given | {"tabs": []}, existing)["tabs"] == []

    mock_lightdash()

    result = await preview(client, PROJECT, "dashboards", item, existing)

    assert result["wouldUpdate"]["changes"] == ["tiles"]
    assert result["wouldUpdate"]["before"] == {"tiles": 2, "tabs": 1, "filters": 1}
    assert result["wouldUpdate"]["after"] == {"tiles": 1, "tabs": 1, "filters": 1}


def mock_upsert(action: str = "update", kind: str = "charts", warnings: list[str] = ()):
    slug, uuid = ("revenue-per-week", CHART_UUID) if kind == "charts" else ("sales", DASHBOARD_UUID)
    saved = {kind: [{"action": action, "data": {"uuid": uuid}}], "warnings": list(warnings)}
    return respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/{kind}/{slug}").mock(
        return_value=httpx.Response(200, json={"results": saved})
    )


def mock_validate(
    kind: str = "chart", uuid: str = CHART_UUID, answer: httpx.Response | None = None
):
    return respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/{kind}/{uuid}").mock(
        return_value=answer or httpx.Response(200, json={"results": {"errors": []}})
    )


@respx.mock
async def test_save_chart_only_saves_without_a_dry_run(call):
    mock_lightdash()
    upsert = mock_upsert("create", warnings=["Space my-team was created"])
    mock_validate()
    args = {"project_uuid": PROJECT, "chart": CHART}

    previewed = await call("save_chart", args)
    assert previewed["wouldCreate"]["slug"] == "revenue-per-week"
    assert not upsert.called

    saved = await call("save_chart", args | {"dry_run": False})
    assert saved == {
        "action": "create",
        "uuid": CHART_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/saved/{CHART_UUID}",
        "warnings": ["Space my-team was created"],
        "validationErrors": [],
    }
    body = json.loads(upsert.calls[0].request.content)
    assert body["version"] == 1 and body["metricQuery"] == CHART["metricQuery"]


TILE = {
    "type": "markdown",
    "x": 0,
    "y": 0,
    "w": 36,
    "h": 4,
    "properties": {"title": "Hi", "content": "Hello"},
}
DASHBOARD = {"name": "Sales", "slug": "sales", "spaceSlug": "my-team", "tiles": [TILE]}


@respx.mock
async def test_save_dashboard_only_saves_without_a_dry_run(call):
    mock_lightdash()
    upsert = mock_upsert("create", "dashboards", warnings=["Space my-team was created"])
    mock_validate("dashboard", DASHBOARD_UUID)
    args = {"project_uuid": PROJECT, "dashboard": DASHBOARD}

    previewed = await call("save_dashboard", args)
    assert previewed["wouldCreate"]["slug"] == "sales" and "chartsNotSavedYet" not in previewed
    assert not upsert.called

    saved = await call("save_dashboard", args | {"dry_run": False})
    assert saved == {
        "action": "create",
        "uuid": DASHBOARD_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/dashboards/{DASHBOARD_UUID}",
        "warnings": ["Space my-team was created"],
        "validationErrors": [],
    }
    assert json.loads(upsert.calls[0].request.content)["tabs"] == []


@respx.mock
async def test_save_dashboard_needs_its_charts_saved_first(call):
    tile = {
        "type": "saved_chart",
        "x": 0,
        "y": 0,
        "w": 36,
        "h": 8,
        "properties": {"chartSlug": "revenue-per-week"},
    }
    mock_lightdash(missing=["revenue-per-week"])
    upsert = mock_upsert("create", "dashboards")
    args = {"project_uuid": PROJECT, "dashboard": DASHBOARD | {"tiles": [tile]}}

    previewed = await call("save_dashboard", args)
    assert previewed["chartsNotSavedYet"] == ["revenue-per-week"]
    assert previewed["next"].startswith(
        "Nothing is saved yet. Save revenue-per-week with save_chart and dry_run=false"
    )
    charts_read = [
        c.request.url for c in respx.calls if c.request.url.path.endswith("/code/charts")
    ]
    assert [url.params.get_list("ids") for url in charts_read] == [["revenue-per-week"]]

    with pytest.raises(ToolError, match="No chart with slug revenue-per-week in this project yet"):
        await call("save_dashboard", args | {"dry_run": False})
    assert not upsert.called


@respx.mock
async def test_replacing_a_dashboard_with_the_tool_keeps_its_tabs(call):
    tabs = [{"uuid": "t1", "name": "Overview", "order": 0}]
    mock_lightdash(
        existing=[DASHBOARD | {"tiles": [TILE, TILE], "tabs": tabs, "updatedAt": "2026-11-01"}]
    )
    upsert = mock_upsert(kind="dashboards")
    mock_validate("dashboard", DASHBOARD_UUID)
    args = {"project_uuid": PROJECT, "dashboard": DASHBOARD}

    previewed = await call("save_dashboard", args)
    assert previewed["wouldUpdate"]["after"]["tabs"] == 1
    assert (await call("save_dashboard", args | {"dry_run": False}))["action"] == "update"
    assert json.loads(upsert.calls[0].request.content)["tabs"] == tabs

    # Tabs given, even none, replace the current ones.
    await call("save_dashboard", {**args, "dashboard": DASHBOARD | {"tabs": []}, "dry_run": False})
    assert json.loads(upsert.calls[1].request.content)["tabs"] == []


@respx.mock
async def test_code_is_read_by_slug(call):
    mock_lightdash(existing=[CHART])
    assert (
        await call("get_chart_code", {"project_uuid": PROJECT, "slug": "revenue-per-week"}) == CHART
    )
    assert respx.calls.last.request.url.params.get_list("ids") == ["revenue-per-week"]
    respx.reset()
    mock_lightdash(existing=[DASHBOARD])
    assert await call("get_dashboard_code", {"project_uuid": PROJECT, "slug": "sales"}) == DASHBOARD
    assert respx.calls.last.request.url.path.endswith("/code/dashboards")
    assert respx.calls.last.request.url.params.get_list("ids") == ["sales"]
    respx.reset()
    mock_lightdash()
    with pytest.raises(ToolError, match="No chart with slug revenue-per-week in this project"):
        await call("get_chart_code", {"project_uuid": PROJECT, "slug": "revenue-per-week"})
    with pytest.raises(ToolError, match="No dashboard with slug sales in this project"):
        await call("get_dashboard_code", {"project_uuid": PROJECT, "slug": "sales"})


@respx.mock
async def test_save_raises_a_401_from_validation(client):
    upsert = mock_upsert()
    mock_validate(answer=httpx.Response(401, json={"error": {"message": "Unauthorized"}}))
    with pytest.raises(LightdashError) as error:
        await save(client, PROJECT, "charts", CHART, LIGHTDASH)
    assert error.value.status == 401 and upsert.called


@respx.mock
async def test_save_keeps_new_spaces_private_forces_the_update_and_validates(client):
    upsert = mock_upsert()
    respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/chart/{CHART_UUID}").mock(
        return_value=httpx.Response(
            200,
            json={"results": {"errors": [{"fieldName": "orders_x", "error": "no longer exists"}]}},
        )
    )

    result = await save(client, PROJECT, "charts", CHART, LIGHTDASH)

    body = json.loads(upsert.calls[0].request.content)
    assert (body["publicSpaceCreate"], body["skipSpaceCreate"]) == (False, False)
    # Lightdash skips a chart update whose name, description and slug are unchanged unless it is forced.
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
    respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/chart/{CHART_UUID}").mock(
        side_effect=[answer]
    )

    result = await save(client, PROJECT, "charts", CHART, LIGHTDASH)

    assert (result["action"], result["uuid"]) == ("create", CHART_UUID)
    assert reason in result["validationFailed"] and "validationErrors" not in result


@respx.mock
async def test_dashboard_tiles_are_checked_and_unsaved_charts_listed(client):
    tile = {
        "type": "saved_chart",
        "x": 0,
        "y": 0,
        "w": 36,
        "h": 8,
        "properties": {"chartSlug": "revenue-per-week"},
    }
    markdown = {"type": "markdown", "x": 0, "y": 0, "properties": {}}
    no_slug = "Tile 0 is a saved_chart tile without properties.chartSlug"
    mock_lightdash(missing=["revenue-per-week"])

    assert await check_dashboard(client, PROJECT, {"tiles": [tile]}) == ["revenue-per-week"]
    with pytest.raises(ToolError, match=no_slug):
        await check_dashboard(client, PROJECT, {"tiles": [tile | {"properties": {}}]})
    with pytest.raises(ToolError, match="Tile 0 needs w, h"):
        await check_dashboard(client, PROJECT, {"tiles": [markdown]})


async def test_slugs_cannot_reach_other_endpoints(settings):
    server = create_server(settings)
    for name, arguments in [
        ("get_chart_code", {"project_uuid": PROJECT, "slug": "../../org"}),
        ("run_chart", {"project_uuid": PROJECT, "chart_uuid": "../../org/users"}),
    ]:
        with pytest.raises(ToolError, match="validation error"):
            await server.call_tool(name, arguments)


async def test_token_endpoint_accepts_a_client_id_sent_only_in_the_basic_header(settings, redis):
    app = asgi_app(settings, redis)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://localhost:8000"
    ) as http:
        registered = (
            await http.post(
                "/register",
                json={
                    "client_name": "dex",
                    "redirect_uris": ["http://localhost:5556/dex/callback"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "grant_types": ["authorization_code", "refresh_token"],
                },
            )
        ).json()

        async def token(secret: str) -> httpx.Response:
            credentials = base64.b64encode(f"{registered['client_id']}:{secret}".encode()).decode()
            return await http.post(
                "/token",
                headers={"Authorization": f"Basic {credentials}"},
                data={
                    "grant_type": "authorization_code",
                    "code": "unknown",
                    "redirect_uri": "http://localhost:5556/dex/callback",
                    "code_verifier": "verifier" * 6,
                },
            )

        accepted = await token(registered["client_secret"])
        refused = await token("wrong")
    # The client is authenticated: only the made-up code is refused.
    assert (accepted.status_code, accepted.json()["error"]) == (400, "invalid_grant")
    assert (refused.status_code, refused.json()["error"]) == (401, "invalid_client")


@respx.mock
async def test_charts_can_be_given_by_slug_within_the_project(client):
    respx.get(f"{LIGHTDASH}/api/v1/saved/revenue-per-week").mock(
        return_value=httpx.Response(
            200, json={"results": {"uuid": CHART_UUID, "projectUuid": PROJECT}}
        )
    )
    respx.get(f"{LIGHTDASH}/api/v1/saved/other-project-chart").mock(
        return_value=httpx.Response(
            200, json={"results": {"uuid": CHART_UUID, "projectUuid": "another"}}
        )
    )

    assert await resolve_chart(client, PROJECT, CHART_UUID) == CHART_UUID
    assert await resolve_chart(client, PROJECT, "revenue-per-week") == CHART_UUID
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
    charts = respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/charts").mock(
        return_value=httpx.Response(200, json={"results": {"charts": [], "missingIds": []}}),
    )
    markdown = {"type": "markdown", "x": 0, "y": 0, "w": 36, "h": 4, "properties": {}}

    missing = await check_dashboard(client, PROJECT, {"tiles": [markdown]})

    assert missing == []
    assert not charts.called


@respx.mock
async def test_custom_dimensions_and_additional_metrics_count_as_fields(client):
    mock_lightdash()
    query = CHART["metricQuery"] | {
        "dimensions": ["orders_order_date_week", "status_group"],
        "metrics": ["orders_revenue", "orders_margin"],
        "customDimensions": [{"id": "status_group", "name": "Status group"}],
        "additionalMetrics": [{"table": "orders", "name": "margin"}],
        "sorts": [{"fieldId": "orders_margin", "descending": True}],
    }

    await check_chart(client, PROJECT, CHART | {"metricQuery": query})


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
    query = CHART["metricQuery"] | change

    with pytest.raises(ToolError, match=f"Unknown fields in orders: {unknown}\\."):
        await check_chart(client, PROJECT, CHART | {"metricQuery": query})


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

    kept = keep_existing("charts", CHART, existing)
    replaced = keep_existing("charts", CHART | {"tableConfig": given_table_config}, existing)

    assert (kept["tableConfig"], kept["pivotConfig"]) == (table_config, pivot_config)
    assert kept["description"] == "Weekly revenue"
    assert kept["chartConfig"] == CHART["chartConfig"]
    assert replaced["tableConfig"] == given_table_config
    assert keep_existing("charts", CHART, None) == CHART
