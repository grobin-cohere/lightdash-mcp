import base64
import json

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashClient
from lightdash_mcp.server import asgi_app, create_server
from lightdash_mcp.tools.code import _require, check_chart, check_dashboard, keep_existing, preview, save
from lightdash_mcp.tools.common import resolve_chart

LIGHTDASH = "http://lightdash.test"
PROJECT = "3675b69e-8324-4110-bdca-059031aa8da3"
CHART_UUID = "d83eaf7e-e041-4a89-af83-e64450cfd524"

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
            "dimensions": {"id": "g", "and": [{"id": "r", "target": {"fieldId": "orders_status"}, "operator": "equals"}]}
        },
        "sorts": [{"fieldId": "orders_order_date_week", "descending": False}],
        "limit": 500,
        "tableCalculations": [{"name": "revenue_share", "sql": "1"}],
    },
    "chartConfig": {"type": "cartesian", "config": {}},
}


def mock_lightdash(existing: list[dict] | None = None, spaces: list[str] = ("my_team",), missing: list[str] = ()):
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/explores/orders").mock(
        return_value=httpx.Response(200, json={"results": EXPLORE})
    )
    for kind in ("charts", "dashboards"):
        respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/{kind}").mock(
            return_value=httpx.Response(200, json={"results": {kind: existing or [], "missingIds": list(missing)}})
        )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/spaces").mock(
        return_value=httpx.Response(200, json={"results": [{"slug": path.split(".")[-1], "path": path} for path in spaces]})
    )


async def client(http: httpx.AsyncClient) -> LightdashClient:
    return LightdashClient(http, "token")


@respx.mock
async def test_chart_fields_must_exist_in_the_explore():
    mock_lightdash()
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        await check_chart(ld, PROJECT, CHART)  # table calculations count as fields
        query = CHART["metricQuery"] | {"filters": {"metrics": {"and": [{"target": {"fieldId": "orders_profit"}}]}}}
        with pytest.raises(ToolError, match="Unknown fields in orders: orders_profit"):
            await check_chart(ld, PROJECT, CHART | {"metricQuery": query})


@respx.mock
async def test_charts_can_use_hidden_fields():
    mock_lightdash()
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        await check_chart(
            await client(http), PROJECT, CHART | {"metricQuery": CHART["metricQuery"] | {"metrics": ["orders_cost"]}}
        )


@respx.mock
@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"tableCalculations": [{"sql": "1"}]}, "Each of metricQuery.tableCalculations needs name"),
        ({"sorts": [{"descending": True}]}, "Each of metricQuery.sorts needs fieldId"),
        ({"additionalMetrics": [{"name": "x"}]}, "Each of metricQuery.additionalMetrics needs table and name"),
        ({"dimensions": [{"fieldId": "orders_status"}]}, "metricQuery.dimensions must be a list of field IDs"),
    ],
)
async def test_malformed_charts_are_refused_with_a_reason(change, error):
    mock_lightdash()
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        with pytest.raises(ToolError, match=error):
            await check_chart(await client(http), PROJECT, CHART | {"metricQuery": CHART["metricQuery"] | change})


def test_charts_need_their_keys_and_a_url_safe_slug():
    with pytest.raises(ToolError, match="needs chartConfig"):
        _require({k: v for k, v in CHART.items() if k != "chartConfig"}, ("name", "slug", "chartConfig"), "chart")
    for slug in ("../../org", "revenue\n", "Revenue"):
        with pytest.raises(ToolError, match="Invalid slug"):
            _require(CHART | {"slug": slug}, ("slug",), "chart")


@respx.mock
async def test_preview_says_whether_it_creates_or_replaces():
    mock_lightdash(spaces=[])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        created = await preview(ld, PROJECT, "charts", CHART, None)
    assert created["wouldCreate"]["slug"] == "revenue-per-week"
    assert "visible only to you" in created["wouldCreate"]["newSpace"]

    respx.reset()
    mock_lightdash()
    existing = CHART | {"name": "Old revenue", "spaceSlug": "finance", "updatedAt": "2026-11-01", "version": 1}
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        replaced = await preview(await client(http), PROJECT, "charts", CHART, existing)
    assert replaced["next"].startswith("Nothing is saved yet. Call save_chart again with dry_run=false")
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
async def test_nested_spaces_are_found_by_their_path():
    mock_lightdash(spaces=["finance", "finance.my_team"])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        nested = await preview(ld, PROJECT, "charts", CHART | {"spaceSlug": "finance/my-team"}, None)
        top_level = await preview(ld, PROJECT, "charts", CHART | {"spaceSlug": "my-team"}, None)
    assert "newSpace" not in nested["wouldCreate"]
    assert "newSpace" in top_level["wouldCreate"]


@respx.mock
async def test_replacing_a_dashboard_keeps_what_it_leaves_out():
    tile = {"type": "markdown", "x": 0, "y": 0, "w": 36, "h": 4, "properties": {"content": "Hi"}}
    filters = {"dimensions": [{"target": {"fieldId": "orders_status"}, "operator": "equals"}], "metrics": []}
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
    assert (item["tabs"], item["filters"], item["description"]) == (existing["tabs"], filters, "Weekly sales")
    assert keep_existing("dashboards", given | {"tabs": []}, existing)["tabs"] == []

    mock_lightdash()
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        result = await preview(await client(http), PROJECT, "dashboards", item, existing)
    assert result["wouldUpdate"]["changes"] == ["tiles"]
    assert result["wouldUpdate"]["before"] == {"tiles": 2, "tabs": 1, "filters": 1}
    assert result["wouldUpdate"]["after"] == {"tiles": 1, "tabs": 1, "filters": 1}


def mock_upsert(action: str = "update"):
    return respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/charts/revenue-per-week").mock(
        return_value=httpx.Response(200, json={"results": {"charts": [{"action": action, "data": {"uuid": CHART_UUID}}]}})
    )


@respx.mock
async def test_save_keeps_new_spaces_private_forces_the_update_and_validates():
    upsert = mock_upsert()
    respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/chart/{CHART_UUID}").mock(
        return_value=httpx.Response(200, json={"results": {"errors": [{"fieldName": "orders_x", "error": "no longer exists"}]}})
    )
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        result = await save(await client(http), PROJECT, "charts", CHART, LIGHTDASH)
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
        (httpx.Response(500, json={"error": {"message": "Validation crashed"}}), "couldn't validate it: Validation crashed"),
        (httpx.ReadTimeout("timed out"), "didn't answer its validation"),
    ],
)
async def test_save_reports_a_failed_validation_without_hiding_the_save(answer, reason):
    mock_upsert("create")
    respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/chart/{CHART_UUID}").mock(side_effect=[answer])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        result = await save(await client(http), PROJECT, "charts", CHART, LIGHTDASH)
    assert (result["action"], result["uuid"]) == ("create", CHART_UUID)
    assert reason in result["validationFailed"] and "validationErrors" not in result


@respx.mock
async def test_dashboard_tiles_are_checked_and_unsaved_charts_listed():
    tile = {"type": "saved_chart", "x": 0, "y": 0, "w": 36, "h": 8, "properties": {"chartSlug": "revenue-per-week"}}
    mock_lightdash(missing=["revenue-per-week"])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        assert await check_dashboard(ld, PROJECT, {"tiles": [tile]}) == ["revenue-per-week"]
        with pytest.raises(ToolError, match="Tile 0 is a saved_chart tile without properties.chartSlug"):
            await check_dashboard(ld, PROJECT, {"tiles": [tile | {"properties": {}}]})
        with pytest.raises(ToolError, match="Tile 0 needs w, h"):
            await check_dashboard(ld, PROJECT, {"tiles": [{"type": "markdown", "x": 0, "y": 0, "properties": {}}]})


async def test_slugs_cannot_reach_other_endpoints():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    server = create_server(settings)
    for name, arguments in [
        ("get_chart_code", {"project_uuid": PROJECT, "slug": "../../org"}),
        ("run_chart", {"project_uuid": PROJECT, "chart_uuid": "../../org/users"}),
    ]:
        with pytest.raises(ToolError, match="validation error"):
            await server.call_tool(name, arguments)


async def test_token_endpoint_accepts_a_client_id_sent_only_in_the_basic_header():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    app = asgi_app(settings, FakeAsyncRedis())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://localhost:8000") as http:
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
async def test_charts_can_be_given_by_slug_within_the_project():
    respx.get(f"{LIGHTDASH}/api/v1/saved/revenue-per-week").mock(
        return_value=httpx.Response(200, json={"results": {"uuid": CHART_UUID, "projectUuid": PROJECT}})
    )
    respx.get(f"{LIGHTDASH}/api/v1/saved/other-project-chart").mock(
        return_value=httpx.Response(200, json={"results": {"uuid": CHART_UUID, "projectUuid": "another"}})
    )
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        assert await resolve_chart(ld, PROJECT, CHART_UUID) == CHART_UUID
        assert await resolve_chart(ld, PROJECT, "revenue-per-week") == CHART_UUID
        with pytest.raises(ToolError, match="No chart with slug other-project-chart in this project"):
            await resolve_chart(ld, PROJECT, "other-project-chart")
