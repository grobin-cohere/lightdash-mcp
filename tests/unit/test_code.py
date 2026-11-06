import base64
import json

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.mcpserver.exceptions import ToolError

from kizaru_mcp.config import Settings
from kizaru_mcp.lightdash import LightdashClient
from kizaru_mcp.server import asgi_app, create_server
from kizaru_mcp.tools.code import _require, check_chart, check_dashboard, preview, save

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
            "metrics": {"revenue": {"table": "orders", "name": "revenue"}},
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


def mock_lightdash(existing: list[dict] | None = None, spaces: list[str] = ("my-team",), missing: list[str] = ()):
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/explores/orders").mock(
        return_value=httpx.Response(200, json={"results": EXPLORE})
    )
    for kind in ("charts", "dashboards"):
        respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/{kind}").mock(
            return_value=httpx.Response(200, json={"results": {kind: existing or [], "missingIds": list(missing)}})
        )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/spaces").mock(
        return_value=httpx.Response(200, json={"results": [{"slug": slug} for slug in spaces]})
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


def test_charts_need_their_keys_and_a_url_safe_slug():
    with pytest.raises(ToolError, match="needs chartConfig"):
        _require({k: v for k, v in CHART.items() if k != "chartConfig"}, ("name", "slug", "chartConfig"), "chart")
    with pytest.raises(ToolError, match="Invalid slug"):
        _require(CHART | {"slug": "../../org"}, ("slug",), "chart")


@respx.mock
async def test_preview_says_whether_it_creates_or_replaces():
    mock_lightdash(spaces=[])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        created = await preview(ld, PROJECT, "charts", CHART)
    assert created["wouldCreate"]["slug"] == "revenue-per-week"
    assert "visible only to you" in created["wouldCreate"]["newSpace"]

    respx.reset()
    mock_lightdash(existing=[{"name": "Old revenue", "spaceSlug": "finance", "updatedAt": "2026-11-01"}])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        replaced = await preview(await client(http), PROJECT, "charts", CHART)
    assert replaced == {
        "wouldUpdate": {
            "slug": "revenue-per-week",
            "name": "Revenue per week",
            "space": "my-team",
            "replaces": {"name": "Old revenue", "space": "finance", "updatedAt": "2026-11-01"},
        }
    }


@respx.mock
async def test_save_keeps_new_spaces_private_and_validates():
    upsert = respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/code/charts/revenue-per-week").mock(
        return_value=httpx.Response(200, json={"results": {"charts": [{"action": "create", "data": {"uuid": CHART_UUID}}]}})
    )
    respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate/chart/{CHART_UUID}").mock(
        return_value=httpx.Response(200, json={"results": {"errors": [{"fieldName": "orders_x", "error": "no longer exists"}]}})
    )
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        result = await save(await client(http), PROJECT, "charts", CHART, LIGHTDASH)
    body = json.loads(upsert.calls[0].request.content)
    assert (body["publicSpaceCreate"], body["skipSpaceCreate"]) == (False, False)
    assert result == {
        "action": "create",
        "uuid": CHART_UUID,
        "url": f"{LIGHTDASH}/projects/{PROJECT}/saved/{CHART_UUID}",
        "validationErrors": [{"field": "orders_x", "error": "no longer exists"}],
    }


@respx.mock
async def test_dashboard_tiles_must_show_charts_that_exist():
    tile = {"type": "saved_chart", "x": 0, "y": 0, "w": 36, "h": 8, "properties": {"chartSlug": "revenue-per-week"}}
    mock_lightdash(missing=["revenue-per-week"])
    async with httpx.AsyncClient(base_url=LIGHTDASH) as http:
        ld = await client(http)
        with pytest.raises(ToolError, match="No chart with slug revenue-per-week"):
            await check_dashboard(ld, PROJECT, {"tiles": [tile]})
        with pytest.raises(ToolError, match="Tile 0 is a saved_chart tile without properties.chartSlug"):
            await check_dashboard(ld, PROJECT, {"tiles": [tile | {"properties": {}}]})
        with pytest.raises(ToolError, match="Tile 0 needs w, h"):
            await check_dashboard(ld, PROJECT, {"tiles": [{"type": "markdown", "x": 0, "y": 0, "properties": {}}]})


async def test_slugs_cannot_reach_other_endpoints():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    server = create_server(settings)
    with pytest.raises(ToolError, match="validation error"):
        await server.call_tool("get_chart_code", {"project_uuid": PROJECT, "slug": "../../org"})


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
