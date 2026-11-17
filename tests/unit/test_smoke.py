import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.mcpserver.exceptions import ToolError
from redis.asyncio import Redis

from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashClient, LightdashError
from lightdash_mcp.server import create_server
from lightdash_mcp.tools.content import _content
from lightdash_mcp.tools.data import _explores


def test_create_server():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    assert create_server(settings).name == "lightdash-mcp"


async def test_tool_arguments_cannot_reach_other_endpoints():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    server = create_server(settings)
    project = "3675b69e-8324-4110-bdca-059031aa8da3"
    for name, arguments in [
        ("update_project_access", {"project_uuid": project, "user_uuid": "../../../org/users/x", "role": "admin"}),
        ("list_spaces", {"project_uuid": "x?evil=1"}),
        ("get_explore", {"project_uuid": project, "explore": "../orders"}),
    ]:
        with pytest.raises(ToolError, match="validation error"):
            await server.call_tool(name, arguments)


def test_missing_settings_stop_the_server():
    with pytest.raises(SystemExit, match="LIGHTDASH_CLIENT_ID, LIGHTDASH_CLIENT_SECRET, FERNET_KEY"):
        Settings(_env_file=None).check()


def test_public_url_follows_the_port_unless_set():
    assert Settings(_env_file=None, port=9000).public_url == "http://localhost:9000"
    assert Settings(_env_file=None, port=9000, public_url="https://mcp.example.com/").public_url == "https://mcp.example.com"


@respx.mock
async def test_client_sends_bearer_and_unwraps_results():
    route = respx.get("http://lightdash.test/api/v1/user").mock(
        return_value=httpx.Response(200, json={"status": "ok", "results": {"email": "demo@lightdash.com"}})
    )
    async with httpx.AsyncClient(base_url="http://lightdash.test") as http:
        client = LightdashClient(http, "token")
        assert await client.request("GET", "/api/v1/user") == {"email": "demo@lightdash.com"}
    assert route.calls[0].request.headers["Authorization"] == "Bearer token"


@respx.mock
async def test_client_handles_empty_bodies_and_errors():
    respx.put("http://lightdash.test/api/v1/groups/g/members/u").mock(return_value=httpx.Response(204))
    respx.get("http://lightdash.test/api/v2/orgs/o/roles").mock(
        return_value=httpx.Response(
            403, json={"status": "error", "error": {"statusCode": 403, "name": "ForbiddenError", "message": "Not allowed"}}
        )
    )
    async with httpx.AsyncClient(base_url="http://lightdash.test") as http:
        client = LightdashClient(http, "token")
        assert await client.request("PUT", "/api/v1/groups/g/members/u") is None
        with pytest.raises(LightdashError) as error:
            await client.get("/api/v2/orgs/o/roles")
    assert (error.value.status, error.value.message) == (403, "Not allowed")


@respx.mock
async def test_client_treats_redirects_as_errors():
    respx.delete("http://lightdash.test/api/v1/schedulers/s").mock(
        return_value=httpx.Response(302, headers={"Location": "/login"})
    )
    async with httpx.AsyncClient(base_url="http://lightdash.test") as http:
        client = LightdashClient(http, "token")
        with pytest.raises(LightdashError) as error:
            await client.request("DELETE", "/api/v1/schedulers/s")
    assert error.value.status == 302


@respx.mock
async def test_content_reads_every_page():
    def page(request):
        number = int(request.url.params["page"])
        return httpx.Response(200, json={"results": {"data": [{"uuid": str(number)}], "pagination": {"totalPageCount": 60}}})

    respx.get("http://lightdash.test/api/v2/content").mock(side_effect=page)
    async with httpx.AsyncClient(base_url="http://lightdash.test") as http:
        client = LightdashClient(http, "token")
        items = await _content(client, "project")
    assert [i["uuid"] for i in items] == [str(n) for n in range(1, 61)]


@respx.mock
async def test_explores_follow_the_tables_configuration():
    def explores(request):
        # Lightdash leaves out the explores that the tables configuration hides only with filtered=true.
        hidden = [] if request.url.params.get("filtered") == "true" else [{"name": "stg_orders"}]
        return httpx.Response(200, json={"results": [{"name": "orders", "label": "Orders", "groupLabel": "Sales"}, *hidden]})

    respx.get("http://lightdash.test/api/v1/projects/project/explores").mock(side_effect=explores)
    async with httpx.AsyncClient(base_url="http://lightdash.test") as http:
        found = await _explores(LightdashClient(http, "token"), "project")
    assert found == [{"name": "orders", "label": "Orders", "group": "Sales", "description": None}]


async def test_health_follows_redis():
    settings = Settings(
        _env_file=None, lightdash_client_id="id", lightdash_client_secret="secret", fernet_key=Fernet.generate_key().decode()
    )
    for redis, status in [(FakeAsyncRedis(), 200), (Redis.from_url("redis://localhost:1"), 503)]:
        app = create_server(settings, redis).streamable_http_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://localhost") as client:
            assert (await client.get("/health")).status_code == status


def test_access_token_lifetime_is_bounded():
    assert Settings(_env_file=None).access_token_ttl == 3600
    assert Settings(_env_file=None, access_token_ttl=86400).access_token_ttl == 86400
    with pytest.raises(ValueError):
        Settings(_env_file=None, access_token_ttl=30 * 24 * 60 * 60)


def required() -> dict:
    return {"_env_file": None, "lightdash_client_id": "id", "lightdash_client_secret": "secret", "fernet_key": "key"}


def test_addresses_are_checked_at_start(caplog):
    Settings(**required()).check()
    Settings(**required(), host="127.0.0.1", public_url="https://lightdash-mcp.tail5566.ts.net").check()
    assert not caplog.records
    for address, error in [
        ({"lightdash_url": "lightdash.example.com"}, "LIGHTDASH_URL"),
        ({"lightdash_url": "ftp://lightdash.example.com"}, "LIGHTDASH_URL"),
        ({"public_url": "http://mcp.example.com"}, "PUBLIC_URL must be https"),
        ({"public_url": "https://example.com/mcp"}, "at the root"),
        ({"public_url": "mcp.example.com"}, "PUBLIC_URL"),
    ]:
        with pytest.raises(SystemExit, match=error):
            Settings(**required(), **address).check()

    # Listening on every interface behind an HTTPS address lets clients around the proxy: allowed, as Docker's
    # published ports need it, but said loudly.
    Settings(**required(), host="0.0.0.0", public_url="https://mcp.example.com").check()
    assert "HOST=0.0.0.0" in caplog.text


def test_redirect_hosts_are_a_comma_separated_list(monkeypatch):
    assert Settings(_env_file=None).redirect_hosts == []
    monkeypatch.setenv("REDIRECT_HOSTS", "dex.example.com, North.Example.com,")
    assert Settings(_env_file=None).redirect_hosts == ["dex.example.com", "north.example.com"]
