import httpx
import pytest
import respx
from fakeredis import FakeAsyncRedis
from mcp.server.mcpserver.exceptions import ToolError
from redis.asyncio import Redis

from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashError
from lightdash_mcp.server import create_server
from lightdash_mcp.tools.content import _content
from lightdash_mcp.tools.data import _explores

from .conftest import LIGHTDASH, PROJECT, make_settings

ORG_URL = f"{LIGHTDASH}/api/v1/org"


def test_create_server(settings):
    server = create_server(settings)

    assert server.name == "lightdash-mcp"


async def test_tool_arguments_cannot_reach_other_endpoints(settings):
    server = create_server(settings)
    escapes = [
        (
            "update_project_access",
            {
                "project_uuid": PROJECT,
                "user_uuid": "../../../org/users/x",
                "role": "admin",
            },
        ),
        ("list_spaces", {"project_uuid": "x?evil=1"}),
        ("get_explore", {"project_uuid": PROJECT, "explore": "../orders"}),
    ]

    for name, arguments in escapes:
        with pytest.raises(ToolError, match="validation error"):
            await server.call_tool(name, arguments)


def test_missing_settings_stop_the_server():
    settings = Settings(_env_file=None)
    missing = "LIGHTDASH_CLIENT_ID, LIGHTDASH_CLIENT_SECRET, FERNET_KEY"

    with pytest.raises(SystemExit, match=missing):
        settings.check()


def test_public_url_follows_the_port_unless_set():
    default = Settings(_env_file=None, port=9000)
    configured = Settings(_env_file=None, port=9000, public_url="https://mcp.example.com/")

    assert default.public_url == "http://localhost:9000"
    assert configured.public_url == "https://mcp.example.com"


@respx.mock
async def test_client_sends_bearer_and_unwraps_results(client):
    user = {"status": "ok", "results": {"email": "demo@lightdash.com"}}
    route = respx.get(f"{LIGHTDASH}/api/v1/user").mock(return_value=httpx.Response(200, json=user))

    result = await client.request("GET", "/api/v1/user")

    sent = route.calls[0].request
    assert result == {"email": "demo@lightdash.com"}
    assert sent.headers["Authorization"] == "Bearer token"


@respx.mock
async def test_client_handles_empty_bodies_and_errors(client):
    forbidden = {
        "status": "error",
        "error": {"statusCode": 403, "name": "ForbiddenError", "message": "Not allowed"},
    }
    members_url = f"{LIGHTDASH}/api/v1/groups/g/members/u"
    respx.put(members_url).mock(return_value=httpx.Response(204))
    respx.get(f"{LIGHTDASH}/api/v2/orgs/o/roles").mock(
        return_value=httpx.Response(403, json=forbidden)
    )

    empty = await client.request("PUT", "/api/v1/groups/g/members/u")

    assert empty is None

    with pytest.raises(LightdashError) as error:
        await client.get("/api/v2/orgs/o/roles")

    assert error.value.status == 403
    assert error.value.message == "Not allowed"


@respx.mock
async def test_client_treats_redirects_as_errors(client):
    redirect = httpx.Response(302, headers={"Location": "/login"})
    respx.delete(f"{LIGHTDASH}/api/v1/schedulers/s").mock(return_value=redirect)

    with pytest.raises(LightdashError) as error:
        await client.request("DELETE", "/api/v1/schedulers/s")

    assert error.value.status == 302


@respx.mock
async def test_content_reads_every_page(client):
    def page(request):
        number = int(request.url.params["page"])
        results = {
            "data": [{"uuid": str(number)}],
            "pagination": {"totalPageCount": 60},
        }

        return httpx.Response(200, json={"results": results})

    respx.get(f"{LIGHTDASH}/api/v2/content").mock(side_effect=page)

    items = await _content(client, "project")

    uuids = [item["uuid"] for item in items]
    assert uuids == [str(number) for number in range(1, 61)]


@respx.mock
async def test_explores_follow_the_tables_configuration(client):
    def explores(request):
        # Lightdash leaves out the explores that the tables configuration hides only with
        # filtered=true.
        is_filtered = request.url.params.get("filtered") == "true"
        orders = {"name": "orders", "label": "Orders", "groupLabel": "Sales"}
        hidden = [] if is_filtered else [{"name": "stg_orders"}]

        return httpx.Response(200, json={"results": [orders, *hidden]})

    respx.get(f"{LIGHTDASH}/api/v1/projects/project/explores").mock(side_effect=explores)

    found = await _explores(client, "project")

    assert found == [{"name": "orders", "label": "Orders", "group": "Sales", "description": None}]


async def test_health_follows_redis(settings):
    cases = [
        (FakeAsyncRedis(), 200),
        (Redis.from_url("redis://localhost:1"), 503),
    ]

    for redis, status in cases:
        server = create_server(settings, redis)
        transport = httpx.ASGITransport(server.streamable_http_app())

        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as http:
            response = await http.get("/health")

        assert response.status_code == status


def test_access_token_lifetime_is_bounded():
    default = Settings(_env_file=None)
    a_day = Settings(_env_file=None, access_token_ttl=86400)

    assert default.access_token_ttl == 3600
    assert a_day.access_token_ttl == 86400

    with pytest.raises(ValueError):
        Settings(_env_file=None, access_token_ttl=30 * 24 * 60 * 60)


def test_addresses_are_checked_at_start(caplog):
    refused = [
        ({"lightdash_url": "lightdash.example.com"}, "LIGHTDASH_URL"),
        ({"lightdash_url": "ftp://lightdash.example.com"}, "LIGHTDASH_URL"),
        ({"public_url": "http://mcp.example.com"}, "PUBLIC_URL must be https"),
        ({"public_url": "https://example.com/mcp"}, "at the root"),
        ({"public_url": "mcp.example.com"}, "PUBLIC_URL"),
    ]

    make_settings().check()
    make_settings(host="127.0.0.1", public_url="https://mcp.example.com").check()

    assert not caplog.records

    for address, error in refused:
        with pytest.raises(SystemExit, match=error):
            make_settings(**address).check()

    # Listening on every interface behind an HTTPS address lets clients around the proxy:
    # allowed, as Docker's published ports need it, but said loudly.
    make_settings(host="0.0.0.0", public_url="https://mcp.example.com").check()

    assert "HOST=0.0.0.0" in caplog.text


def test_redirect_hosts_are_a_comma_separated_list(monkeypatch):
    default = Settings(_env_file=None)

    assert default.redirect_hosts == []

    monkeypatch.setenv("REDIRECT_HOSTS", "dex.example.com, Claude.AI,")
    configured = Settings(_env_file=None)

    assert configured.redirect_hosts == ["dex.example.com", "claude.ai"]


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (httpx.Response(500, json={"error": {"name": "InternalError"}}), "InternalError"),
        (httpx.Response(502, json={"error": {}}), "Bad Gateway"),
        (httpx.Response(503), "Service Unavailable"),
        (httpx.Response(500, text="x" * 1000), "x" * 300),
        (httpx.Response(400, json={"error": "Bad request"}), "Bad request"),
        (httpx.Response(400, json={"error": "y" * 1000}), "y" * 300),
        (httpx.Response(400, json=["first", "second"]), "['first', 'second']"),
    ],
)
@respx.mock
async def test_client_errors_read_whatever_lightdash_sends(client, answer, message):
    respx.get(ORG_URL).mock(return_value=answer)

    with pytest.raises(LightdashError) as error:
        await client.get("/api/v1/org")

    assert error.value.status == answer.status_code
    assert error.value.message == message


@respx.mock
async def test_client_without_a_refresh_does_not_retry_a_401(client):
    refused = httpx.Response(401, json={"error": {"message": "Expired"}})
    route = respx.get(ORG_URL).mock(return_value=refused)

    with pytest.raises(LightdashError) as error:
        await client.get("/api/v1/org")

    assert error.value.status == 401
    assert error.value.message == "Expired"
    assert route.call_count == 1


@pytest.mark.parametrize(
    "public_url",
    [
        "https://mcp.example.com?next=1",
        "https://mcp.example.com#top",
        "https://mcp.example.com/mcp/",
        "http://:8000",
        "http://",
    ],
)
def test_public_url_must_be_the_root_of_a_host(public_url):
    settings = make_settings(public_url=public_url)

    with pytest.raises(SystemExit, match="PUBLIC_URL"):
        settings.check()


def test_settings_accept_ipv6_loopback_and_strip_trailing_slashes():
    make_settings(public_url="http://[::1]:8000").check()

    with_trailing_slash = make_settings(lightdash_url=f"{LIGHTDASH}/")

    assert with_trailing_slash.lightdash_url == LIGHTDASH


def test_access_token_lifetime_is_at_least_a_minute():
    a_minute = make_settings(access_token_ttl=60)

    assert a_minute.access_token_ttl == 60

    with pytest.raises(ValueError):
        make_settings(access_token_ttl=59)
