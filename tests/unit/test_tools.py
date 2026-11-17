import asyncio
import json

import httpx
import pytest
import respx
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.lightdash import LightdashError
from lightdash_mcp.server import create_server
from lightdash_mcp.tools import data
from lightdash_mcp.tools.access import add_member, grant, project_access, roles, update_grant
from lightdash_mcp.tools.common import Slug
from lightdash_mcp.tools.content import _item, _summary, _tile, unused_content
from lightdash_mcp.tools.schedulers import update
from lightdash_mcp.tools.shared import MAX_PAGES, conforms, every_page, space_slug

from .conftest import LIGHTDASH, PROJECT

GROUP = "5e3f3c8a-0b8e-4c39-9a3d-2d4f4b3c1a10"
USER = "8f0a52a0-3c1e-4d0a-9d6e-6c1d2a7c9b11"
QUERY = "0f6b1c1e-6a1f-4b8e-9a4c-1d2e3f4a5b6c"


def results(value) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok", "results": value})


def page_of(items: list, total_pages: int = 1) -> httpx.Response:
    return results({"data": items, "pagination": {"totalPageCount": total_pages}})


async def test_access_changes_are_destructive_and_dry_run_by_default(settings):
    tools = {tool.name: tool for tool in await create_server(settings).list_tools()}
    for name in ("grant_project_access", "update_project_access", "add_group_member"):
        assert tools[name].annotations.destructive_hint is True
    for tool in tools.values():
        if tool.annotations.destructive_hint:
            assert tool.input_schema["properties"]["dry_run"]["default"] is True, tool.name


@respx.mock
async def test_access_changes_only_preview_on_a_dry_run(client):
    respx.get(f"{LIGHTDASH}/api/v1/org/users").mock(
        return_value=page_of([{"userUuid": USER, "email": "Alice@example.com", "role": "viewer", "groups": []}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access").mock(
        return_value=results([{"userUuid": USER, "email": "alice@example.com", "role": "viewer"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/groupAccesses").mock(
        return_value=results([{"groupUuid": GROUP, "role": "admin"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/org/groups").mock(return_value=page_of([{"uuid": GROUP, "name": "Admins"}]))
    respx.get(f"{LIGHTDASH}/api/v1/groups/{GROUP}").mock(return_value=results({"uuid": GROUP, "name": "Admins"}))
    respx.get(f"{LIGHTDASH}/api/v1/groups/{GROUP}/members").mock(return_value=results([]))
    respx.get(f"{LIGHTDASH}/api/v1/org/projects").mock(return_value=results([{"projectUuid": PROJECT, "name": "Jaffle"}]))
    writes = [
        respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access").mock(return_value=httpx.Response(200)),
        respx.patch(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access/{USER}").mock(return_value=httpx.Response(200)),
        respx.put(f"{LIGHTDASH}/api/v1/groups/{GROUP}/members/{USER}").mock(return_value=httpx.Response(204)),
    ]

    granted = await grant(client, PROJECT, "alice@example.com", "admin", dry_run=True)
    assert granted["wouldGrant"] == {"email": "alice@example.com", "role": "admin"}
    assert granted["currentAccess"] == {
        "projectRole": "viewer",
        "organizationRole": "viewer",
        "directRole": "viewer",
        "groups": [],
    }
    changed = await update_grant(client, PROJECT, USER, "admin", dry_run=True)
    assert changed["wouldChange"] == {"userUuid": USER, "email": "alice@example.com", "from": "viewer", "to": "admin"}
    added = await add_member(client, GROUP, USER, dry_run=True)
    assert added["wouldAdd"] == {"userUuid": USER, "group": "Admins"}
    assert added["groupGives"] == [{"projectUuid": PROJECT, "project": "Jaffle", "role": "admin"}]
    assert not any(route.called for route in writes)

    await grant(client, PROJECT, "alice@example.com", "admin", dry_run=False)
    await update_grant(client, PROJECT, USER, "admin", dry_run=False)
    await add_member(client, GROUP, USER, dry_run=False)
    assert all(route.call_count == 1 for route in writes)
    assert json.loads(writes[0].calls[0].request.content) == {"email": "alice@example.com", "role": "admin", "sendEmail": False}


@respx.mock
async def test_project_access_is_the_highest_role_from_any_source(client):
    def user(uuid: str, role: str, groups: list[str] = ()) -> dict:
        return {
            "userUuid": uuid,
            "email": f"{uuid}@example.com",
            "role": role,
            "groups": [{"uuid": g, "name": g} for g in groups],
        }

    respx.get(f"{LIGHTDASH}/api/v1/org/users").mock(
        return_value=page_of(
            [
                user("no-access", "member"),
                user("org-admin", "admin"),
                user("direct-editor", "member"),
                user("best-group", "viewer", ["viewers", "developers"]),
                user("custom", "member", ["custom-group"]),
            ]
        )
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access").mock(
        return_value=results([{"userUuid": "direct-editor", "role": "editor"}, {"userUuid": "org-admin", "role": "viewer"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/groupAccesses").mock(
        return_value=results(
            [
                {"groupUuid": "viewers", "role": "viewer"},
                {"groupUuid": "developers", "role": "developer"},
                {"groupUuid": "custom-group", "role": "4b1f0c0e-custom-role"},
            ]
        )
    )
    respx.get(f"{LIGHTDASH}/api/v1/org/groups").mock(return_value=page_of([{"uuid": "viewers", "name": "Viewers"}]))

    access = await project_access(client, PROJECT)
    users = {u["userUuid"]: u for u in access["users"]}
    assert "no-access" not in users
    assert {uuid: u["projectRole"] for uuid, u in users.items()} == {
        "org-admin": "admin",
        "direct-editor": "editor",
        "best-group": "developer",
        "custom": None,
    }
    assert users["custom"]["customRoleUuids"] == ["4b1f0c0e-custom-role"]
    assert users["org-admin"]["directRole"] == "viewer"
    assert access["groups"][0] == {"groupUuid": "viewers", "name": "Viewers", "projectRole": "viewer"}


@respx.mock
async def test_roles_come_with_their_scopes_when_allowed(client):
    def roles_answer(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("load") == "scopes":
            return httpx.Response(403, json={"error": {"message": "Forbidden"}})
        return results([{"roleUuid": "viewer", "name": "Viewer"}])

    route = respx.get(f"{LIGHTDASH}/api/v2/orgs/org/roles").mock(
        return_value=results([{"roleUuid": "viewer", "name": "Viewer", "scopes": ["view:Dashboard"]}])
    )
    assert (await roles(client, "org"))[0]["scopes"] == ["view:Dashboard"]
    assert route.calls[0].request.url.params["load"] == "scopes"

    route.mock(side_effect=roles_answer)
    assert (await roles(client, "org"))[0] == {
        "roleUuid": "viewer",
        "name": "Viewer",
        "description": None,
        "ownerType": None,
        "level": None,
        "scopes": None,
    }

    route.mock(return_value=httpx.Response(500, json={"error": {"message": "Down"}}))
    with pytest.raises(LightdashError):
        await roles(client, "org")


@respx.mock
async def test_scheduler_updates_send_back_every_field(client):
    current = {
        "schedulerUuid": USER,
        "name": "Weekly",
        "cron": "0 9 * * 1",
        "targets": [{"schedulerEmailTargetUuid": "t", "recipient": "a@example.com"}],
        "filters": [{"id": "f", "target": {"fieldId": "orders_status"}, "operator": "equals", "values": ["paid"]}],
        "parameters": {"region": "EU"},
        "selectedTabs": ["tab"],
        "customViewportWidth": 1400,
        "useCachedResults": True,
        "appState": {"page": 2},
    }
    respx.get(f"{LIGHTDASH}/api/v1/schedulers/{USER}").mock(return_value=results(current))
    patch = respx.patch(f"{LIGHTDASH}/api/v1/schedulers/{USER}").mock(return_value=results(current | {"name": "Daily"}))
    await update(client, USER, {"name": "Daily"})
    assert json.loads(patch.calls[0].request.content) == current | {"name": "Daily"}


@respx.mock
async def test_lists_follow_every_page_up_to_a_cap(client):
    def users(request: httpx.Request) -> httpx.Response:
        number = int(request.url.params["page"])
        return page_of([{"userUuid": str(number)}], total_pages=3)

    route = respx.get(f"{LIGHTDASH}/api/v1/org/users").mock(side_effect=users)
    assert [u["userUuid"] for u in await every_page(client, "/api/v1/org/users")] == ["1", "2", "3"]
    assert route.calls[0].request.url.params["pageSize"] == "100"

    route.mock(return_value=page_of([], total_pages=0))
    assert await every_page(client, "/api/v1/org/users") == []

    route.mock(return_value=page_of([{"userUuid": "x"}], total_pages=MAX_PAGES + 1))
    with pytest.raises(ToolError, match="narrow the search"):
        await every_page(client, "/api/v1/org/users")


@respx.mock
async def test_queries_are_cancelled_when_they_time_out(client, monkeypatch):
    monkeypatch.setattr(data, "QUERY_TIMEOUT", 0.2)
    respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/metric-query").mock(return_value=results({"queryUuid": QUERY}))
    poll = respx.get(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}").mock(return_value=results({"status": "pending"}))
    cancel = respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}/cancel").mock(return_value=results(None))

    with pytest.raises(ToolError, match="more than 0.2 seconds and was cancelled"):
        await data._run(client, PROJECT, "metric-query", {}, 10)
    assert cancel.call_count == 1

    # A slow answer counts against the same deadline: it isn't a number of polls.
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return results({"status": "pending"})

    poll.mock(side_effect=slow)
    with pytest.raises(ToolError, match="was cancelled"):
        await asyncio.wait_for(data._run(client, PROJECT, "metric-query", {}, 10), 0.8)
    assert cancel.call_count == 2


@respx.mock
async def test_queries_are_cancelled_when_polling_fails_or_the_call_is_cancelled(client):
    respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/metric-query").mock(return_value=results({"queryUuid": QUERY}))
    poll = respx.get(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}").mock(
        return_value=httpx.Response(502, json={"error": {"message": "Bad gateway"}})
    )
    cancel = respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}/cancel").mock(return_value=results(None))
    with pytest.raises(LightdashError):
        await data._run(client, PROJECT, "metric-query", {}, 10)
    assert cancel.call_count == 1

    poll.mock(return_value=results({"status": "pending"}))
    task = asyncio.create_task(data._run(client, PROJECT, "metric-query", {}, 10))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancel.call_count == 2


@respx.mock
async def test_content_actions_check_the_item_they_act_on(client):
    space = "2d3c1b0a-1111-4222-8333-444455556666"
    other = {"uuid": "9e8d7c6b-1111-4222-8333-444455556666", "contentType": "space", "name": "Everything"}
    route = respx.get(f"{LIGHTDASH}/api/v2/content").mock(return_value=page_of([other]))
    with pytest.raises(ToolError, match=f"No space {space} in this project"):
        await _item(client, PROJECT, "space", space)

    route.mock(return_value=page_of([other, {"uuid": space, "contentType": "space", "name": "Old"}]))
    assert (await _item(client, PROJECT, "space", space.upper()))["name"] == "Old"


def test_viewed_content_is_not_called_never_viewed():
    old = "2020-01-01T00:00:00+00:00"
    items = [
        {"uuid": "viewed-no-date", "contentType": "chart", "name": "a", "views": 12, "lastViewedAt": None, "createdAt": old},
        {"uuid": "never", "contentType": "chart", "name": "b", "views": 0, "lastViewedAt": None, "createdAt": old},
        {"uuid": "stale", "contentType": "dashboard", "name": "c", "views": 3, "lastViewedAt": old, "createdAt": old},
        {
            "uuid": "recent",
            "contentType": "dashboard",
            "name": "d",
            "views": 3,
            "lastViewedAt": "2999-01-01T00:00:00+00:00",
            "createdAt": old,
        },
    ]
    assert [i["uuid"] for i in unused_content(items, 90)] == ["never", "stale"]


def test_content_comes_with_slugs():
    assert _summary({"contentType": "chart", "uuid": "u", "slug": "revenue", "name": "Revenue"})["slug"] == "revenue"
    tile = {"type": "saved_chart", "properties": {"savedChartUuid": "u", "chartSlug": "revenue", "chartName": "Revenue"}}
    assert _tile(tile, {})["chartSlug"] == "revenue"
    assert space_slug({"slug": "my_team", "path": "finance.my_team"}) == "finance/my-team"


def test_slug_checks_match_the_whole_value():
    assert conforms(Slug, "revenue-per-week")
    assert not any(conforms(Slug, value) for value in ("revenue\n", "../org", "Revenue", "", 3))
