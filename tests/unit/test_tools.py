import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fakeredis import FakeAsyncRedis
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver.exceptions import ToolError

from lightdash_mcp.auth.provider import Access, Grant
from lightdash_mcp.auth.store import Store
from lightdash_mcp.config import Settings
from lightdash_mcp.lightdash import LightdashError
from lightdash_mcp.server import create_server
from lightdash_mcp.tools import content, data
from lightdash_mcp.tools.access import add_member, grant, project_access, roles, update_grant
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, WRITE, Slug
from lightdash_mcp.tools.content import _item, _summary, _tile, unused_content
from lightdash_mcp.tools.schedulers import update
from lightdash_mcp.tools.shared import MAX_PAGES, conforms, every_page, space_slug

from .conftest import LIGHTDASH, PROJECT

GROUP = "5e3f3c8a-0b8e-4c39-9a3d-2d4f4b3c1a10"
USER = "8f0a52a0-3c1e-4d0a-9d6e-6c1d2a7c9b11"
QUERY = "0f6b1c1e-6a1f-4b8e-9a4c-1d2e3f4a5b6c"
OTHER_USER = "1a2b3c4d-1111-4222-8333-444455556666"
SPACE = "2d3c1b0a-1111-4222-8333-444455556666"
TARGET_SPACE = "7f6e5d4c-1111-4222-8333-444455556666"
CHART = "d83eaf7e-e041-4a89-af83-e64450cfd524"
DASHBOARD = "c0ffee00-1111-4222-8333-444455556666"
SCHEDULER = "5c4e0d1e-1111-4222-8333-444455556666"
OTHER_PROJECT = "9b8a7c6d-1111-4222-8333-444455556666"

USERS_URL = f"{LIGHTDASH}/api/v1/org/users"
GROUPS_URL = f"{LIGHTDASH}/api/v1/org/groups"
ACCESS_URL = f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access"
GROUP_ACCESSES_URL = f"{LIGHTDASH}/api/v1/projects/{PROJECT}/groupAccesses"
MEMBERS_URL = f"{LIGHTDASH}/api/v1/groups/{GROUP}/members"
CONTENT_URL = f"{LIGHTDASH}/api/v2/content"
DELETE_URL = f"{LIGHTDASH}/api/v2/content/{PROJECT}/delete"
MOVE_URL = f"{LIGHTDASH}/api/v2/content/{PROJECT}/move"
SCHEDULER_URL = f"{LIGHTDASH}/api/v1/schedulers/{SCHEDULER}"
EXPLORE_URL = f"{LIGHTDASH}/api/v1/projects/{PROJECT}/explores/orders"
QUERY_URL = f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query"
POLL_URL = f"{QUERY_URL}/{QUERY}"
VALIDATE_URL = f"{LIGHTDASH}/api/v1/projects/{PROJECT}/validate"
JOB_URL = f"{LIGHTDASH}/api/v1/schedulers/job/job-1/status"

EXPLORE = {
    "name": "orders",
    "baseTable": "orders",
    "tables": {
        "orders": {
            "dimensions": {
                "status": {"table": "orders", "name": "status"},
                "order_date_day": {"table": "orders", "name": "order_date_day"},
                "secret": {"table": "orders", "name": "secret", "hidden": True},
            },
            "metrics": {"revenue": {"table": "orders", "name": "revenue"}},
        }
    },
}
READY = {
    "status": "ready",
    "rows": [{"orders_status": {"value": {"raw": "paid"}}}],
    "columns": {"orders_status": {"label": "Status"}},
    "totalResults": 1,
}

TOOL_ANNOTATIONS = {
    "list_projects": READ,
    "list_users": READ,
    "list_groups": READ,
    "list_roles": READ,
    "list_project_access": READ,
    "list_spaces": READ,
    "list_space_access": READ,
    "grant_project_access": DESTRUCTIVE,
    "update_project_access": DESTRUCTIVE,
    "revoke_project_access": DESTRUCTIVE,
    "add_group_member": DESTRUCTIVE,
    "remove_group_member": DESTRUCTIVE,
    "search_content": READ,
    "get_dashboard": READ,
    "find_unused_content": READ,
    "list_validation_errors": READ,
    "move_content": WRITE,
    "delete_content": DESTRUCTIVE,
    "list_schedulers": READ,
    "set_scheduler_enabled": WRITE,
    "update_scheduler": WRITE,
    "delete_scheduler": DESTRUCTIVE,
    "list_explores": READ,
    "get_explore": READ,
    "run_query": READ,
    "run_chart": READ,
    "get_chart_code": READ,
    "get_dashboard_code": READ,
    "save_chart": DESTRUCTIVE,
    "save_dashboard": DESTRUCTIVE,
}


def results(value) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok", "results": value})


def page_of(items: list, total_pages: int = 1) -> httpx.Response:
    return results({"data": items, "pagination": {"totalPageCount": total_pages}})


def signed_in_tools(settings: Settings, redis: FakeAsyncRedis) -> Callable[..., Awaitable[Any]]:
    """Calls the server's tools as a signed-in user with a fresh Lightdash token, as the bearer
    middleware does."""
    server = create_server(settings, redis)
    store = Store(redis, settings.fernet_key)
    access = Access(
        token="our-access",
        client_id="client",
        scopes=[],
        subject="user",
        grant_id="grant",
    )

    async def call(tool_name: str, /, **arguments: Any) -> Any:
        grant = Grant(
            client_id="client",
            subject="user",
            access_token="ld-access",
            refresh_token="ld-refresh",
            expires_at=time.time() + 3600,
        )
        await store.put("grant", "grant", grant)
        context = auth_context_var.set(AuthenticatedUser(access))
        try:
            result = await server.call_tool(tool_name, arguments)
        finally:
            auth_context_var.reset(context)
        structured = result.structured_content
        return structured["result"] if set(structured) == {"result"} else structured

    return call


@pytest.fixture
def call_tool(settings, redis) -> Callable[..., Awaitable[Any]]:
    return signed_in_tools(settings, redis)


def body_of(route: respx.Route, index: int = 0) -> Any:
    return json.loads(route.calls[index].request.content)


def org_user(uuid: str, role: str, groups: tuple[str, ...] = ()) -> dict:
    return {
        "userUuid": uuid,
        "email": f"{uuid}@example.com",
        "role": role,
        "groups": [{"uuid": group, "name": group} for group in groups],
    }


def mock_query(endpoint: str = "metric-query") -> tuple[respx.Route, respx.Route]:
    """The explore, and a query ready at the first poll. Returns the start and poll routes."""
    respx.get(EXPLORE_URL).mock(return_value=results(EXPLORE))
    start = respx.post(f"{QUERY_URL}/{endpoint}").mock(return_value=results({"queryUuid": QUERY}))
    poll = respx.get(POLL_URL).mock(return_value=results(READY))

    return start, poll


async def test_tools_keep_their_annotations_and_destructive_ones_dry_run_by_default(settings):
    tools = {tool.name: tool for tool in await create_server(settings).list_tools()}

    parameters = {name: tool.input_schema["properties"] for name, tool in tools.items()}
    with_dry_run = {name for name, given in parameters.items() if "dry_run" in given}
    destructive = {name for name, tool in tools.items() if tool.annotations.destructive_hint}

    assert {name: tool.annotations for name, tool in tools.items()} == TOOL_ANNOTATIONS
    assert with_dry_run == destructive
    for name in destructive:
        assert parameters[name]["dry_run"]["default"] is True, name
    for name, annotations in TOOL_ANNOTATIONS.items():
        if annotations == READ:
            assert tools[name].annotations.read_only_hint is True, name


@respx.mock
async def test_access_changes_only_preview_on_a_dry_run(client):
    respx.get(f"{LIGHTDASH}/api/v1/org/users").mock(
        return_value=page_of(
            [{"userUuid": USER, "email": "Alice@example.com", "role": "viewer", "groups": []}]
        )
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access").mock(
        return_value=results([{"userUuid": USER, "email": "alice@example.com", "role": "viewer"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/groupAccesses").mock(
        return_value=results([{"groupUuid": GROUP, "role": "admin"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/org/groups").mock(
        return_value=page_of([{"uuid": GROUP, "name": "Admins"}])
    )
    respx.get(f"{LIGHTDASH}/api/v1/groups/{GROUP}").mock(
        return_value=results({"uuid": GROUP, "name": "Admins"})
    )
    respx.get(f"{LIGHTDASH}/api/v1/groups/{GROUP}/members").mock(return_value=results([]))
    respx.get(f"{LIGHTDASH}/api/v1/org/projects").mock(
        return_value=results([{"projectUuid": PROJECT, "name": "Jaffle"}])
    )
    writes = [
        respx.post(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access").mock(
            return_value=httpx.Response(200)
        ),
        respx.patch(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/access/{USER}").mock(
            return_value=httpx.Response(200)
        ),
        respx.put(f"{LIGHTDASH}/api/v1/groups/{GROUP}/members/{USER}").mock(
            return_value=httpx.Response(204)
        ),
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
    assert changed["wouldChange"] == {
        "userUuid": USER,
        "email": "alice@example.com",
        "from": "viewer",
        "to": "admin",
    }
    added = await add_member(client, GROUP, USER, dry_run=True)
    assert added["wouldAdd"] == {"userUuid": USER, "group": "Admins"}
    assert added["groupGives"] == [{"projectUuid": PROJECT, "project": "Jaffle", "role": "admin"}]
    assert not any(route.called for route in writes)

    await grant(client, PROJECT, "alice@example.com", "admin", dry_run=False)
    await update_grant(client, PROJECT, USER, "admin", dry_run=False)
    await add_member(client, GROUP, USER, dry_run=False)
    assert all(route.call_count == 1 for route in writes)
    assert json.loads(writes[0].calls[0].request.content) == {
        "email": "alice@example.com",
        "role": "admin",
        "sendEmail": False,
    }


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
        return_value=results(
            [
                {"userUuid": "direct-editor", "role": "editor"},
                {"userUuid": "org-admin", "role": "viewer"},
            ]
        )
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
    respx.get(f"{LIGHTDASH}/api/v1/org/groups").mock(
        return_value=page_of([{"uuid": "viewers", "name": "Viewers"}])
    )

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
    assert access["groups"][0] == {
        "groupUuid": "viewers",
        "name": "Viewers",
        "projectRole": "viewer",
    }


@respx.mock
async def test_roles_come_with_their_scopes_when_allowed(client):
    def roles_answer(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("load") == "scopes":
            return httpx.Response(403, json={"error": {"message": "Forbidden"}})
        return results([{"roleUuid": "viewer", "name": "Viewer"}])

    route = respx.get(f"{LIGHTDASH}/api/v2/orgs/org/roles").mock(
        return_value=results(
            [{"roleUuid": "viewer", "name": "Viewer", "scopes": ["view:Dashboard"]}]
        )
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
        "filters": [
            {
                "id": "f",
                "target": {"fieldId": "orders_status"},
                "operator": "equals",
                "values": ["paid"],
            }
        ],
        "parameters": {"region": "EU"},
        "selectedTabs": ["tab"],
        "customViewportWidth": 1400,
        "useCachedResults": True,
        "appState": {"page": 2},
    }
    respx.get(f"{LIGHTDASH}/api/v1/schedulers/{USER}").mock(return_value=results(current))
    patch = respx.patch(f"{LIGHTDASH}/api/v1/schedulers/{USER}").mock(
        return_value=results(current | {"name": "Daily"})
    )
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
    respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/metric-query").mock(
        return_value=results({"queryUuid": QUERY})
    )
    poll = respx.get(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}").mock(
        return_value=results({"status": "pending"})
    )
    cancel = respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}/cancel").mock(
        return_value=results(None)
    )

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
    respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/metric-query").mock(
        return_value=results({"queryUuid": QUERY})
    )
    poll = respx.get(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}").mock(
        return_value=httpx.Response(502, json={"error": {"message": "Bad gateway"}})
    )
    cancel = respx.post(f"{LIGHTDASH}/api/v2/projects/{PROJECT}/query/{QUERY}/cancel").mock(
        return_value=results(None)
    )
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
    other = {
        "uuid": "9e8d7c6b-1111-4222-8333-444455556666",
        "contentType": "space",
        "name": "Everything",
    }
    route = respx.get(f"{LIGHTDASH}/api/v2/content").mock(return_value=page_of([other]))
    with pytest.raises(ToolError, match=f"No space {space} in this project"):
        await _item(client, PROJECT, "space", space)

    route.mock(
        return_value=page_of([other, {"uuid": space, "contentType": "space", "name": "Old"}])
    )
    assert (await _item(client, PROJECT, "space", space.upper()))["name"] == "Old"


def test_viewed_content_is_not_called_never_viewed():
    old = "2020-01-01T00:00:00+00:00"
    items = [
        {
            "uuid": "viewed-no-date",
            "contentType": "chart",
            "name": "a",
            "views": 12,
            "lastViewedAt": None,
            "createdAt": old,
        },
        {
            "uuid": "never",
            "contentType": "chart",
            "name": "b",
            "views": 0,
            "lastViewedAt": None,
            "createdAt": old,
        },
        {
            "uuid": "stale",
            "contentType": "dashboard",
            "name": "c",
            "views": 3,
            "lastViewedAt": old,
            "createdAt": old,
        },
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
    assert (
        _summary({"contentType": "chart", "uuid": "u", "slug": "revenue", "name": "Revenue"})[
            "slug"
        ]
        == "revenue"
    )
    tile = {
        "type": "saved_chart",
        "properties": {"savedChartUuid": "u", "chartSlug": "revenue", "chartName": "Revenue"},
    }
    assert _tile(tile, {})["chartSlug"] == "revenue"
    assert space_slug({"slug": "my_team", "path": "finance.my_team"}) == "finance/my-team"


def test_slug_checks_match_the_whole_value():
    assert conforms(Slug, "revenue-per-week")
    assert not any(conforms(Slug, value) for value in ("revenue\n", "../org", "Revenue", "", 3))


@respx.mock
async def test_access_changes_without_a_direct_grant_send_nothing(client, call_tool):
    other_member = {"userUuid": OTHER_USER, "email": "bob@example.com", "role": "viewer"}
    respx.get(ACCESS_URL).mock(return_value=results([other_member]))
    patch = respx.patch(f"{ACCESS_URL}/{USER}").mock(return_value=httpx.Response(200))
    delete = respx.delete(f"{ACCESS_URL}/{USER}").mock(return_value=httpx.Response(200))

    changed = await update_grant(client, PROJECT, USER, "admin", dry_run=False)
    revoked = await call_tool(
        "revoke_project_access",
        project_uuid=PROJECT,
        user_uuid=USER,
        dry_run=False,
    )

    assert changed["changed"] is None
    assert revoked["removed"] is None
    assert not patch.called
    assert not delete.called


@respx.mock
async def test_revoking_a_grant_only_previews_on_a_dry_run(call_tool):
    member = {"userUuid": USER, "email": "alice@example.com", "role": "editor"}
    respx.get(ACCESS_URL).mock(return_value=results([member]))
    delete = respx.delete(f"{ACCESS_URL}/{USER}").mock(return_value=httpx.Response(200))

    preview = await call_tool("revoke_project_access", project_uuid=PROJECT, user_uuid=USER)

    assert preview == {"wouldRemove": member}
    assert not delete.called


@respx.mock
async def test_group_removals_only_preview_on_a_dry_run_and_skip_non_members(call_tool):
    alice = {"userUuid": USER, "email": "alice@example.com"}
    respx.get(MEMBERS_URL).mock(return_value=results([alice]))
    delete_alice = respx.delete(f"{MEMBERS_URL}/{USER}").mock(return_value=httpx.Response(204))
    delete_bob = respx.delete(f"{MEMBERS_URL}/{OTHER_USER}").mock(return_value=httpx.Response(204))

    preview = await call_tool("remove_group_member", group_uuid=GROUP, user_uuid=USER)
    not_a_member = await call_tool(
        "remove_group_member",
        group_uuid=GROUP,
        user_uuid=OTHER_USER,
        dry_run=False,
    )

    assert preview == {"wouldRemove": alice}
    assert not_a_member["removed"] is None
    assert not delete_alice.called
    assert not delete_bob.called


@respx.mock
async def test_project_access_counts_custom_grants_and_only_groups_with_access(client):
    users = [
        org_user("custom-direct", "member"),
        org_user("custom-and-ranked", "editor", ("custom-group",)),
        org_user("other-group-only", "member", ("no-access-group",)),
    ]
    # A grant with a custom role keeps a system role in `role` too: the custom one is the grant.
    direct = [{"userUuid": "custom-direct", "role": "viewer", "roleUuid": "direct-custom-role"}]
    group_accesses = [{"groupUuid": "custom-group", "role": "group-custom-role"}]
    respx.get(USERS_URL).mock(return_value=page_of(users))
    respx.get(ACCESS_URL).mock(return_value=results(direct))
    respx.get(GROUP_ACCESSES_URL).mock(return_value=results(group_accesses))
    respx.get(GROUPS_URL).mock(return_value=page_of([{"uuid": "custom-group", "name": "Custom"}]))

    access = await project_access(client, PROJECT)

    listed = {user["userUuid"]: user for user in access["users"]}
    assert set(listed) == {"custom-direct", "custom-and-ranked"}
    assert listed["custom-direct"]["directRole"] == "direct-custom-role"
    assert listed["custom-direct"]["projectRole"] is None
    assert listed["custom-direct"]["customRoleUuids"] == ["direct-custom-role"]
    assert listed["custom-and-ranked"]["projectRole"] == "editor"
    assert listed["custom-and-ranked"]["customRoleUuids"] == ["group-custom-role"]
    assert listed["custom-and-ranked"]["groups"] == ["custom-group"]


@respx.mock
async def test_project_access_skips_the_group_list_when_no_group_has_access(client):
    users = [org_user("grouped", "member", ("developers",)), org_user("org-admin", "admin")]
    respx.get(USERS_URL).mock(return_value=page_of(users))
    respx.get(ACCESS_URL).mock(return_value=results([]))
    respx.get(GROUP_ACCESSES_URL).mock(return_value=results([]))
    groups = respx.get(GROUPS_URL).mock(return_value=page_of([]))

    access = await project_access(client, PROJECT)

    assert [user["userUuid"] for user in access["users"]] == ["org-admin"]
    assert access["groups"] == []
    assert not groups.called


@respx.mock
async def test_content_of_another_type_with_the_same_uuid_is_not_the_item(client):
    chart = {"uuid": SPACE, "contentType": "chart", "name": "Same UUID"}
    route = respx.get(CONTENT_URL).mock(return_value=page_of([chart]))

    with pytest.raises(ToolError, match=f"No space {SPACE} in this project"):
        await _item(client, PROJECT, "space", SPACE)

    params = route.calls[0].request.url.params
    assert params["projectUuids"] == PROJECT
    assert params["uuids"] == SPACE
    assert params["contentTypes"] == "space"


@respx.mock
async def test_deleting_a_space_previews_what_it_holds_without_deleting(call_tool):
    space = {"uuid": SPACE, "contentType": "space", "name": "Finance", "slug": "finance"}
    impact = {
        "uuid": SPACE,
        "charts": [{"name": "Revenue"}],
        "dashboards": [],
        "spaces": [{"name": "Archive"}],
    }
    respx.get(CONTENT_URL).mock(return_value=page_of([space]))
    respx.get(f"{LIGHTDASH}/api/v1/projects/{PROJECT}/spaces/{SPACE}/delete-impact").mock(
        return_value=results(impact),
    )
    delete = respx.post(DELETE_URL).mock(return_value=results(None))

    preview = await call_tool(
        "delete_content",
        project_uuid=PROJECT,
        content_type="space",
        uuid=SPACE,
    )

    summary = {
        "contentType": "space",
        "uuid": SPACE,
        "slug": "finance",
        "name": "Finance",
        "space": None,
    }
    includes = {"charts": ["Revenue"], "spaces": ["Archive"]}
    assert preview == {"wouldDelete": {"item": summary, "includes": includes}}
    assert not delete.called


@respx.mock
async def test_deleting_a_chart_sends_its_source(call_tool):
    chart = {"uuid": CHART, "contentType": "chart", "name": "Revenue", "source": "dbt_explore"}
    respx.get(CONTENT_URL).mock(return_value=page_of([chart]))
    delete = respx.post(DELETE_URL).mock(return_value=results(None))

    deleted = await call_tool(
        "delete_content",
        project_uuid=PROJECT,
        content_type="chart",
        uuid=CHART,
        dry_run=False,
    )

    item = {"contentType": "chart", "uuid": CHART, "source": "dbt_explore"}
    assert body_of(delete) == {"item": item, "action": {"type": "delete"}}
    assert deleted["deleted"]["item"]["name"] == "Revenue"


@respx.mock
@pytest.mark.parametrize(
    ("item", "payload"),
    [
        (
            {"uuid": SPACE, "contentType": "space", "name": "Finance"},
            {"contentType": "space", "uuid": SPACE},
        ),
        (
            {"uuid": CHART, "contentType": "chart", "name": "Revenue", "source": "sql"},
            {"contentType": "chart", "uuid": CHART, "source": "sql"},
        ),
    ],
)
async def test_moves_send_the_item_and_the_target_space(call_tool, item, payload):
    respx.get(CONTENT_URL).mock(return_value=page_of([item]))
    move = respx.post(MOVE_URL).mock(return_value=results(None))

    message = await call_tool(
        "move_content",
        project_uuid=PROJECT,
        content_type=item["contentType"],
        uuid=item["uuid"],
        target_space_uuid=TARGET_SPACE,
    )

    action = {"type": "move", "targetSpaceUuid": TARGET_SPACE}
    assert body_of(move) == {"item": payload, "action": action}
    assert message == f'Moved {item["contentType"]} "{item["name"]}".'


@respx.mock
async def test_scheduler_tool_changes_only_the_fields_given(call_tool):
    current = {
        "schedulerUuid": SCHEDULER,
        "name": "Weekly",
        "cron": "0 9 * * 1",
        "timezone": "Europe/Paris",
        "message": "Numbers for the week",
        "targets": [],
    }
    respx.get(SCHEDULER_URL).mock(return_value=results(current))
    patch = respx.patch(SCHEDULER_URL).mock(return_value=results(current | {"name": "Daily"}))

    updated = await call_tool("update_scheduler", scheduler_uuid=SCHEDULER, name="Daily")

    assert body_of(patch) == current | {"name": "Daily"}
    assert updated["name"] == "Daily"
    assert (updated["cron"], updated["timezone"]) == ("0 9 * * 1", "Europe/Paris")


@respx.mock
async def test_queries_need_a_field(call_tool):
    with pytest.raises(ToolError, match="Give at least one dimension or metric"):
        await call_tool("run_query", project_uuid=PROJECT, explore="orders")


@respx.mock
@pytest.mark.parametrize(("limit", "rows"), [(0, 1), (9999, 2500)])
async def test_query_limits_are_clamped_and_ask_one_row_more(call_tool, limit, rows):
    start, poll = mock_query()

    table = await call_tool(
        "run_query",
        project_uuid=PROJECT,
        explore="orders",
        dimensions=["orders_status"],
        limit=limit,
    )

    assert body_of(start)["query"]["limit"] == rows + 1
    assert poll.calls[0].request.url.params["pageSize"] == str(rows)
    assert table == {
        "columns": {"orders_status": "Status"},
        "rows": [{"orders_status": "paid"}],
        "truncated": False,
    }


def described(rule: dict) -> tuple:
    return rule["target"]["fieldId"], rule["operator"], rule["values"]


@respx.mock
async def test_query_filters_are_split_between_dimensions_and_metrics(call_tool):
    start, _ = mock_query()
    past_week = {
        "field_id": "orders_order_date_day",
        "operator": "inThePast",
        "values": [7],
        "settings": {"unitOfTime": "days"},
    }
    filters = [
        {"field_id": "orders_status", "operator": "equals", "values": ["paid"]},
        {"field_id": "orders_revenue", "operator": "greaterThan", "values": [10]},
        past_week,
    ]

    await call_tool(
        "run_query",
        project_uuid=PROJECT,
        explore="orders",
        dimensions=["orders_status"],
        metrics=["orders_revenue"],
        filters=filters,
    )

    body = body_of(start)
    dimension_rules = body["query"]["filters"]["dimensions"]["and"]
    metric_rules = body["query"]["filters"]["metrics"]["and"]
    assert body["context"] == "api"
    dimensions = [described(rule) for rule in dimension_rules]
    metrics = [described(rule) for rule in metric_rules]
    assert dimensions == [
        ("orders_status", "equals", ["paid"]),
        ("orders_order_date_day", "inThePast", [7]),
    ]
    assert "settings" not in dimension_rules[0]
    assert dimension_rules[1]["settings"] == {"unitOfTime": "days"}
    assert metrics == [("orders_revenue", "greaterThan", [10])]


@respx.mock
@pytest.mark.parametrize(
    ("arguments", "unknown"),
    [
        ({"filters": [{"field_id": "orders_profit", "operator": "notNull"}]}, "orders_profit"),
        ({"sorts": [{"field_id": "orders_rank"}]}, "orders_rank"),
        ({"dimensions": ["orders_secret"]}, "orders_secret"),  # hidden
    ],
)
async def test_queries_refuse_fields_the_explore_does_not_show(call_tool, arguments, unknown):
    start, _ = mock_query()
    query = {"project_uuid": PROJECT, "explore": "orders", "dimensions": ["orders_status"]}

    with pytest.raises(ToolError, match=f"Unknown fields in orders: {unknown}\\. See get_explore"):
        await call_tool("run_query", **(query | arguments))

    assert not start.called


@respx.mock
async def test_queries_that_end_in_error_fail(client):
    respx.post(f"{QUERY_URL}/metric-query").mock(return_value=results({"queryUuid": QUERY}))
    respx.get(POLL_URL).mock(return_value=results({"status": "error", "error": "Column not found"}))

    with pytest.raises(ToolError, match=r"The query failed \(error\): Column not found"):
        await data._run(client, PROJECT, "metric-query", {}, 10)


@respx.mock
async def test_a_failed_cancel_does_not_hide_the_query_error(client):
    respx.post(f"{QUERY_URL}/metric-query").mock(return_value=results({"queryUuid": QUERY}))
    bad_gateway = httpx.Response(502, json={"error": {"message": "Bad gateway"}})
    respx.get(POLL_URL).mock(return_value=bad_gateway)
    down = httpx.Response(500, json={"error": {"message": "Down"}})
    cancel = respx.post(f"{POLL_URL}/cancel").mock(return_value=down)

    with pytest.raises(LightdashError) as error:
        await data._run(client, PROJECT, "metric-query", {}, 10)

    assert error.value.status == 502
    assert cancel.call_count == 1


@respx.mock
async def test_explores_with_errors_and_no_tables_are_refused(client):
    broken = {"name": "orders", "errors": [{"message": "Model not found"}]}
    respx.get(EXPLORE_URL).mock(return_value=results(broken))

    with pytest.raises(ToolError, match="Explore orders has errors: .*Model not found"):
        await data.load_explore(client, PROJECT, "orders")


@respx.mock
async def test_charts_run_by_slug(call_tool):
    found = {"uuid": CHART, "projectUuid": PROJECT}
    respx.get(f"{LIGHTDASH}/api/v1/saved/revenue-per-week").mock(return_value=results(found))
    start, _ = mock_query("chart")

    table = await call_tool("run_chart", project_uuid=PROJECT, chart_uuid="revenue-per-week")

    assert body_of(start) == {"chartUuid": CHART, "context": "api"}
    assert table["rows"] == [{"orders_status": "paid"}]


@respx.mock
async def test_charts_do_not_run_with_a_dashboard_of_another_project(call_tool):
    tile = {"uuid": "tile-1", "type": "saved_chart", "properties": {"savedChartUuid": CHART}}
    dashboard = {
        "uuid": DASHBOARD,
        "projectUuid": OTHER_PROJECT,
        "tiles": [tile],
        "filters": {"dimensions": [], "metrics": [], "tableCalculations": []},
    }
    respx.get(f"{LIGHTDASH}/api/v1/dashboards/{DASHBOARD}").mock(return_value=results(dashboard))
    start, _ = mock_query("dashboard-chart")

    with pytest.raises(ToolError):
        await call_tool(
            "run_chart",
            project_uuid=PROJECT,
            chart_uuid=CHART,
            dashboard_uuid=DASHBOARD,
        )

    assert not start.called


@pytest.fixture
def no_waiting(monkeypatch):
    """Validation polls at most 3 times, without waiting between polls."""
    real_sleep = asyncio.sleep

    async def skip(seconds: float) -> None:
        await real_sleep(0)

    monkeypatch.setattr(content, "VALIDATION_TIMEOUT", 3)
    monkeypatch.setattr(asyncio, "sleep", skip)


@respx.mock
@pytest.mark.parametrize(("status", "polls"), [("pending", 3), ("error", 1)])
async def test_revalidation_fails_unless_it_completes(call_tool, no_waiting, status, polls):
    respx.post(VALIDATE_URL).mock(return_value=results({"jobId": "job-1"}))
    job = respx.get(JOB_URL).mock(return_value=results({"status": status}))
    errors = respx.get(VALIDATE_URL).mock(return_value=results([]))

    with pytest.raises(ToolError, match=rf"Validation did not complete \(status: {status}\)"):
        await call_tool("list_validation_errors", project_uuid=PROJECT, revalidate=True)

    assert job.call_count == polls
    assert not errors.called


@respx.mock
async def test_validation_errors_name_the_chart_then_the_dashboard_then_the_table(
    call_tool,
    no_waiting,
):
    respx.post(VALIDATE_URL).mock(return_value=results({"jobId": "job-1"}))
    statuses = [results({"status": "pending"}), results({"status": "completed"})]
    respx.get(JOB_URL).mock(side_effect=statuses)
    found = [
        {"source": "chart", "chartUuid": "chart-1", "dashboardUuid": "dash-1", "chartViews": 4},
        {"source": "dashboard", "dashboardUuid": "dash-1", "tableName": "t", "dashboardViews": 2},
        {"source": "table", "tableName": "t"},
    ]
    respx.get(VALIDATE_URL).mock(return_value=results(found))

    errors = await call_tool("list_validation_errors", project_uuid=PROJECT, revalidate=True)

    assert [(error["source"], error["uuid"], error["views"]) for error in errors] == [
        ("chart", "chart-1", 4),
        ("dashboard", "dash-1", 2),
        ("table", "t", None),
    ]


def test_content_created_within_the_window_is_not_unused():
    old = "2020-01-01T00:00:00+00:00"
    recent = datetime.now(UTC).isoformat()
    items = [
        {"uuid": "new", "contentType": "chart", "name": "a", "views": 0, "createdAt": recent},
        {"uuid": "old", "contentType": "chart", "name": "b", "views": 0, "createdAt": old},
    ]

    unused = unused_content(items, 90)

    assert [item["uuid"] for item in unused] == ["old"]


@respx.mock
async def test_lists_without_pagination_are_one_page(client):
    route = respx.get(USERS_URL).mock(return_value=results({"data": [{"userUuid": "only"}]}))

    users = await every_page(client, "/api/v1/org/users")

    assert users == [{"userUuid": "only"}]
    assert route.call_count == 1


def dashboard_tile(kind: str, tab: str, y: int, x: int, title: str) -> dict:
    return {"type": kind, "tabUuid": tab, "y": y, "x": x, "properties": {"title": title}}


@respx.mock
async def test_dashboards_list_tiles_by_tab_then_row_then_column(call_tool):
    intro = dashboard_tile("markdown", "overview", 0, 0, "Intro")
    intro["properties"]["content"] = "Welcome"
    tiles = [
        dashboard_tile("saved_chart", "details", 0, 0, "Details"),
        dashboard_tile("saved_chart", "overview", 4, 0, "Below"),
        dashboard_tile("saved_chart", "overview", 0, 12, "Right"),
        intro,
    ]
    tabs = [
        {"uuid": "details", "name": "Details", "order": 1},
        {"uuid": "overview", "name": "Overview", "order": 0},
    ]
    dashboard = {"name": "Sales", "projectUuid": PROJECT, "tabs": tabs, "tiles": tiles}
    respx.get(f"{LIGHTDASH}/api/v1/dashboards/{DASHBOARD}").mock(return_value=results(dashboard))

    shown = await call_tool("get_dashboard", dashboard_uuid=DASHBOARD)

    assert [(tile["title"], tile["tab"]) for tile in shown["tiles"]] == [
        ("Intro", "Overview"),
        ("Right", "Overview"),
        ("Below", "Overview"),
        ("Details", "Details"),
    ]
    markdown = {"type": "markdown", "title": "Intro", "tab": "Overview", "content": "Welcome"}
    assert shown["tiles"][0] == markdown
