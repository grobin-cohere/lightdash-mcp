"""Every tool against the local Lightdash, as the admin and as the viewer."""

import json
import logging
import secrets
from typing import Any

import httpx
import pytest

from .conftest import ADMIN, EDITOR

CONTENT = "/api/v2/content"
UNKNOWN_UUID = "00000000-0000-4000-8000-000000000000"
PAYMENT_METHOD_CHART = "How much revenue do we have per payment method?"


def ok(result) -> Any:
    assert not result.is_error, result.content

    content = result.structured_content

    return content["result"] if set(content) == {"result"} else content


def denied(result) -> str:
    assert result.is_error

    return result.content[0].text


def list_content(lightdash_admin: httpx.Client, params: dict[str, Any]) -> list[dict[str, Any]]:
    response = lightdash_admin.get(CONTENT, params=params)

    return response.json()["results"]["data"]


def direct_role(access: dict[str, Any], user_uuid: str) -> str | None:
    roles = (user["directRole"] for user in access["users"] if user["userUuid"] == user_uuid)

    return next(roles, None)


@pytest.fixture
def editor_uuid(lightdash_admin: httpx.Client) -> str:
    users = lightdash_admin.get("/api/v1/org/users").json()["results"]["data"]

    return next(user["userUuid"] for user in users if user["email"] == EDITOR)


@pytest.fixture
def space(lightdash_admin: httpx.Client, project_uuid: str):
    created = lightdash_admin.post(
        f"/api/v1/projects/{project_uuid}/spaces",
        json={"name": "mcp test space"},
    )
    uuid = created.json()["results"]["uuid"]

    yield uuid

    lightdash_admin.delete(f"/api/v1/projects/{project_uuid}/spaces/{uuid}")


@pytest.fixture
def scheduler(lightdash_admin: httpx.Client, project_uuid: str):
    params = {"projectUuids": project_uuid, "contentTypes": "chart", "pageSize": 100}
    charts = list_content(lightdash_admin, params)
    chart = next(
        candidate
        for candidate in charts
        if candidate["chartKind"] in ("vertical_bar", "line", "table")
    )
    delivery = {
        "name": "mcp test delivery",
        "message": "mcp test message",
        "format": "csv",
        "cron": "0 9 * * 1",
        "timezone": "UTC",
        "enabled": True,
        "options": {"formatted": True, "limit": "table"},
        "targets": [{"recipient": ADMIN}],
        "includeLinks": True,
        "appUuid": None,  # required by the request schema, though not for a chart
        "appName": None,
    }
    created = lightdash_admin.post(f"/api/v1/saved/{chart['uuid']}/schedulers", json=delivery)
    uuid = created.json()["results"]["schedulerUuid"]

    yield uuid

    lightdash_admin.delete(f"/api/v1/schedulers/{uuid}")


async def test_read_tools(admin, tool, project_uuid):
    project = {"project_uuid": project_uuid}

    projects = ok(await tool(admin, "list_projects"))
    assert project_uuid in [listed["projectUuid"] for listed in projects]

    users = ok(await tool(admin, "list_users"))
    emails = {user["email"] for user in users}
    assert {ADMIN, EDITOR} <= emails

    groups = ok(await tool(admin, "list_groups"))
    assert groups
    assert all("members" in group for group in groups)

    roles = ok(await tool(admin, "list_roles"))
    role_names = {role["name"] for role in roles}
    viewer_roles = [role for role in roles if role["name"] == "Viewer"]
    assert {"Admin", "Viewer"} <= role_names
    assert all(role["scopes"] for role in viewer_roles)

    access = ok(await tool(admin, "list_project_access", project))
    admin_roles = [user["projectRole"] for user in access["users"] if user["email"] == ADMIN]
    assert "admin" in admin_roles

    spaces = ok(await tool(admin, "list_spaces", project))
    assert spaces
    assert all(listed["spaceSlug"] for listed in spaces)

    first_space = {**project, "space_uuid": spaces[0]["spaceUuid"]}
    space_access = ok(await tool(admin, "list_space_access", first_space))
    assert space_access["users"]

    unused = ok(await tool(admin, "find_unused_content", {**project, "unused_days": 0}))
    content_types = {item["contentType"] for item in unused}
    assert unused
    assert content_types <= {"chart", "dashboard"}

    revalidate = {**project, "revalidate": True}
    errors = ok(await tool(admin, "list_validation_errors", revalidate))
    assert isinstance(errors, list)


async def test_permissions_follow_the_user(admin, viewer, tool, project_uuid, editor_uuid):
    roles = ok(await tool(admin, "list_roles"))
    assert roles

    roles_message = denied(await tool(viewer, "list_roles"))
    assert "Permission denied" in roles_message

    project = {"project_uuid": project_uuid}
    schedulers_message = denied(await tool(viewer, "list_schedulers", project))
    assert "Permission denied" in schedulers_message

    grant = {
        **project,
        "email": EDITOR,
        "role": "viewer",
        "dry_run": False,
    }
    grant_message = denied(await tool(viewer, "grant_project_access", grant))
    assert "Permission denied" in grant_message


async def test_project_access_lifecycle(admin, tool, lightdash_admin, project_uuid, editor_uuid):
    lightdash_admin.delete(f"/api/v1/projects/{project_uuid}/access/{editor_uuid}")
    args = {"project_uuid": project_uuid}

    async def editor_role() -> str | None:
        access = ok(await tool(admin, "list_project_access", args))
        return direct_role(access, editor_uuid)

    grant = {**args, "email": EDITOR, "role": "editor"}
    grant_preview = ok(await tool(admin, "grant_project_access", grant))
    assert grant_preview["wouldGrant"] == {"email": EDITOR, "role": "editor"}
    role = await editor_role()
    assert role is None

    ok(await tool(admin, "grant_project_access", {**grant, "dry_run": False}))
    role = await editor_role()
    assert role == "editor"

    update = {**args, "user_uuid": editor_uuid, "role": "viewer"}
    update_preview = ok(await tool(admin, "update_project_access", update))
    assert update_preview["wouldChange"]["from"] == "editor"

    ok(await tool(admin, "update_project_access", {**update, "dry_run": False}))
    role = await editor_role()
    assert role == "viewer"

    revoke = {**args, "user_uuid": editor_uuid}
    revoke_preview = ok(await tool(admin, "revoke_project_access", revoke))
    assert revoke_preview["wouldRemove"]["role"] == "viewer"
    role = await editor_role()
    assert role == "viewer"

    ok(await tool(admin, "revoke_project_access", {**revoke, "dry_run": False}))
    role = await editor_role()
    assert role is None


async def test_group_membership(admin, tool, editor_uuid):
    groups = ok(await tool(admin, "list_groups"))
    group = next(listed for listed in groups if listed["name"] == "Org 1 Group")
    args = {"group_uuid": group["groupUuid"], "user_uuid": editor_uuid}

    def members(groups) -> set[str]:
        current = next(listed for listed in groups if listed["groupUuid"] == group["groupUuid"])
        return {member["userUuid"] for member in current["members"]}

    add_preview = ok(await tool(admin, "add_group_member", args))
    assert add_preview["wouldAdd"]["group"] == "Org 1 Group"

    groups = ok(await tool(admin, "list_groups"))
    assert editor_uuid not in members(groups)

    ok(await tool(admin, "add_group_member", {**args, "dry_run": False}))
    added_again = ok(await tool(admin, "add_group_member", {**args, "dry_run": False}))
    assert added_again["added"] is None  # already a member

    groups = ok(await tool(admin, "list_groups"))
    assert editor_uuid in members(groups)

    remove_preview = ok(await tool(admin, "remove_group_member", args))
    assert remove_preview["wouldRemove"]["email"] == EDITOR

    groups = ok(await tool(admin, "list_groups"))
    assert editor_uuid in members(groups)

    ok(await tool(admin, "remove_group_member", {**args, "dry_run": False}))
    groups = ok(await tool(admin, "list_groups"))
    assert editor_uuid not in members(groups)


async def test_scheduler_lifecycle(admin, tool, project_uuid, scheduler, lightdash_admin):
    project = {"project_uuid": project_uuid}
    scheduler_url = f"/api/v1/schedulers/{scheduler}"

    def find(schedulers) -> dict[str, Any]:
        return next(listed for listed in schedulers if listed["schedulerUuid"] == scheduler)

    schedulers = ok(await tool(admin, "list_schedulers", project))
    listed = find(schedulers)
    assert listed["recipients"] == [ADMIN]

    rename = {"scheduler_uuid": scheduler, "name": "renamed"}
    renamed = ok(await tool(admin, "update_scheduler", rename))
    stored = lightdash_admin.get(scheduler_url).json()["results"]
    assert renamed["name"] == "renamed"
    assert renamed["cron"] == "0 9 * * 1"
    assert renamed["timezone"] == "UTC"
    assert stored["timezone"] == "UTC"
    assert stored["message"] == "mcp test message"

    reschedule = {**rename, "cron": "0 7 * * 2"}
    updated = ok(await tool(admin, "update_scheduler", reschedule))
    assert updated["name"] == "renamed"
    assert updated["cron"] == "0 7 * * 2"
    assert updated["recipients"] == [ADMIN]

    disable = {"scheduler_uuid": scheduler, "enabled": False}
    ok(await tool(admin, "set_scheduler_enabled", disable))
    schedulers = ok(await tool(admin, "list_schedulers", project))
    assert find(schedulers)["enabled"] is False

    delete = {"scheduler_uuid": scheduler}
    delete_preview = ok(await tool(admin, "delete_scheduler", delete))
    assert delete_preview["wouldDelete"]["name"] == "renamed"

    before_delete = lightdash_admin.get(scheduler_url)
    assert before_delete.status_code == 200

    ok(await tool(admin, "delete_scheduler", {**delete, "dry_run": False}))
    after_delete = lightdash_admin.get(scheduler_url)
    assert after_delete.status_code == 404


async def test_move_and_delete_content(admin, tool, project_uuid, space, lightdash_admin):
    params = {"projectUuids": project_uuid, "contentTypes": "chart", "pageSize": 1}
    charts = list_content(lightdash_admin, params)
    chart = charts[0]["uuid"]
    home = charts[0]["space"]["uuid"]

    def chart_space() -> str:
        found = list_content(lightdash_admin, {"projectUuids": project_uuid, "uuids": chart})
        return found[0]["space"]["uuid"]

    move = {"project_uuid": project_uuid, "content_type": "chart", "uuid": chart}
    ok(await tool(admin, "move_content", {**move, "target_space_uuid": space}))
    assert chart_space() == space

    ok(await tool(admin, "move_content", {**move, "target_space_uuid": home}))
    assert chart_space() == home

    delete = {"project_uuid": project_uuid, "content_type": "space", "uuid": space}
    preview = ok(await tool(admin, "delete_content", delete))
    assert preview["wouldDelete"]["item"]["name"] == "mcp test space"

    before_delete = lightdash_admin.get(f"/api/v1/projects/{project_uuid}/spaces/{space}")
    assert before_delete.status_code == 200

    ok(await tool(admin, "delete_content", {**delete, "dry_run": False}))
    spaces = ok(await tool(admin, "list_spaces", {"project_uuid": project_uuid}))
    assert space not in [listed["spaceUuid"] for listed in spaces]


async def test_data_tools(admin, viewer, tool, project_uuid):
    args = {"project_uuid": project_uuid}

    explores = ok(await tool(viewer, "list_explores", args))
    assert "orders" in [explore["name"] for explore in explores]

    explore = ok(await tool(viewer, "get_explore", {**args, "explore": "orders"}))
    dimension_ids = [dimension["fieldId"] for dimension in explore["dimensions"]]
    metric_ids = [metric["fieldId"] for metric in explore["metrics"]]
    assert "orders_status" in dimension_ids
    assert "customers_first_name" in dimension_ids  # joined table
    assert "orders_total_order_amount" in metric_ids

    query = {
        **args,
        "explore": "orders",
        "dimensions": ["orders_status"],
        "metrics": ["orders_unique_order_count"],
        "filters": [
            {"field_id": "orders_status", "operator": "notEquals", "values": ["returned"]},
            {"field_id": "orders_unique_order_count", "operator": "greaterThan", "values": [0]},
        ],
        "sorts": [{"field_id": "orders_unique_order_count", "descending": True}],
        "limit": 3,
    }
    result = ok(await tool(admin, "run_query", query))
    # bigint counts come as strings
    counts = [int(row["orders_unique_order_count"]) for row in result["rows"]]
    statuses = [row["orders_status"] for row in result["rows"]]
    assert set(result["columns"]) == {"orders_status", "orders_unique_order_count"}
    assert 0 < len(counts) <= 3
    assert counts == sorted(counts, reverse=True)
    assert all(count > 0 for count in counts)
    assert "returned" not in statuses

    viewer_message = denied(await tool(viewer, "run_query", query))
    assert "Permission denied" in viewer_message  # viewers only see saved charts

    unknown_query = {**args, "explore": "orders", "metrics": ["orders_nope"]}
    unknown = denied(await tool(admin, "run_query", unknown_query))
    assert "Unknown fields in orders: orders_nope" in unknown

    status_query = {**args, "explore": "orders", "dimensions": ["orders_status"]}
    one_row = ok(await tool(admin, "run_query", {**status_query, "limit": 1}))
    assert one_row["truncated"] is True

    all_rows = ok(await tool(admin, "run_query", {**status_query, "limit": 2500}))
    assert all_rows["truncated"] is False


@pytest.fixture
def filtered_dashboard(lightdash_admin: httpx.Client, project_uuid: str):
    """A dashboard showing revenue per payment method, filtered to credit cards."""
    params = {
        "projectUuids": project_uuid,
        "contentTypes": "chart",
        "search": "per payment method",
    }
    charts = list_content(lightdash_admin, params)
    chart = next(candidate for candidate in charts if candidate["name"] == PAYMENT_METHOD_CHART)
    tile = {
        "type": "saved_chart",
        "x": 0,
        "y": 0,
        "h": 9,
        "w": 12,
        "properties": {"savedChartUuid": chart["uuid"]},
    }
    credit_card_filter = {
        "id": "6b1c4b4e-1111-4b4e-8b4e-111111111111",
        "target": {"fieldId": "payments_payment_method", "tableName": "payments"},
        "operator": "equals",
        "values": ["credit_card"],
    }
    dashboard = {
        "name": "mcp test dashboard",
        "spaceUuid": chart["space"]["uuid"],
        "tabs": [],
        "tiles": [tile],
        "filters": {
            "dimensions": [credit_card_filter],
            "metrics": [],
            "tableCalculations": [],
        },
    }
    created = lightdash_admin.post(f"/api/v1/projects/{project_uuid}/dashboards", json=dashboard)
    uuid = created.json()["results"]["uuid"]

    yield uuid, chart["uuid"]

    lightdash_admin.delete(f"/api/v1/dashboards/{uuid}")


async def test_saved_content_tools(viewer, tool, project_uuid, filtered_dashboard):
    args = {"project_uuid": project_uuid}
    dashboard_uuid, chart_uuid = filtered_dashboard

    chart_search = {**args, "search": "revenue", "content_type": "chart"}
    charts = ok(await tool(viewer, "search_content", chart_search))
    everything = ok(await tool(viewer, "search_content", args))
    assert charts
    assert all(chart["contentType"] == "chart" for chart in charts)
    assert len(charts) < len(everything)

    dashboard_search = {**args, "content_type": "dashboard"}
    dashboards = ok(await tool(viewer, "search_content", dashboard_search))
    assert dashboard_uuid in [listed["uuid"] for listed in dashboards]

    dashboard = ok(await tool(viewer, "get_dashboard", {"dashboard_uuid": dashboard_uuid}))
    expected_filter = {
        "fieldId": "payments_payment_method",
        "operator": "equals",
        "values": ["credit_card"],
        "disabled": False,
    }
    assert dashboard["projectUuid"] == project_uuid
    assert dashboard["filters"] == [expected_filter]
    assert [tile["chartUuid"] for tile in dashboard["tiles"]] == [chart_uuid]

    chart_args = {**args, "chart_uuid": chart_uuid}
    alone = ok(await tool(viewer, "run_chart", chart_args))  # viewers can run saved charts
    on_dashboard_args = {**chart_args, "dashboard_uuid": dashboard_uuid}
    on_dashboard = ok(await tool(viewer, "run_chart", on_dashboard_args))
    payment_methods = [row["payments_payment_method"] for row in on_dashboard["rows"]]
    assert len(alone["rows"]) > 1
    assert alone["truncated"] is False
    assert payment_methods == ["credit_card"]

    unknown_chart = {**args, "chart_uuid": UNKNOWN_UUID, "dashboard_uuid": dashboard_uuid}
    unknown_message = denied(await tool(viewer, "run_chart", unknown_chart))
    assert "not on the dashboard" in unknown_message


def made_by_the_test(lightdash_admin: httpx.Client, project_uuid: str, suffix: str) -> list:
    """What a test made, found by name: a save can succeed even when its tool call then fails."""
    params = {"projectUuids": project_uuid, "search": "mcp test", "pageSize": 100}
    content = list_content(lightdash_admin, params)

    return [item for item in content if item["name"].endswith(suffix)]


def delete_what_the_test_made(lightdash_admin: httpx.Client, project_uuid: str, suffix: str):
    leftovers = made_by_the_test(lightdash_admin, project_uuid, suffix)
    dashboards_first = sorted(leftovers, key=lambda item: item["contentType"] != "dashboard")

    for item in dashboards_first:
        path = "dashboards" if item["contentType"] == "dashboard" else "saved"
        lightdash_admin.delete(f"/api/v1/{path}/{item['uuid']}")


async def copy_of_a_chart(as_admin, suffix: str) -> dict[str, Any]:
    """A demo chart's code, copied in the same space: not on the source's dashboard, nor with
    its access."""
    search = {"search": "per payment method", "content_type": "chart"}
    found = ok(await as_admin("search_content", **search))
    source = next((chart for chart in found if chart["name"] == PAYMENT_METHOD_CHART), None)
    assert source, found

    downloaded = ok(await as_admin("get_chart_code", slug=source["slug"]))
    left_out = ("dashboardSlug", "access", "updatedAt", "downloadedAt")
    copied = {key: value for key, value in downloaded.items() if key not in left_out}

    return copied | {"name": f"mcp test chart {suffix}", "slug": f"mcp-test-chart-{suffix}"}


async def check_the_dashboard_waits_for_its_chart(as_admin, dashboard: dict, chart_slug: str):
    previewed = ok(await as_admin("save_dashboard", dashboard=dashboard))
    refused = denied(await as_admin("save_dashboard", dashboard=dashboard, dry_run=False))

    assert previewed["chartsNotSavedYet"] == [chart_slug]
    assert "No chart with slug" in refused


async def save_chart_as_code(as_admin, chart: dict[str, Any]) -> str:
    """Previews, then saves the chart. Returns its UUID."""
    previewed = ok(await as_admin("save_chart", chart=chart))
    not_saved = denied(await as_admin("get_chart_code", slug=chart["slug"]))

    assert previewed["wouldCreate"]["slug"] == chart["slug"]
    assert "No chart with slug" in not_saved

    created = ok(await as_admin("save_chart", chart=chart, dry_run=False))
    downloaded = ok(await as_admin("get_chart_code", slug=chart["slug"]))

    assert created["action"] == "create"
    assert created["url"].endswith(f"/saved/{created['uuid']}")
    assert created.get("validationErrors") == [], created
    assert downloaded["name"] == chart["name"]

    return created["uuid"]


async def save_dashboard_as_code(as_admin, dashboard: dict, chart_slug: str) -> str:
    """Saves the dashboard. Returns its UUID."""
    created = ok(await as_admin("save_dashboard", dashboard=dashboard, dry_run=False))
    code = ok(await as_admin("get_dashboard_code", slug=dashboard["slug"]))

    chart_slugs = [tile["properties"]["chartSlug"] for tile in code["tiles"]]
    assert created["action"] == "create"
    assert created["url"].endswith(f"/dashboards/{created['uuid']}")
    assert chart_slugs == [chart_slug]

    return created["uuid"]


async def delete_with_the_tool(as_admin, content_type: str, uuid: str):
    delete = {"content_type": content_type, "uuid": uuid}

    preview = ok(await as_admin("delete_content", **delete))
    assert preview["wouldDelete"]

    ok(await as_admin("delete_content", **delete, dry_run=False))


async def test_charts_and_dashboards_round_trip_as_code(admin, tool, project_uuid, lightdash_admin):
    async def as_admin(tool_name: str, **arguments: Any):
        return await tool(admin, tool_name, {"project_uuid": project_uuid, **arguments})

    suffix = secrets.token_hex(3)
    chart = await copy_of_a_chart(as_admin, suffix)
    tile = {
        "type": "saved_chart",
        "x": 0,
        "y": 0,
        "w": 12,
        "h": 9,
        "properties": {"chartSlug": chart["slug"]},
    }
    dashboard = {
        "name": f"mcp test dashboard {suffix}",
        "slug": f"mcp-test-dashboard-{suffix}",
        "spaceSlug": chart["spaceSlug"],
        "tiles": [tile],
    }

    try:
        await check_the_dashboard_waits_for_its_chart(as_admin, dashboard, chart["slug"])
        chart_uuid = await save_chart_as_code(as_admin, chart)
        dashboard_uuid = await save_dashboard_as_code(as_admin, dashboard, chart["slug"])
        await delete_with_the_tool(as_admin, "dashboard", dashboard_uuid)
        await delete_with_the_tool(as_admin, "chart", chart_uuid)

        deleted = denied(await as_admin("get_chart_code", slug=chart["slug"]))
        leftovers = made_by_the_test(lightdash_admin, project_uuid, suffix)
        assert "No chart with slug" in deleted
        assert leftovers == []
    finally:
        delete_what_the_test_made(lightdash_admin, project_uuid, suffix)


async def test_tool_calls_are_logged(admin, tool, project_uuid, lightdash_admin, caplog):
    user = lightdash_admin.get("/api/v1/user").json()["results"]
    admin_uuid = user["userUuid"]
    caplog.set_level(logging.INFO, logger="lightdash_mcp.audit")

    ok(await tool(admin, "list_spaces", {"project_uuid": project_uuid}))
    denied(await tool(admin, "list_spaces", {"project_uuid": UNKNOWN_UUID}))

    records = [record for record in caplog.records if record.name == "lightdash_mcp.audit"]
    lines = [json.loads(record.getMessage()) for record in records]
    calls = [line for line in lines if line["event"] == "tool_call"]
    tools = [call["tool"] for call in calls]
    users = [call["user"] for call in calls]
    assert tools == ["list_spaces", "list_spaces"]
    assert users == [admin_uuid, admin_uuid]
    assert calls[0]["arguments"]["project_uuid"] == project_uuid
    assert calls[0]["error"] is False
    assert calls[1]["arguments"]["project_uuid"] == UNKNOWN_UUID
    assert calls[1]["error"] is True
