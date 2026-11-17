"""Scheduled deliveries: list, pause, edit and delete."""

from typing import Any

from mcp.server.mcpserver import MCPServer

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, WRITE, Uuid, lightdash
from lightdash_mcp.tools.shared import every_page


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def list_schedulers(
        project_uuid: Uuid, search: str | None = None
    ) -> list[dict[str, Any]]:
        """List a project's scheduled deliveries with their schedule, owner, recipients and
        latest run."""
        async with lightdash(provider) as client:
            schedulers = await every_page(
                client,
                f"/api/v1/schedulers/{project_uuid}/list",
                searchQuery=search,
                includeLatestRun="true",
            )

        return [_summarize(scheduler) for scheduler in schedulers]

    @server.tool(annotations=WRITE)
    async def set_scheduler_enabled(scheduler_uuid: Uuid, enabled: bool) -> str:
        """Pause (enabled=false) or resume (enabled=true) a scheduled delivery."""
        async with lightdash(provider) as client:
            await client.request(
                "PATCH",
                f"/api/v1/schedulers/{scheduler_uuid}/enabled",
                json={"enabled": enabled},
            )

        return "Resumed the delivery." if enabled else "Paused the delivery."

    @server.tool(annotations=WRITE)
    async def update_scheduler(
        scheduler_uuid: Uuid,
        name: str | None = None,
        cron: str | None = None,
        timezone: str | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Change a scheduled delivery's name, schedule (cron expression), timezone or message.
        Fields left out stay as they are."""
        fields = {
            "name": name,
            "cron": cron,
            "timezone": timezone,
            "message": message,
        }
        changes = {field: value for field, value in fields.items() if value is not None}

        async with lightdash(provider) as client:
            updated = await update(client, scheduler_uuid, changes)

        return _summarize(updated)

    @server.tool(annotations=DESTRUCTIVE)
    async def delete_scheduler(scheduler_uuid: Uuid, dry_run: bool = True) -> dict[str, Any]:
        """Delete a scheduled delivery. dry_run, on by default, shows it. Pass
        dry_run=false to delete it."""
        async with lightdash(provider) as client:
            found = await client.get(f"/api/v1/schedulers/{scheduler_uuid}")
            scheduler = _summarize(found)

            if dry_run:
                return {"wouldDelete": scheduler}

            await client.request("DELETE", f"/api/v1/schedulers/{scheduler_uuid}")

        return {"deleted": scheduler}


def _summarize(scheduler: dict[str, Any]) -> dict[str, Any]:
    targets = scheduler.get("targets") or []
    return {
        "schedulerUuid": scheduler["schedulerUuid"],
        "name": scheduler["name"],
        "enabled": scheduler.get("enabled"),
        "cron": scheduler.get("cron"),
        "timezone": scheduler.get("timezone"),
        "format": scheduler.get("format"),
        "content": _find_content_name(scheduler),
        "owner": scheduler.get("createdByName"),
        "recipients": [_find_recipient(target) for target in targets],
        "latestRun": scheduler.get("latestRun"),
    }


def _find_content_name(scheduler: dict[str, Any]) -> str | None:
    return (
        scheduler.get("savedChartName")
        or scheduler.get("dashboardName")
        or scheduler.get("savedSqlName")
        or scheduler.get("appName")
    )


def _find_recipient(target: dict[str, Any]) -> str | None:
    return target.get("recipient") or target.get("channel") or target.get("url")


async def update(
    client: LightdashClient, scheduler_uuid: str, changes: dict[str, Any]
) -> dict[str, Any]:
    # PATCH writes every column, so a field left out becomes null (SchedulerModel.updateScheduler):
    # send the whole scheduler back with the changes. Lightdash ignores the read-only fields.
    path = f"/api/v1/schedulers/{scheduler_uuid}"
    current = await client.get(path)

    return await client.request("PATCH", path, json=current | changes)
