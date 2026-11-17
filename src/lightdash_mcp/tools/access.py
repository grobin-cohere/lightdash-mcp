"""Who can see what: users, groups, roles, project access and space access."""

from typing import Any, Literal, get_args

from mcp.server.mcpserver import MCPServer

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient, LightdashError
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, Uuid, full_name, lightdash, pick
from lightdash_mcp.tools.shared import PAGE_SIZE, every_page, space_slug

ProjectRole = Literal["viewer", "interactive_viewer", "editor", "developer", "admin"]
RANKS: tuple[str, ...] = get_args(ProjectRole)  # lowest first


async def _users(client: LightdashClient, search: str | None = None) -> list[dict[str, Any]]:
    # includeGroups is also a row limit in Lightdash (OrganizationMemberProfileModel), so page through the members.
    return await every_page(
        client, "/api/v1/org/users", searchQuery=search, includeGroups=PAGE_SIZE
    )


async def project_access(client: LightdashClient, project_uuid: str) -> dict[str, Any]:
    """Each user with access to the project and their effective role: the highest of their organization role,
    their direct grant and the roles of their groups. Custom roles can't be ranked, so they are listed apart."""
    users = await _users(client)
    direct = {
        m["userUuid"]: m.get("roleUuid") or m["role"]
        for m in await client.get(f"/api/v1/projects/{project_uuid}/access")
    }
    group_roles = {
        g["groupUuid"]: g["role"]
        for g in await client.get(f"/api/v1/projects/{project_uuid}/groupAccesses")
    }
    group_names = (
        {g["uuid"]: g["name"] for g in await every_page(client, "/api/v1/org/groups")}
        if group_roles
        else {}
    )
    listed = []
    for u in users:
        groups = [g for g in u.get("groups") or [] if g["uuid"] in group_roles]
        # An organization member without a project role has no access to the project.
        organization_role = u.get("role") if u.get("role") != "member" else None
        roles = {
            r
            for r in (
                organization_role,
                direct.get(u["userUuid"]),
                *(group_roles[g["uuid"]] for g in groups),
            )
            if r
        }
        if not roles:
            continue
        custom = sorted(roles.difference(RANKS))
        listed.append(
            {
                "userUuid": u["userUuid"],
                "name": full_name(u),
                "email": u.get("email"),
                "projectRole": max(roles.intersection(RANKS), key=RANKS.index, default=None),
                "organizationRole": u.get("role"),
                "directRole": direct.get(u["userUuid"]),
                "groups": [g["name"] for g in groups],
                **({"customRoleUuids": custom} if custom else {}),
            }
        )
    return {
        "users": listed,
        "groups": [
            {"groupUuid": uuid, "name": group_names.get(uuid), "projectRole": role}
            for uuid, role in group_roles.items()
        ],
    }


async def roles(client: LightdashClient, organization_uuid: str) -> list[dict[str, Any]]:
    path = f"/api/v2/orgs/{organization_uuid}/roles"
    try:
        found = await client.get(path, load="scopes")
    except LightdashError as error:
        # Lightdash loads scopes only for organization admins (RolesService.getRolesByOrganizationUuid).
        if error.status != 403:
            raise
        found = await client.get(path)
    return [
        pick(r, "roleUuid", "name", "description", "ownerType", "level", "scopes") for r in found
    ]


async def _current(
    client: LightdashClient,
    project_uuid: str,
    user_uuid: str | None = None,
    email: str | None = None,
) -> dict[str, Any] | None:
    """A user's current access to the project, as list_project_access shows it, or None."""
    users = (await project_access(client, project_uuid))["users"]
    return next(
        (
            pick(u, "projectRole", "organizationRole", "directRole", "groups")
            for u in users
            if u["userUuid"] == user_uuid
            or (email is not None and (u["email"] or "").lower() == email.lower())
        ),
        None,
    )


async def grant(
    client: LightdashClient, project_uuid: str, email: str, role: str, dry_run: bool
) -> dict[str, Any]:
    access = {"email": email, "role": role}
    if dry_run:
        return {
            "wouldGrant": access,
            "currentAccess": await _current(client, project_uuid, email=email),
            "next": "Nothing is changed yet. Call grant_project_access again with dry_run=false to grant it.",
        }
    await client.request(
        "POST", f"/api/v1/projects/{project_uuid}/access", json=access | {"sendEmail": False}
    )
    return {"granted": access}


async def update_grant(
    client: LightdashClient, project_uuid: str, user_uuid: str, role: str, dry_run: bool
) -> dict[str, Any]:
    members = await client.get(f"/api/v1/projects/{project_uuid}/access")
    member = next((m for m in members if m["userUuid"] == user_uuid), None)
    if member is None:
        return {
            "changed": None,
            "message": "This user has no direct grant on the project: use grant_project_access.",
        }
    change = {
        "userUuid": user_uuid,
        "email": member.get("email"),
        "from": member.get("role"),
        "to": role,
    }
    if dry_run:
        return {
            "wouldChange": change,
            "currentAccess": await _current(client, project_uuid, user_uuid=user_uuid),
            "next": "Nothing is changed yet. Call update_project_access again with dry_run=false to change it.",
        }
    await client.request(
        "PATCH", f"/api/v1/projects/{project_uuid}/access/{user_uuid}", json={"role": role}
    )
    return {"changed": change}


async def add_member(
    client: LightdashClient, group_uuid: str, user_uuid: str, dry_run: bool
) -> dict[str, Any]:
    group = await client.get(f"/api/v1/groups/{group_uuid}")
    if any(
        m["userUuid"] == user_uuid for m in await client.get(f"/api/v1/groups/{group_uuid}/members")
    ):
        return {"added": None, "message": "This user is already a member of the group."}
    membership = {"userUuid": user_uuid, "group": group["name"]}
    if dry_run:
        gives = []
        for project in await client.get("/api/v1/org/projects"):
            accesses = await client.get(f"/api/v1/projects/{project['projectUuid']}/groupAccesses")
            gives += [
                {
                    "projectUuid": project["projectUuid"],
                    "project": project["name"],
                    "role": a["role"],
                }
                for a in accesses
                if a["groupUuid"] == group_uuid
            ]
        return {
            "wouldAdd": membership,
            "groupGives": gives,
            "next": "Nothing is changed yet. Call add_group_member again with dry_run=false to add them.",
        }
    await client.request("PUT", f"/api/v1/groups/{group_uuid}/members/{user_uuid}")
    return {"added": membership}


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def list_projects() -> list[dict[str, Any]]:
        """List the Lightdash projects you can see. Most tools need a project UUID from here."""
        async with lightdash(provider) as client:
            return [
                pick(p, "projectUuid", "name", "type")
                for p in await client.get("/api/v1/org/projects")
            ]

    @server.tool(annotations=READ)
    async def list_users(search: str | None = None) -> list[dict[str, Any]]:
        """List organization members with their organization role, status and groups."""
        async with lightdash(provider) as client:
            users = await _users(client, search)
        return [
            {
                "userUuid": u["userUuid"],
                "name": full_name(u),
                "email": u.get("email"),
                "organizationRole": u.get("role"),
                "isActive": u.get("isActive"),
                "isPending": u.get("isPending"),
                "groups": [g["name"] for g in u.get("groups") or []],
            }
            for u in users
        ]

    @server.tool(annotations=READ)
    async def list_groups(search: str | None = None) -> list[dict[str, Any]]:
        """List groups and their members."""
        async with lightdash(provider) as client:
            groups = await every_page(
                client, "/api/v1/org/groups", searchQuery=search, includeMembers=1000
            )
        return [
            {
                "groupUuid": g["uuid"],
                "name": g["name"],
                "members": [
                    {"userUuid": m["userUuid"], "name": full_name(m), "email": m.get("email")}
                    for m in g.get("members") or []
                ],
            }
            for g in groups
        ]

    @server.tool(annotations=READ)
    async def list_roles() -> list[dict[str, Any]]:
        """List the organization's roles, system and custom, with the permission scopes each grants.
        Lightdash shows the scopes to organization admins only: for others, scopes is null."""
        async with lightdash(provider) as client:
            org = await client.get("/api/v1/org")
            return await roles(client, org["organizationUuid"])

    @server.tool(annotations=READ)
    async def list_project_access(project_uuid: Uuid) -> dict[str, Any]:
        """Show who can access a project: each user's effective role, the highest of their organization role,
        their direct grant and their groups' roles, with the direct grant and the groups, and the groups with access."""
        async with lightdash(provider) as client:
            return await project_access(client, project_uuid)

    @server.tool(annotations=READ)
    async def list_spaces(project_uuid: Uuid) -> list[dict[str, Any]]:
        """List a project's spaces, nested ones included, with their content counts. spaceSlug is the space as
        chart and dashboard code name it, such as parent/child."""
        async with lightdash(provider) as client:
            spaces = await client.get(f"/api/v1/projects/{project_uuid}/spaces")
        return [
            {
                "spaceUuid": s["uuid"],
                "spaceSlug": space_slug(s),
                "name": s["name"],
                "parentSpaceUuid": s.get("parentSpaceUuid"),
                "inheritsParentPermissions": s.get("inheritParentPermissions"),
                "charts": int(s.get("chartCount") or 0),
                "dashboards": int(s.get("dashboardCount") or 0),
                "childSpaces": int(s.get("childSpaceCount") or 0),
            }
            for s in spaces
        ]

    @server.tool(annotations=READ)
    async def list_space_access(project_uuid: Uuid, space_uuid: Uuid) -> dict[str, Any]:
        """Show who can access a space and why: direct access, or inherited from the organization,
        the project or a parent space."""
        async with lightdash(provider) as client:
            space = await client.get(f"/api/v1/projects/{project_uuid}/spaces/{space_uuid}")
        return {
            "space": space["name"],
            "inheritsParentPermissions": space.get("inheritParentPermissions"),
            "users": [
                {
                    "userUuid": a["userUuid"],
                    "name": full_name(a),
                    "email": a.get("email"),
                    "spaceRole": a.get("role"),
                    "hasDirectAccess": a.get("hasDirectAccess"),
                    "inheritedFrom": a.get("inheritedFrom"),
                    "projectRole": a.get("projectRole"),
                }
                for a in space.get("access") or []
            ],
            "groups": [
                pick(g, "groupUuid", "groupName", "spaceRole")
                for g in space.get("groupsAccess") or []
            ],
        }

    @server.tool(annotations=DESTRUCTIVE)
    async def grant_project_access(
        project_uuid: Uuid, email: str, role: ProjectRole, dry_run: bool = True
    ) -> dict[str, Any]:
        """Give an organization member direct access to a project, without an email. Fails if they already have
        a direct grant, as Lightdash refuses a second one: use update_project_access to change it.
        dry_run, on by default, shows their current access and the grant. Pass dry_run=false to grant it."""
        async with lightdash(provider) as client:
            return await grant(client, project_uuid, email, role, dry_run)

    @server.tool(annotations=DESTRUCTIVE)
    async def update_project_access(
        project_uuid: Uuid, user_uuid: Uuid, role: ProjectRole, dry_run: bool = True
    ) -> dict[str, Any]:
        """Change a user's direct project role.
        dry_run, on by default, shows their current access and the change. Pass dry_run=false to change it."""
        async with lightdash(provider) as client:
            return await update_grant(client, project_uuid, user_uuid, role, dry_run)

    @server.tool(annotations=DESTRUCTIVE)
    async def revoke_project_access(
        project_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Remove a user's direct project grant. Access through their organization role or a group remains.
        dry_run, on by default, shows the grant that would be removed. Pass dry_run=false to remove it."""
        async with lightdash(provider) as client:
            members = await client.get(f"/api/v1/projects/{project_uuid}/access")
            member = next((m for m in members if m["userUuid"] == user_uuid), None)
            if member is None:
                return {"removed": None, "message": "This user has no direct grant on the project."}
            grant = {
                "userUuid": user_uuid,
                "email": member.get("email"),
                "role": member.get("role"),
            }
            if dry_run:
                return {"wouldRemove": grant}
            await client.request("DELETE", f"/api/v1/projects/{project_uuid}/access/{user_uuid}")
        return {"removed": grant}

    @server.tool(annotations=DESTRUCTIVE)
    async def add_group_member(
        group_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Add a user to a group, and with it the project access the group gives.
        dry_run, on by default, shows the group and the projects it gives access to. Pass dry_run=false to add them."""
        async with lightdash(provider) as client:
            return await add_member(client, group_uuid, user_uuid, dry_run)

    @server.tool(annotations=DESTRUCTIVE)
    async def remove_group_member(
        group_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Remove a user from a group, and with it any access the group gave them.
        dry_run, on by default, checks the membership. Pass dry_run=false to remove it."""
        async with lightdash(provider) as client:
            members = await client.get(f"/api/v1/groups/{group_uuid}/members")
            member = next((m for m in members if m["userUuid"] == user_uuid), None)
            if member is None:
                return {"removed": None, "message": "This user is not a member of the group."}
            membership = {"userUuid": user_uuid, "email": member.get("email")}
            if dry_run:
                return {"wouldRemove": membership}
            await client.request("DELETE", f"/api/v1/groups/{group_uuid}/members/{user_uuid}")
        return {"removed": membership}
