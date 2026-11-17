"""Who can see what: users, groups, roles, project access and space access."""

from typing import Any, Literal, get_args

from mcp.server.mcpserver import MCPServer

from lightdash_mcp.auth.provider import LightdashOAuthProvider
from lightdash_mcp.lightdash import LightdashClient, LightdashError
from lightdash_mcp.tools.common import DESTRUCTIVE, READ, Uuid, full_name, lightdash, pick
from lightdash_mcp.tools.shared import PAGE_SIZE, every_page, space_slug

ProjectRole = Literal[
    "viewer",
    "interactive_viewer",
    "editor",
    "developer",
    "admin",
]
RANKS: tuple[str, ...] = get_args(ProjectRole)  # lowest first

MEMBERS_PER_GROUP = 1000
ROLE_FIELDS = (
    "roleUuid",
    "name",
    "description",
    "ownerType",
    "level",
    "scopes",
)
CURRENT_ACCESS_FIELDS = (
    "projectRole",
    "organizationRole",
    "directRole",
    "groups",
)


def register(server: MCPServer, provider: LightdashOAuthProvider) -> None:
    @server.tool(annotations=READ)
    async def list_projects() -> list[dict[str, Any]]:
        """List the Lightdash projects you can see. Most tools need a project UUID from here."""
        async with lightdash(provider) as client:
            projects = await client.get("/api/v1/org/projects")

        return [pick(project, "projectUuid", "name", "type") for project in projects]

    @server.tool(annotations=READ)
    async def list_users(search: str | None = None) -> list[dict[str, Any]]:
        """List organization members with their organization role, status and groups."""
        async with lightdash(provider) as client:
            users = await _fetch_users(client, search)

        return [_describe_user(user) for user in users]

    @server.tool(annotations=READ)
    async def list_groups(search: str | None = None) -> list[dict[str, Any]]:
        """List groups and their members."""
        async with lightdash(provider) as client:
            groups = await every_page(
                client,
                "/api/v1/org/groups",
                searchQuery=search,
                includeMembers=MEMBERS_PER_GROUP,
            )

        return [_describe_group(group) for group in groups]

    @server.tool(annotations=READ)
    async def list_roles() -> list[dict[str, Any]]:
        """List the organization's roles, system and custom, with the permission scopes each grants.
        Lightdash shows the scopes to organization admins only: for others, scopes is null."""
        async with lightdash(provider) as client:
            organization = await client.get("/api/v1/org")
            return await roles(client, organization["organizationUuid"])

    @server.tool(annotations=READ)
    async def list_project_access(project_uuid: Uuid) -> dict[str, Any]:
        """Show who can access a project: each user's effective role, the highest of their
        organization role, their direct grant and their groups' roles, with the direct grant and
        the groups, and the groups with access."""
        async with lightdash(provider) as client:
            return await project_access(client, project_uuid)

    @server.tool(annotations=READ)
    async def list_spaces(project_uuid: Uuid) -> list[dict[str, Any]]:
        """List a project's spaces, nested ones included, with their content counts. spaceSlug is
        the space as chart and dashboard code name it, such as parent/child."""
        async with lightdash(provider) as client:
            spaces = await client.get(f"/api/v1/projects/{project_uuid}/spaces")

        return [_describe_space(space) for space in spaces]

    @server.tool(annotations=READ)
    async def list_space_access(project_uuid: Uuid, space_uuid: Uuid) -> dict[str, Any]:
        """Show who can access a space and why: direct access, or inherited from the organization,
        the project or a parent space."""
        async with lightdash(provider) as client:
            space = await client.get(f"/api/v1/projects/{project_uuid}/spaces/{space_uuid}")

        users = space.get("access") or []
        groups = space.get("groupsAccess") or []

        return {
            "space": space["name"],
            "inheritsParentPermissions": space.get("inheritParentPermissions"),
            "users": [_describe_space_user(user) for user in users],
            "groups": [pick(group, "groupUuid", "groupName", "spaceRole") for group in groups],
        }

    @server.tool(annotations=DESTRUCTIVE)
    async def grant_project_access(
        project_uuid: Uuid,
        email: str,
        role: ProjectRole,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Give an organization member direct access to a project, without an email. Fails if
        they already have a direct grant, as Lightdash refuses a second one: use
        update_project_access to change it.
        dry_run, on by default, shows their current access and the grant. Pass dry_run=false to
        grant it."""
        async with lightdash(provider) as client:
            return await grant(
                client,
                project_uuid,
                email,
                role,
                dry_run,
            )

    @server.tool(annotations=DESTRUCTIVE)
    async def update_project_access(
        project_uuid: Uuid,
        user_uuid: Uuid,
        role: ProjectRole,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Change a user's direct project role.
        dry_run, on by default, shows their current access and the change. Pass dry_run=false to
        change it."""
        async with lightdash(provider) as client:
            return await update_grant(
                client,
                project_uuid,
                user_uuid,
                role,
                dry_run,
            )

    @server.tool(annotations=DESTRUCTIVE)
    async def revoke_project_access(
        project_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Remove a user's direct project grant. Access through their organization role or a
        group remains.
        dry_run, on by default, shows the grant that would be removed. Pass dry_run=false to
        remove it."""
        async with lightdash(provider) as client:
            members = await client.get(f"/api/v1/projects/{project_uuid}/access")
            member = _find_member(members, user_uuid)

            if member is None:
                return {
                    "removed": None,
                    "message": "This user has no direct grant on the project.",
                }

            direct_grant = {
                "userUuid": user_uuid,
                "email": member.get("email"),
                "role": member.get("role"),
            }

            if dry_run:
                return {"wouldRemove": direct_grant}

            await client.request("DELETE", f"/api/v1/projects/{project_uuid}/access/{user_uuid}")

        return {"removed": direct_grant}

    @server.tool(annotations=DESTRUCTIVE)
    async def add_group_member(
        group_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Add a user to a group, and with it the project access the group gives.
        dry_run, on by default, shows the group and the projects it gives access to. Pass
        dry_run=false to add them."""
        async with lightdash(provider) as client:
            return await add_member(
                client,
                group_uuid,
                user_uuid,
                dry_run,
            )

    @server.tool(annotations=DESTRUCTIVE)
    async def remove_group_member(
        group_uuid: Uuid, user_uuid: Uuid, dry_run: bool = True
    ) -> dict[str, Any]:
        """Remove a user from a group, and with it any access the group gave them.
        dry_run, on by default, checks the membership. Pass dry_run=false to remove it."""
        async with lightdash(provider) as client:
            members = await client.get(f"/api/v1/groups/{group_uuid}/members")
            member = _find_member(members, user_uuid)

            if member is None:
                return {"removed": None, "message": "This user is not a member of the group."}

            membership = {"userUuid": user_uuid, "email": member.get("email")}

            if dry_run:
                return {"wouldRemove": membership}

            await client.request("DELETE", f"/api/v1/groups/{group_uuid}/members/{user_uuid}")

        return {"removed": membership}


async def _fetch_users(client: LightdashClient, search: str | None = None) -> list[dict[str, Any]]:
    # includeGroups is also a row limit in Lightdash (OrganizationMemberProfileModel), so page
    # through the members.
    return await every_page(
        client,
        "/api/v1/org/users",
        searchQuery=search,
        includeGroups=PAGE_SIZE,
    )


def _describe_user(user: dict[str, Any]) -> dict[str, Any]:
    groups = user.get("groups") or []
    return {
        "userUuid": user["userUuid"],
        "name": full_name(user),
        "email": user.get("email"),
        "organizationRole": user.get("role"),
        "isActive": user.get("isActive"),
        "isPending": user.get("isPending"),
        "groups": [group["name"] for group in groups],
    }


def _describe_group(group: dict[str, Any]) -> dict[str, Any]:
    members = group.get("members") or []
    return {
        "groupUuid": group["uuid"],
        "name": group["name"],
        "members": [_describe_group_member(member) for member in members],
    }


def _describe_group_member(member: dict[str, Any]) -> dict[str, Any]:
    return {
        "userUuid": member["userUuid"],
        "name": full_name(member),
        "email": member.get("email"),
    }


async def roles(client: LightdashClient, organization_uuid: str) -> list[dict[str, Any]]:
    path = f"/api/v2/orgs/{organization_uuid}/roles"

    try:
        found = await client.get(path, load="scopes")
    except LightdashError as error:
        # Lightdash loads scopes only for organization admins
        # (RolesService.getRolesByOrganizationUuid).
        if error.status != 403:
            raise

        found = await client.get(path)

    return [pick(role, *ROLE_FIELDS) for role in found]


async def project_access(client: LightdashClient, project_uuid: str) -> dict[str, Any]:
    """Each user with access to the project and their effective role: the highest of their
    organization role, their direct grant and the roles of their groups. Custom roles can't be
    ranked, so they are listed apart."""
    users = await _fetch_users(client)
    members = await client.get(f"/api/v1/projects/{project_uuid}/access")
    direct_roles = {member["userUuid"]: _direct_role(member) for member in members}
    group_accesses = await client.get(f"/api/v1/projects/{project_uuid}/groupAccesses")
    group_roles = {access["groupUuid"]: access["role"] for access in group_accesses}
    group_names: dict[str, str] = {}

    if group_roles:
        groups = await every_page(client, "/api/v1/org/groups")
        group_names = {group["uuid"]: group["name"] for group in groups}

    listed = []

    for user in users:
        described = _describe_project_user(user, direct_roles, group_roles)

        if described is not None:
            listed.append(described)

    listed_groups = [
        {"groupUuid": group_uuid, "name": group_names.get(group_uuid), "projectRole": role}
        for group_uuid, role in group_roles.items()
    ]

    return {"users": listed, "groups": listed_groups}


def _direct_role(member: dict[str, Any]) -> str:
    return member.get("roleUuid") or member["role"]


def _describe_project_user(
    user: dict[str, Any],
    direct_roles: dict[str, str],
    group_roles: dict[str, str],
) -> dict[str, Any] | None:
    """A user's access to the project, as project_access lists it, or None without any."""
    user_groups = user.get("groups") or []
    groups = [group for group in user_groups if group["uuid"] in group_roles]
    roles_from_groups = [group_roles[group["uuid"]] for group in groups]
    organization_role = user.get("role")
    # An organization member without a project role has no access to the project.
    role_from_organization = organization_role if organization_role != "member" else None
    direct_role = direct_roles.get(user["userUuid"])
    candidates = (role_from_organization, direct_role, *roles_from_groups)
    user_roles = {role for role in candidates if role}

    if not user_roles:
        return None

    ranked = user_roles.intersection(RANKS)
    custom = sorted(user_roles.difference(RANKS))
    described = {
        "userUuid": user["userUuid"],
        "name": full_name(user),
        "email": user.get("email"),
        "projectRole": max(ranked, key=RANKS.index, default=None),
        "organizationRole": organization_role,
        "directRole": direct_role,
        "groups": [group["name"] for group in groups],
    }

    if custom:
        described["customRoleUuids"] = custom

    return described


def _describe_space(space: dict[str, Any]) -> dict[str, Any]:
    return {
        "spaceUuid": space["uuid"],
        "spaceSlug": space_slug(space),
        "name": space["name"],
        "parentSpaceUuid": space.get("parentSpaceUuid"),
        "inheritsParentPermissions": space.get("inheritParentPermissions"),
        "charts": _read_count(space, "chartCount"),
        "dashboards": _read_count(space, "dashboardCount"),
        "childSpaces": _read_count(space, "childSpaceCount"),
    }


def _read_count(space: dict[str, Any], field: str) -> int:
    return int(space.get(field) or 0)


def _describe_space_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "userUuid": user["userUuid"],
        "name": full_name(user),
        "email": user.get("email"),
        "spaceRole": user.get("role"),
        "hasDirectAccess": user.get("hasDirectAccess"),
        "inheritedFrom": user.get("inheritedFrom"),
        "projectRole": user.get("projectRole"),
    }


async def grant(
    client: LightdashClient,
    project_uuid: str,
    email: str,
    role: str,
    dry_run: bool,
) -> dict[str, Any]:
    access = {"email": email, "role": role}

    if dry_run:
        current = await _find_current_access(client, project_uuid, email=email)
        return {
            "wouldGrant": access,
            "currentAccess": current,
            "next": (
                "Nothing is changed yet. "
                "Call grant_project_access again with dry_run=false to grant it."
            ),
        }

    path = f"/api/v1/projects/{project_uuid}/access"
    await client.request("POST", path, json=access | {"sendEmail": False})

    return {"granted": access}


async def _find_current_access(
    client: LightdashClient,
    project_uuid: str,
    user_uuid: str | None = None,
    email: str | None = None,
) -> dict[str, Any] | None:
    """A user's current access to the project, as list_project_access shows it, or None."""
    access = await project_access(client, project_uuid)

    for user in access["users"]:
        if _is_matching_user(user, user_uuid, email):
            return pick(user, *CURRENT_ACCESS_FIELDS)

    return None


def _is_matching_user(user: dict[str, Any], user_uuid: str | None, email: str | None) -> bool:
    if user["userUuid"] == user_uuid:
        return True

    if email is None:
        return False

    user_email = user["email"] or ""
    return user_email.lower() == email.lower()


async def update_grant(
    client: LightdashClient,
    project_uuid: str,
    user_uuid: str,
    role: str,
    dry_run: bool,
) -> dict[str, Any]:
    members = await client.get(f"/api/v1/projects/{project_uuid}/access")
    member = _find_member(members, user_uuid)

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
        current = await _find_current_access(client, project_uuid, user_uuid=user_uuid)
        return {
            "wouldChange": change,
            "currentAccess": current,
            "next": (
                "Nothing is changed yet. "
                "Call update_project_access again with dry_run=false to change it."
            ),
        }

    path = f"/api/v1/projects/{project_uuid}/access/{user_uuid}"
    await client.request("PATCH", path, json={"role": role})

    return {"changed": change}


def _find_member(members: list[dict[str, Any]], user_uuid: str) -> dict[str, Any] | None:
    for member in members:
        if member["userUuid"] == user_uuid:
            return member

    return None


async def add_member(
    client: LightdashClient,
    group_uuid: str,
    user_uuid: str,
    dry_run: bool,
) -> dict[str, Any]:
    group = await client.get(f"/api/v1/groups/{group_uuid}")
    members = await client.get(f"/api/v1/groups/{group_uuid}/members")
    is_member = _find_member(members, user_uuid) is not None

    if is_member:
        return {"added": None, "message": "This user is already a member of the group."}

    membership = {"userUuid": user_uuid, "group": group["name"]}

    if dry_run:
        gives = await _list_group_grants(client, group_uuid)
        return {
            "wouldAdd": membership,
            "groupGives": gives,
            "next": (
                "Nothing is changed yet. "
                "Call add_group_member again with dry_run=false to add them."
            ),
        }

    await client.request("PUT", f"/api/v1/groups/{group_uuid}/members/{user_uuid}")
    return {"added": membership}


async def _list_group_grants(client: LightdashClient, group_uuid: str) -> list[dict[str, Any]]:
    """The projects the group gives access to, with the role it gives on each."""
    grants = []
    projects = await client.get("/api/v1/org/projects")

    for project in projects:
        project_uuid = project["projectUuid"]
        accesses = await client.get(f"/api/v1/projects/{project_uuid}/groupAccesses")
        roles_given = [access["role"] for access in accesses if access["groupUuid"] == group_uuid]
        grants += [
            {"projectUuid": project_uuid, "project": project["name"], "role": role}
            for role in roles_given
        ]

    return grants
