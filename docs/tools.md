# Tools

Every tool runs as the signed-in user. A tool fails with a permission message when the user's Lightdash role doesn't allow the call.

Write tools are marked idempotent where repeating them changes nothing. Destructive tools, which include the tools that grant access, are marked destructive and take `dry_run`, on by default, which shows what would change without changing it. Pass `dry_run=false` to apply the change.

## Read

| Tool | Parameters | Returns | Lightdash API |
| --- | --- | --- | --- |
| `list_projects` | | Projects the user can see | `/api/v1/org/projects` |
| `list_users` | `search` | Organization members with role, status and groups, every page | `/api/v1/org/users` |
| `list_groups` | `search` | Groups and their members, every page | `/api/v1/org/groups` |
| `list_roles` | | System and custom roles with their permission scopes. Lightdash shows scopes to organization admins only; others get `scopes: null` | `/api/v2/orgs/{org}/roles?load=scopes` |
| `list_project_access` | `project_uuid` | The users with access, each with their effective role (the highest of their organization role, direct grant and groups' roles), organization role, direct grant and groups; and the groups with access. Custom roles, which can't be ranked, are listed in `customRoleUuids` | `/org/users`, `/projects/{p}/access`, `/projects/{p}/groupAccesses`, `/org/groups` |
| `list_spaces` | `project_uuid` | Spaces, nested ones included, with content counts and `spaceSlug`, the space's path (such as `parent/child`) that chart and dashboard code use | `/projects/{p}/spaces` |
| `list_space_access` | `project_uuid`, `space_uuid` | Who can access a space and why: direct, or inherited | `/projects/{p}/spaces/{s}` |
| `search_content` | `project_uuid`, `search`, `content_type` | Charts and dashboards matching the search, or all of them, with slug, space, views and last update | `/api/v2/content` |
| `get_dashboard` | `dashboard_uuid` | A dashboard's slug, filters and tiles in layout order: charts with their UUID, slug and kind, and text | `/dashboards/{d}` |
| `find_unused_content` | `project_uuid`, `unused_days` (90), `content_type` | Charts and dashboards not viewed in that many days, never-viewed first. Content created within the window is left out, and so is content with views but no recorded last view date | `/api/v2/content` |
| `list_validation_errors` | `project_uuid`, `revalidate` | Broken charts and dashboards from the last validation run, or a fresh one | `/projects/{p}/validate` |
| `list_schedulers` | `project_uuid`, `search` | Scheduled deliveries with schedule, owner, recipients and latest run, every page | `/schedulers/{p}/list` |

## Data

| Tool | Parameters | Returns | Lightdash API |
| --- | --- | --- | --- |
| `list_explores` | `project_uuid` | Explores with label, group and description, and errors when they don't compile. Leaves out the tables that the project's tables configuration hides, as Lightdash does | `/projects/{p}/explores?filtered=true` |
| `get_explore` | `project_uuid`, `explore` | Visible dimensions and metrics, joined tables included, with field ID, label, type, table and description | `/projects/{p}/explores/{e}` |
| `run_query` | `project_uuid`, `explore`, `dimensions`, `metrics`, `filters`, `sorts`, `limit` (500) | Column labels, rows of raw values (at most 2500), and `truncated` when more rows match | `POST /api/v2/projects/{p}/query/metric-query`, then `/api/v2/projects/{p}/query/{q}` |
| `run_chart` | `project_uuid`, `chart_uuid` (UUID or slug), `dashboard_uuid` | A saved chart's results as saved, with the dashboard's filters when `dashboard_uuid` is given. Same shape as `run_query` | `POST /api/v2/projects/{p}/query/chart` or `/query/dashboard-chart`, then `/api/v2/projects/{p}/query/{q}` |

A filter is `{field_id, operator, values, settings}`. Filters are combined with AND; a filter on a metric applies after aggregation. Date filters take `settings`, such as `inThePast` with `values: [30]` and `settings: {"unitOfTime": "days"}`.

## Write

| Tool | Parameters | Does | Lightdash API |
| --- | --- | --- | --- |
| `grant_project_access` | `project_uuid`, `email`, `role`, `dry_run` | Gives a member a direct project role, without an email. Fails when a direct grant exists. `dry_run` shows their current access and the grant | `POST /projects/{p}/access` |
| `update_project_access` | `project_uuid`, `user_uuid`, `role`, `dry_run` | Changes a direct project role. `dry_run` shows their current access and the change | `PATCH /projects/{p}/access/{u}` |
| `revoke_project_access` | `project_uuid`, `user_uuid`, `dry_run` | Removes a direct grant. Access through the organization role or a group remains | `DELETE /projects/{p}/access/{u}` |
| `add_group_member` | `group_uuid`, `user_uuid`, `dry_run` | Adds a user to a group. `dry_run` shows the group and the project roles it gives | `PUT /groups/{g}/members/{u}` |
| `remove_group_member` | `group_uuid`, `user_uuid`, `dry_run` | Removes a user from a group, and the access it gave them | `DELETE /groups/{g}/members/{u}` |
| `move_content` | `project_uuid`, `content_type`, `uuid`, `target_space_uuid` | Moves a chart, dashboard or space into another space | `/api/v2/content/{p}/move` |
| `delete_content` | `project_uuid`, `content_type`, `uuid`, `dry_run` | Deletes a chart, dashboard or space with everything in it. `dry_run` on a space lists what it holds | `/api/v2/content/{p}/delete` |
| `set_scheduler_enabled` | `scheduler_uuid`, `enabled` | Pauses or resumes a delivery | `PATCH /schedulers/{s}/enabled` |
| `update_scheduler` | `scheduler_uuid`, `name`, `cron`, `timezone`, `message` | Changes the fields given, keeps the rest, filters and parameters included | `PATCH /schedulers/{s}` |
| `delete_scheduler` | `scheduler_uuid`, `dry_run` | Deletes a delivery | `DELETE /schedulers/{s}` |

## Build

Charts and dashboards as code, in the format that `lightdash download` writes and `lightdash upload` reads, so content made through lightdash-mcp can be pulled into a repository later.

| Tool | Parameters | Does | Lightdash API |
| --- | --- | --- | --- |
| `get_chart_code` | `project_uuid`, `slug` | Returns a chart as code: explore, fields, filters, sorts, chart configuration | `GET /projects/{p}/code/charts?ids=` |
| `get_dashboard_code` | `project_uuid`, `slug` | Returns a dashboard as code: tiles with their position and chart slug, tabs, filters | `GET /projects/{p}/code/dashboards?ids=` |
| `save_chart` | `project_uuid`, `chart`, `dry_run` | Creates a chart, or replaces the one with the same slug, then validates it. Refuses fields its explore doesn't have; hidden fields are allowed. On replace, `description`, `tableConfig`, `pivotConfig` and `parameters` left out keep their value | `POST /projects/{p}/code/charts/{slug}`, `POST /projects/{p}/validate/chart/{c}` |
| `save_dashboard` | `project_uuid`, `dashboard`, `dry_run` | Creates a dashboard, or replaces the one with the same slug, then validates it. On replace, `tabs`, `filters`, `description`, `config` and `parameters` left out keep their value. A dry run lists the charts its tiles show that aren't saved yet, and the tile, tab and filter counts before and after; saving refuses unsaved charts | `POST /projects/{p}/code/dashboards/{slug}`, `POST /projects/{p}/validate/dashboard/{d}` |

`save_chart` and `save_dashboard` are marked destructive because they can replace content: `dry_run` says whether they would create or replace, what they would replace and which keys change, and ends with the call that saves. Both return the content's URL. Once the content is saved, a validation that fails or doesn't answer is reported in `validationFailed` instead of failing the call. `save_chart` sends `force`, so Lightdash updates the chart even when its name, description and slug are unchanged.

Project roles are `viewer`, `interactive_viewer`, `editor`, `developer` and `admin`.

## Things to know

- `run_query` needs the Interactive Viewer role or above. Viewers only see saved charts, so Lightdash refuses their queries: they use `run_chart`.
- `run_query` asks Lightdash for one row more than `limit`, so `truncated` is exact. `run_chart` keeps the chart's saved row limit, so `truncated` only says whether rows were cut at 2500.
- Raw values are what the warehouse returns: Postgres counts and other big integers come as strings.
- A query that runs longer than 120 seconds, wall clock, is cancelled. So is a query whose polling fails or whose call the client cancels.

- Deleting content is permanent on a default Lightdash instance: it doesn't appear in the deleted-content list.
- A chart or dashboard saved into a `spaceSlug` that doesn't exist creates that space, restricted to its creator and admins. Share it, or move the content, to show it to others.
- Lightdash saves a dashboard tile whose chart slug doesn't exist as an empty tile, and its validation doesn't report it, so `save_dashboard` checks every chart slug first.
- Lightdash's `PATCH /schedulers/{s}` writes every field, and a field left out becomes empty. `update_scheduler` reads the whole scheduler, applies the changes, and sends it all back. Lightdash has no version check, so an edit made in Lightdash between the read and the write is lost.
- Lists that Lightdash paginates are read page by page, up to 10,000 items. Past that, the tool fails and asks to narrow the search.
