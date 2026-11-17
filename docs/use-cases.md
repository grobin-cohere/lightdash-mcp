# Use cases

What you can ask once lightdash-mcp is connected. Screenshots from Claude on the local Lightdash demo (`make dev`).

The screenshots were taken before the rename, when the server was called Kizaru.

## Monthly report

> Create a monthly report of Jaffle Shop.

Tools: `list_projects`, `list_explores`, `get_explore`, `run_query`

![Claude writing a monthly report of Jaffle Shop](use-cases/1-monthly-report.jpg)

![The monthly revenue trend in the report](use-cases/1-monthly-report-trend.jpg)

## Revenue by country

> What was our revenue by country last quarter?

Tools: `list_projects`, `list_explores`, `get_explore`, `run_query`

![Claude answering revenue by country](use-cases/2-revenue-by-country.jpg)

## Space access

> Who can see the Finance space, and why?

Tools: `list_projects`, `list_spaces`, `list_space_access`, `list_groups`

![Claude explaining who can see the Finance space](use-cases/3-finance-space-access.jpg)

## Unused dashboards

> Which dashboards has nobody opened in 90 days? Move them to an Archive space.

Tools: `list_projects`, `find_unused_content`, `list_spaces`, `move_content`

![Claude listing unused dashboards](use-cases/4-archive-unused-dashboards.jpg)

![Claude moving them to the Archive space](use-cases/4-archive-unused-dashboards-end.jpg)

## Broken charts

> List the broken charts and what's wrong with them.

Tools: `list_projects`, `list_validation_errors`

![Claude listing broken charts and their errors](use-cases/5-broken-charts.jpg)

## Project access

> Give alice@example.com editor access to Jaffle Shop.

Tools: `list_projects`, `grant_project_access`

![Claude granting editor access](use-cases/6-grant-access.jpg)

The screenshot shows an older version, which granted access in one step. Since 0.4.0, the assistant first shows a preview with Alice's current access and the grant. It applies the grant after you confirm, with `dry_run=false`.

## Deliveries

> Pause the weekly sales delivery.

Tools: `list_projects`, `list_schedulers`, `set_scheduler_enabled`

![Claude pausing a scheduled delivery](use-cases/7-pause-delivery.jpg)
