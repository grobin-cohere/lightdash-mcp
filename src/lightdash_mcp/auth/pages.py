"""The HTML pages the user sees during sign-in: the consent page and the error page."""

import html

from starlette.responses import HTMLResponse


def consent(
    client_name: str, redirect_uri: str, warning: str | None, transaction_id: str, csrf: str
) -> HTMLResponse:
    notice = f'<p class="warning">{html.escape(warning)}</p>' if warning else ""
    body = f"""
            <p><strong>{html.escape(client_name)}</strong> wants to use Lightdash as you.</p>
            <p class="muted">It will act with your Lightdash permissions. You'll return to:</p>
            <p><code>{html.escape(redirect_uri)}</code></p>
            {notice}
            <form method="post">
              <input type="hidden" name="transaction" value="{html.escape(transaction_id)}">
              <input type="hidden" name="csrf" value="{html.escape(csrf)}">
              <button name="action" value="deny" class="secondary">Cancel</button>
              <button name="action" value="allow">Continue to Lightdash</button>
            </form>"""
    return page("Connect to Lightdash", body)


def expired(hint: str = "Start again from your MCP client.", status: int = 400) -> HTMLResponse:
    return page("Sign-in expired", f"<p>{html.escape(hint)}</p>", status)


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; --bg: #f6f7f9; --card: #fff; --text: #16181d; --muted: #5f6673; --accent: #7262ff; --line: #e3e5ea;
           --warn-bg: #fff4e0; --warn: #8a4b00; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg: #111317; --card: #1a1d23; --text: #eceef2; --muted: #9aa1ad; --line: #2b2f37;
                                                 --warn-bg: #3a2a10; --warn: #ffc56b; }} }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text);
         font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 16px; box-sizing: border-box; }}
  main {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 28px; max-width: 420px; width: 100%; }}
  h1 {{ font-size: 18px; margin: 0 0 16px; }}
  code {{ display: block; overflow-wrap: anywhere; font-size: 13px; padding: 8px; border: 1px solid var(--line); border-radius: 6px; }}
  .muted {{ color: var(--muted); }}
  .warning {{ background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 10px 12px; }}
  form {{ display: flex; gap: 8px; justify-content: flex-end; margin-top: 24px; }}
  button {{ font: inherit; border-radius: 8px; padding: 8px 14px; border: 1px solid var(--accent); background: var(--accent); color: #fff; cursor: pointer; }}
  button.secondary {{ background: transparent; color: var(--text); border-color: var(--line); }}
</style></head>
<body><main><h1>{title}</h1>{body}</main></body></html>""",
        status_code=status,
        headers={"Content-Security-Policy": "frame-ancestors 'none'", "Cache-Control": "no-store"},
    )
