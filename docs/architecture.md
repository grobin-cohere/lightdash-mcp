# Architecture

One Python process: an MCP server built on the official MCP Python SDK (`MCPServer`, Streamable HTTP), which is also the OAuth authorization server its clients sign in with. It calls the Lightdash REST API with each user's own Lightdash token. All state is in Redis.

## Modules

| Module | Owns |
| --- | --- |
| `server.py` | Builds the server: auth settings, consent, callback and health routes, tools, the tool-call audit log, allowed hosts, the Basic-header fix on `/token` and `/revoke`, and their answer to a Redis failure or a busy grant lock |
| `config.py` | Settings from the environment |
| `auth/provider.py` | The OAuth provider: clients, consent, Lightdash callback, codes and tokens, upstream refresh |
| `auth/pages.py` | The consent and error pages |
| `auth/audit.py` | The audit log: one JSON line per event |
| `auth/store.py` | Encrypted Redis storage, atomic writes and locks |
| `lightdash.py` | The async Lightdash API client and its errors. Every user's client shares the provider's HTTP client and its connections. That client keeps no cookies, so one user's cookie never goes out with another's request |
| `tools/common.py` | A Lightdash client for the signed-in user, error mapping, tool annotations |
| `tools/shared.py` | Helpers the tools modules share: paginated lists, argument pattern checks, space slugs |
| `tools/access.py` | Users, groups, roles, project and space access |
| `tools/content.py` | Finding charts and dashboards, reading dashboards, unused content, validation errors, moving and deleting content |
| `tools/code.py` | Charts and dashboards as code: reading them, checking them, creating and replacing them |
| `tools/schedulers.py` | Scheduled deliveries |
| `tools/data.py` | Explores, fields, metric queries and saved charts |

## Sign-in

1. The MCP client registers itself (`/register`) and opens `/authorize`.
2. The server saves the request for 10 minutes and shows its consent page (`/oauth/consent`). One Lightdash OAuth client serves every MCP client, so Lightdash's own consent page can't tell them apart. The consent page works like this:
   - It names the client and shows the whole address it returns to.
   - It warns when that address is an app, or a website: not a loopback address, and not on a host of `REDIRECT_HOSTS`.
   - A CSRF token in a `SameSite=Lax` cookie protects the form. There is one per sign-in. `/authorize` makes it once, so a prefetch or a second tab doesn't change it. The cookie is `Secure` when `PUBLIC_URL` is HTTPS.
   - The page can't be framed.
3. On **Continue to Lightdash**, the server redirects to Lightdash's `/authorize` with its own PKCE and the saved request's id as `state`. On **Cancel**, the client gets `error=access_denied`.
4. Lightdash signs the user in and returns to `/oauth/lightdash/callback`.
   - The callback goes on only in the browser that approved the consent page. The same cookie proves it.
   - Once approved, the consent page no longer opens, so no other browser can get a new cookie.
   - So a Lightdash link taken from someone else's consent can't send this user's sign-in to another client.
   - The server exchanges the code, reads the user from `/api/v1/user`, creates a grant, and returns its own single-use code to the client.
   - If Lightdash fails, the client gets `error=server_error`. Of Lightdash's own errors, only `access_denied` and `temporarily_unavailable` reach the client. Any other becomes `server_error`.
5. The client exchanges that code, with its PKCE verifier, for the server's tokens.

A client registered with `client_secret_basic` can send its credentials only in the `Authorization` header, as RFC 6749 section 2.3.1 allows. Dex's OAuth connector does this. The MCP SDK's token and revocation endpoints also require the credentials in the form body. So `BasicAuthClientId` copies them there from the header, for `/token` and `/revoke`. The SDK still checks the secret. `BasicAuthClientId` reads at most 64 KiB of body and answers 413 above that, as the consent form does.

### What registration accepts

Registration is open, as MCP clients need, so it checks what it stores:

- Redirect URIs: `https` (on a host of `REDIRECT_HOSTS` only, when it is set), `http` on `localhost`, `127.0.0.1` or `[::1]` only, and custom schemes for native apps (RFC 8252), such as `myapp://callback`. Never `javascript:`, `data:`, `vbscript:`, `file:` or `blob:`, a user name or password (`https://good@evil`), or a fragment.
- At most 10 redirect URIs of 2000 characters, a `client_name` of 200, and 8 KiB in all. Metadata the server doesn't use (logo, contacts, policy and terms URIs, JWKS, software ID and version) isn't stored.
- `/authorize` needs an S256 `code_challenge` (43 characters) and limits `state` and `resource` to 1024 characters.

## Grants and tokens

- A grant is one sign-in. It holds the user's Lightdash access and refresh tokens, and the digests of this server's current code and tokens for it.
- The client gets the server's own tokens: an access token for 1 hour (`ACCESS_TOKEN_TTL`) and a refresh token for 14 days. Both point to the grant, and are valid only while the grant points back to them. Lightdash tokens never leave the server.
- A grant lasts at most 90 days, however often its client refreshes: then the user signs in again. The 90 days are a fixed constant in the code (`GRANT_LIFETIME` in `auth/provider.py`), not a setting.
- Refreshing the client's tokens also refreshes the Lightdash ones, so both sign-ins last as long. A tool call refreshes the Lightdash token when it expires within a minute.
- Refreshes run under a Redis lock per grant, `lightdash-mcp:lock:grant:<id>`. The lock expires after 60 seconds (`LOCK_TIMEOUT`), and a request waits at most 30 seconds to get it (`LOCK_WAIT`). The new Lightdash tokens are saved before they are used, so a Lightdash refresh token is never used twice.
- Requests that Lightdash refused with the same token refresh it once: the others get the new one. A refresh gives up after 20 seconds (`REFRESH_TIMEOUT`), so the refresh and its four Redis commands under the lock (taking it, reading the grant, saving the Lightdash tokens, writing the new tokens) end before the lock expires, even when each command takes its 10 seconds to fail (below). `REFRESH_TIMEOUT` is computed from the other timeouts.
- A client's refresh holds the grant's lock from start to end. Its new access token, refresh token and grant are written in one Redis transaction (`MULTI`), and only then is the old refresh token gone: a failure, a crash or a cancellation before that leaves the old tokens working.
- A refresh token works once. Its digest is kept for 14 days after its exchange: presented again by its client, it was copied, and the grant ends, here and on Lightdash. A second refresh still in flight with the same token is only refused.
- When Lightdash refuses a refresh with `invalid_grant`, the grant ends and the user signs in again. Any other error, such as `invalid_client` from a wrong client secret, a malformed answer, or Lightdash being unreachable, keeps the grant and the client's refresh token so it can retry.
- Revoking a token ends the grant here and revokes its refresh token on Lightdash, with this server's Lightdash client credentials. A refusal or a failure there is logged. The revocation waits for a refresh in flight on the same grant, so the refresh can't bring the grant back or issue tokens after it.
- Ending a grant deletes it and its tokens in one Redis transaction too. Only the request whose transaction removes the grant logs its end.
- A lock that expires before its holder releases it, or that Redis fails to release, is not an error: the work under it is saved by then. A lock left behind expires after its 60 seconds, and until then the grant's next exchange or revocation finds it busy. For a refresh, an error would hide new tokens that have already replaced the old ones. For the same reason, a failure to renew the client registration's expiry after an exchange is ignored. A refresh rarely outlasts the lock, as it gives up on Lightdash after 20 seconds and Redis commands fail after about 10 seconds each (below). If one does, a revocation that took the expired lock meanwhile can't stop it: the refresh puts the grant back.

### When `/token` or `/revoke` can't finish for now

| Case | Answer | Kept |
| --- | --- | --- |
| Lightdash fails a refresh: unreachable, no answer in 20 seconds, an error status other than `invalid_grant`, or a malformed answer | `/token`: 400 `invalid_request`, with why and "Try again in a moment." | The grant and the refresh token |
| The grant's lock stays busy for 30 seconds, during a code or refresh exchange | `/token`: 400 `invalid_request`, "Try again in a moment." | The grant, and the code or refresh token |
| The lock stays busy while a reused refresh token is found | `/token`: the same 400 `invalid_request`. The grant ends only if the token is presented again, and nothing is logged until then | The grant |
| The lock stays busy during a revocation | `/revoke`: 503, `Retry-After: 5`, no body | The grant and its tokens |
| Redis fails or doesn't answer in 5 seconds (`REDIS_TIMEOUT`), twice (`REDIS_RETRIES`, below), anywhere in `/token`: the client lookup, loading the code or refresh token (also from a Bearer header), the exchange | `/token`: 400 `invalid_request`, "This server's storage didn't answer. Try again in a moment." | The grant, and the refresh token. The code too, unless it failed after the code was taken (below) |
| Redis fails or doesn't answer, twice, anywhere in `/revoke` | `/revoke`: 503, `Retry-After: 5`, no body | The grant and its tokens, unless only the answer to the transaction that ends the grant was lost, and its retry failed (below) |

Why `invalid_request` on `/token`: RFC 6749 section 5.2 has no `server_error` or `temporarily_unavailable` code for the token endpoint, and the MCP SDK fails with a 500 on any code outside its list: RFC 6749's codes and RFC 8707's `invalid_target`. Of the codes it allows, `invalid_grant` tells clients that the session has ended, so they drop it and sign in again. `invalid_client` and `unauthorized_client` make some clients drop their registration. `invalid_request` says nothing about the grant or the client, so a client may retry with the same code or refresh token. Not every client does: the MCP Python SDK's client drops its tokens after any failed refresh and signs in again.

Why 503 on `/revoke`: RFC 7009 section 2.2.1 says that after a 503 the client must assume the token still works, and may try again later. Ending the grant without its lock would let the exchange in flight bring the grant back.

The SDK catches errors only around the code and refresh exchanges, and only `TokenError`. A Redis error in `/token` or `/revoke`, or a busy lock outside the exchanges (the reuse check, a revocation), reaches `TryAgain` in `server.py`, which gives the answers above and logs `storage_failed` for a Redis error. It is the app's outermost middleware, inside the SDK's 500 handler, so it also sees the token load of the SDK's Bearer middleware, which runs before any route. The provider can't answer these errors itself: the client lookup and the loads can only return nothing, which the SDK answers with `invalid_grant`. A Redis error on any other path is still a 500.

#### What a Redis failure can still cost

Most of these steps only read, or change nothing until the transaction that writes the new tokens. That transaction succeeds or fails as a whole, so when Redis fails before or during it, the client retries with what it has.

The Redis client sends a command, or a transaction, once more after a connection error or a timeout (`REDIS_RETRIES = 1` in `auth/store.py`), on a new connection, then gives up with an error. One retry covers a pooled connection that Redis closed, such as after a restart. More retries would only make a Redis that stopped answering fail later, 5 seconds per attempt, while the MCP client waits for its answer. A retried command runs twice when Redis applied it but its answer was lost. The reads, the `SET`s, the deletes, the transactions, which only delete keys and set fixed values, renewing a client's expiry and releasing a lock give the same result however many times they run, so a retry after a lost answer to a transaction succeeds, and the request with it. Taking a grant's lock (`SET NX`) would find the lock taken the second time, so a lock whose key already holds the request's own token counts as taken (`do_acquire` in `auth/store.py`; each token is unique). Two commands do answer differently the second time:

- The `GETDEL` of a sign-in request in the Lightdash callback: the browser gets the expired page, and the user starts again from the MCP client. The Lightdash code isn't exchanged yet, so nothing leaks.
- The `GETDEL` of a code (below).

The cases left are failures where Redis did some of the work before the error:

- **Redis applied a transaction, but its answer was lost and its retry failed.** A transaction that writes new tokens may have been applied, though the client never gets the tokens. On a refresh, the client's retry presents the old refresh token, which now reads as reused: the grant ends, here and on Lightdash, and the user signs in again. On a code exchange, the code is spent (next case). Nobody holds the lost tokens, so nothing leaks. When a transaction that ends a grant is applied, `/revoke` still answers 503. The client's retry gets 200, but the grant's Lightdash refresh token isn't revoked: it was deleted with the grant.
- **A code exchange fails after it takes the code.** The code is taken (`GETDEL`) before the tokens are written, so that it can't be used twice even by an exchange whose lock expired. When Redis then fails, in the grant's read or the token write, the exchange gets the retryable 400, but the client's retry gets `invalid_grant` ("authorization code does not exist"), and the user signs in again. When Redis applied the `GETDEL` but its answer was lost, the Redis client's retry finds the code gone, and that exchange itself gets `invalid_grant`.
- **Saving the new Lightdash tokens fails.** Lightdash rotates its refresh token before this server saves the new one. When the save fails, the grant keeps a Lightdash refresh token that no longer works. The client keeps its own, but its retry gets `invalid_grant` from Lightdash, and the user signs in again.

Once the new tokens are written, a Redis failure can't fail the request any more (see the lock bullet above).

## Storage

Redis keys are `lightdash-mcp:{client,transaction,code,access,refresh,rotated,grant}:<id>`, and the grant locks are `lightdash-mcp:lock:grant:<id>`. Token keys are sha256 digests of the tokens.

Every value is encrypted with `FERNET_KEY`, together with its own key, so a value copied under another key in Redis doesn't load. A value that doesn't decrypt, names another key, or no longer parses counts as missing: the client signs in again.

Everything expires:

- Client registrations: 30 days after their last token exchange.
- Sign-in requests: 10 minutes.
- Codes: 5 minutes.
- Tokens and grants: with their lifetimes.
- A grant whose client hasn't exchanged the code yet: 10 minutes, so an unfinished sign-in doesn't keep the Lightdash tokens.
- Grant locks: 60 seconds.

## Errors

| Lightdash returns | The tool says |
| --- | --- |
| 401 | The token is refreshed and the request retried once, as when it expires during a long query. Refresh refused (`invalid_grant`): the sign-in has ended, reconnect, and the grant is ended. Still 401 with the new token: `Lightdash refused this request (401)`, and the grant is kept, as the 401 is about something else, such as an Enterprise-only route |
| 403 | Permission denied, with Lightdash's message |
| 404 | Not found, with Lightdash's message |
| Any other error | `Lightdash error <status>`, with its message |
| No response | Lightdash can't be reached: try again |
| A refresh fails otherwise | Why (an error status, no answer in time, a malformed answer), then try again. The same text whether it happens before the call or after a 401 |
| The grant's lock is busy for 30 seconds | Another request is refreshing the sign-in: try again |

## Logs

The `lightdash_mcp.audit` logger writes one JSON object per line, so a value sent by a client, such as a tool name with a newline, can't forge a line. Tokens and secrets are never logged.

| `event` | When | Fields |
| --- | --- | --- |
| `tool_call` | Every tool call, at INFO | `user` (Lightdash UUID), `tool`, `arguments`, `error`. A value longer than 200 characters once serialized is cut, and at most 30 arguments are logged |
| `client_registered` | A client registers | `client_id`, `client_name`, `redirect_uris` |
| `consent` | The user clicks Continue to Lightdash or Cancel | `client_id`, `decision`: `allow` or `deny` |
| `grant_created` | A Lightdash sign-in finishes | `grant`, `subject`, `client_id` |
| `sign_in_failed` | Lightdash's code exchange or user lookup fails, at WARNING | `client_id` |
| `refresh_failed` | A Lightdash refresh fails but keeps the grant, at WARNING | `grant`, `subject`, `client_id`, `reason` |
| `token_revoked` | A client's revocation ends a grant, once the grant is removed, before `grant_ended`. A token whose grant has already ended is revoked without a log line | `grant`, `subject`, `client_id` |
| `revoke_busy` | A revocation fails because the grant's lock stays busy for 30 seconds, at WARNING. `/revoke` answers 503, and the grant and its tokens are kept | `grant`, `subject`, `client_id` |
| `grant_ended` | A grant ends | `grant`, `subject`, `client_id`, `reason`: `revoked`, `lightdash_refused_refresh` or `refresh_token_reused` |
| `lightdash_revoke_failed` | Lightdash refuses or misses a revocation, at WARNING | `grant`, `subject`, `failure` (status or error) |
| `storage_failed` | Redis fails or doesn't answer during `/token` or `/revoke`, at WARNING | `path`, `error` (the Redis error's class) |

```
{"event": "tool_call", "user": "b264d83a-9000-426a-85ec-3f9c20f368ce", "tool": "revoke_project_access", "arguments": {"project_uuid": "3675b69e-...", "user_uuid": "...", "dry_run": false}, "error": false}
```

The SDK also logs each tool error's message, and the traceback of unexpected exceptions.

## Allowed hosts

The SDK protects against DNS rebinding by accepting only `localhost` hosts. The server also accepts `PUBLIC_URL`'s host, so requests through a tunnel or a proxy get in.

## How Lightdash OAuth behaves

Checked on Lightdash 3.93.6, open source, without a license:

- **Discovery:** `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` exist. The OAuth server is part of the open-source core, at `/api/v1/oauth`.
- **Registration:** open, and `http://localhost` redirect URIs are accepted.
- **Flow:** authorization code with S256 PKCE works without `resource`. The token is then for the REST API, which accepts it as `Authorization: Bearer`. Permissions follow the user.
- **Consent page:** Lightdash shows its own consent page on every sign-in. Its redirect back is an HTML page with a meta refresh, not a 302. In strict security mode the callback also gets an `iss` parameter.
- **Lifetimes:** access token 1 hour, refresh token 14 days (`AUTH_OAUTH_SERVER_ACCESS_TOKEN_LIFETIME`, `AUTH_OAUTH_SERVER_REFRESH_TOKEN_LIFETIME`).
- **Revocation:** `/revoke` takes the token alone and ignores client credentials. The server sends them anyway, as RFC 7009 asks of a confidential client. Its handler in Lightdash's source (`packages/backend/src/routers/oauthRouter.ts`) is the same at 3.93.6 and 3.148.1.
- **Rotation:** each refresh returns a new refresh token. The old one stays usable for 60 seconds (`AUTH_OAUTH_SERVER_REFRESH_TOKEN_ROTATION_GRACE`), then gets `invalid_grant`. Reuse doesn't revoke the newest tokens.
- **Introspection:** `/introspect` needs a Lightdash session, not client credentials. The server doesn't need it: it keeps the Lightdash tokens itself.
- **Scopes:** `read` and `write` are only enforced behind the `AgentIdentity` and `OAuthScopeEnforcement` feature flags, off by default. A token can do whatever the user's role allows.
- **Official Lightdash MCP:** lives in `ee/`, so it needs a license key.
