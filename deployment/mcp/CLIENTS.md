# Connect AI apps to Ostadix

Use the public **Streamable HTTP** URL, including `/mcp` and without a trailing
slash. For Lee's deployment the connector URL is:

```text
https://leeostadi.com/mcp
```

For another installation, substitute its own URL everywhere below. The host
must have [native OAuth enabled and the metadata routes forwarded](README.md#enable-native-oauth-for-chat-apps).
Choose **OAuth** when the app asks for authentication. Dynamic Client
Registration (DCR) supplies client credentials automatically; leave manual
client-ID/secret fields empty unless the app specifically requires them.

The browser opens an Ostadix approval page on the configured server's own
HTTPS origin. Review the requesting client and enter the server owner's token
there to authorize that connection. This token is the contents of the server's
`--token-file`; it is not an OAuth client secret. Do not put it in the connector
URL or chat conversation. The app receives its own OAuth tokens. Every
authorized app can use the host's Ostadix tools; OAuth does not create a
separate host account or filesystem sandbox.

The instructions below were checked against official documentation on
**2026-10-19**. They describe supported client configuration paths. They are
not a claim that each app/account has been registered and tested against this
deployment. Plan, regional, administrator and rollout restrictions still
apply. A successful protocol test and a successful connection inside an app
are separate checks.

## ChatGPT

On the web, open **Plugins → + → Add custom MCP server**. Enter the URL above,
select OAuth, create the plugin, and install it. Select it with `@` in a
conversation. If registration options are shown, use DCR for this server;
it does not advertise Client ID Metadata Documents (CIMD). Workspace
permissions and security modes may restrict adding or using custom servers.
The hosted connector UI documents OAuth and no-auth modes, not a general
custom bearer-header field. [Official setup](https://developers.openai.com/api/docs/guides/custom-mcp-server).

ChatGPT requires authorization code with S256 PKCE. When the issuer advertises
RFC 9207 and includes the matching `iss` in authorization redirects, its stable
callback is `https://chatgpt.com/connector_platform_oauth_redirect`. Otherwise,
new configurations can use `https://chatgpt.com/connector/oauth/{callback_id}`.
Use the exact callback shown in the app rather than inventing one.
[Official OAuth requirements](https://developers.openai.com/plugins/build/auth).

## Claude web, Desktop, mobile and Cowork

In **Customize → Connectors → Add custom connector**, enter the URL and complete
OAuth. Remote connectors run through Anthropic's servers, including when
added in Desktop; a loopback-only URL is insufficient. Availability and
workspace policy depend on the account.
[Add a custom connector](https://claude.com/docs/connectors/custom/add-unlisted),
[remote connector availability](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

Hosted Claude uses `https://claude.ai/api/mcp/auth_callback`. DCR is supported
by default and every authorization request uses S256 PKCE. Discovery must
return `401` with `WWW-Authenticate`; the metadata's `resource` must exactly
match the entered `/mcp` URL. Static request headers are a limited
organization beta, so OAuth is the common connection method.
[Official authentication requirements](https://claude.com/docs/connectors/building/authentication).

## Claude Code

```bash
claude mcp add --transport http ostadix https://leeostadi.com/mcp
claude mcp login ostadix
```

The `/mcp` panel also manages authentication. Current releases support
`claude mcp login ostadix --no-browser` for an interactive terminal without a
local browser. The callback uses `http://localhost:<port>/callback`; some
versions use `127.0.0.1`. Static bearer headers are also supported with
`--header`, and a preregistered client can use `--client-id`, optional
`--client-secret`, and `--callback-port`. DCR avoids those manual settings.
[Official Claude Code MCP guide](https://code.claude.com/docs/en/mcp).

## Cursor

Merge this entry into `~/.cursor/mcp.json`, or `.cursor/mcp.json` for one
project, then complete the server's OAuth prompt:

```json
{
  "mcpServers": {
    "ostadix": { "url": "https://leeostadi.com/mcp" }
  }
}
```

Cursor supports DCR, static OAuth client configuration and custom `headers`.
Its documented callbacks are `http://localhost:8787/callback` for Desktop and
`https://www.cursor.com/agents/mcp/oauth/callback` for web/Agents. If the
Ostadix service runs on the same computer as Cursor, use a different internal
service port to leave Cursor's callback port available; see
[changing the local port](README.md#use-a-different-local-port).
[Official Cursor MCP guide](https://cursor.com/docs/mcp).

## VS Code and GitHub Copilot agent chat

Merge this into `.vscode/mcp.json`, or add the equivalent server to your user
profile's MCP configuration. Start it using the configuration's Start action
and complete browser authentication:

```json
{
  "servers": {
    "ostadix": { "type": "http", "url": "https://leeostadi.com/mcp" }
  }
}
```

Custom `headers` and a static OAuth `clientId` are supported.
[Configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).
VS Code uses DCR with a manual client-credential fallback. Its documented
redirects include `http://127.0.0.1:33418` and `https://vscode.dev/redirect`;
use the actual registered redirect if a version chooses another loopback
port. [MCP developer guide](https://code.visualstudio.com/api/extension-guides/ai/mcp).

This is the VS Code agent integration. Consumer Microsoft Copilot's
[documented connectors](https://support.microsoft.com/en-us/microsoft-copilot/connecting-microsoft-copilot-to-other-services)
list specific Microsoft and Google services and do not document an arbitrary
MCP URL field. Do not infer consumer Copilot support from VS Code support.

## Codex CLI

```bash
codex mcp add ostadix --url https://leeostadi.com/mcp
codex mcp login ostadix
```

OAuth may begin during `add`. `login --no-browser` supports a separate
browser. The CLI supports DCR, CIMD and preregistered clients; this server uses
DCR. Static bearer mode is available through
`--bearer-token-env-var OSTADIX_MCP_TOKEN`, with the token supplied separately
in that environment variable. Arbitrary HTTP headers are configurable too.

Codex uses a loopback callback. With supported issuer binding, eligible new
registrations use `http://127.0.0.1/callback` with the active listener port;
other configurations can include `/callback/<callback_id>`. Follow the
exact callback Codex displays. `mcp_oauth_callback_port` controls the listener;
setting a callback URL alone does not set its listening port.
[Official Codex MCP guide](https://developers.openai.com/codex/mcp).

## Gemini CLI

Merge the following into your Gemini CLI `settings.json`:

```json
{
  "mcpServers": {
    "ostadix": { "httpUrl": "https://leeostadi.com/mcp" }
  }
}
```

Use `/mcp auth ostadix` if authentication is needed. `httpUrl` selects
Streamable HTTP; `url` is the older SSE setting. The CLI discovers OAuth and
registers dynamically, and also supports configured credentials and custom
headers. Its callback is `http://localhost:<random-port>/oauth/callback`.
It validates the issuer in RFC 9207 redirects. The documented browser flow
requires local browser/loopback access and has limitations in headless, SSH
and container sessions.
[Official Gemini CLI MCP guide](https://geminicli.com/docs/tools/mcp-server/).

## Gemini web and mobile

On the web, open **Settings → Connected Apps** (sometimes under Personal
Intelligence), then **Custom apps → Add a custom app**. Enter the URL, select
Next and finish sign-in. DCR avoids the Advanced features credential fields.
Once added on the web, the app can be used on web/mobile, including through
`@`. Current requirements include a personal Google account, age 18+, US
availability, English and Keep Activity enabled; work/school accounts are
excluded. Google's guide does not publish a fixed OAuth callback or generic
bearer-header configuration, so use its registration flow.
[Official Gemini custom-app guide](https://support.google.com/gemini/answer/17209137?hl=en-SM).

## Grok

Open [grok.com/connectors](https://grok.com/connectors), select **New Connector
→ Custom**, enter the public URL and complete authentication. Organization
admins may need to provision the connector first. Grok's public guide does not
specify a stable custom-MCP OAuth callback or a generic bearer-header field;
use the registration details it requests.
[Official Grok connector guide](https://docs.x.ai/grok/connectors).

## Perplexity

Open **Plugins → Add custom → Connector → Add MCP connector**, choose Remote,
and enter the URL. Choose **Streamable HTTP** and **OAuth**, add the connector,
then open its card to authenticate. Some interfaces still use
**Customize → Connectors**. DCR is supported; API Key and manual OAuth client
credentials are alternatives. Callbacks are
`https://www.perplexity.ai/rest/connections/oauth_callback` and, for Enterprise
subdomain organizations,
`https://enterprise.perplexity.ai/rest/connections/oauth_callback`.
[Official custom-connector guide](https://www.perplexity.ai/help-center/en/articles/13915507-adding-custom-remote-connectors).
Availability includes Pro, Max and Enterprise; administrators control member
access. [Official availability announcement](https://www.perplexity.ai/en-GB/changelog/what-we-shipped---march-13-2026).

## Verify a connection

After authorizing in each app, request `o_env` to confirm the selected host and
runtime, then `o_capabilities` to discover the exposed commands. A tool list
alone does not prove a runtime is installed or an execution succeeded. For a
deliberate execution check, invoke `o_smoke` and inspect its actual result.
Record the app/version, public URL and date of that check; avoid publishing
tokens, authorization codes or session IDs.

If the app shows an authorization error, check the public metadata URLs in
the [deployment guide](README.md#enable-native-oauth-for-chat-apps), exact
resource/issuer URL, callback registration, and whether the account allows
custom connectors. A browser receiving a `401` at `/mcp` before sign-in is
expected. An HTML website page, a proxy login redirect or a `404` at discovery
paths is not the OAuth response clients need.

Other clients can use the same URL when they implement Streamable HTTP and
compatible OAuth discovery/registration, or configurable bearer headers.
Apps without such a connector surface require an integration of their own;
pasting the URL into an ordinary chat does not install a tool.
