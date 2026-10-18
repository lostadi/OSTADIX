# Ostadix MCP over a URL

The same native `ostadix-mcp` binary supports local stdio clients and remote
**MCP Streamable HTTP** clients. Its connector URL is:

```text
https://mcp.example.com/mcp
```

This exposes the existing Ostadix tools, resources and session state through
HTTP. The host still runs the Ostadix runtime and its installed language
backends. A chatbot must support remote MCP to use this URL; merely accepting a
web link is insufficient. The server does not implement the older two-endpoint
HTTP+SSE transport or a chatbot-specific REST API.

## Host requirements and reproducibility

- Linux and macOS: Bash, Git, Python 3.10+, a native C linker and Rust through
  `rustup`. The checked-in `rust-toolchain.toml` selects the Rust version; the
  root and MCP crate each have their own `Cargo.lock`.
- Windows: run these commands in **WSL2 with Linux dependencies**, including the
  reverse proxy or a proxy that can reach WSL. This workflow does not qualify
  native Windows execution of the Unix process/job tools.
- Other Unix systems may run the core project, but this deployment script is
  currently limited to Linux/macOS. Cross-compilation and every CPU/OS pairing
  have not been qualified by this connector change.
- Optional language tools remain host dependencies. A working MCP endpoint
  does not prove that every backend, compiler SDK, kernel harness or VM exists.
  Query `o_env`, `o_doctor` and `o_runtimes` through the connector.

Keep the server, native runtime binaries, scripts and `backends/` from the same
checkout. Builds use the explicit `cargo +VERSION` toolchain selector,
`--locked` and checkout-local target directories.
For exact source reproducibility, retain the Git commit ID printed by
`git rev-parse HEAD`. Lockfiles pin Rust packages; host libraries, optional
backends, linkers and build paths still affect the resulting binary. These
instructions establish repeatable source builds, not bit-for-bit binaries
across operating systems.

## Build and test

From a fresh checkout:

```bash
git clone https://github.com/lostadi/OSTADIX.git
cd OSTADIX
bash scripts/setup_ostadix_mcp_http.sh --with-runtime
```

`--with-runtime` first runs the project's canonical `setup.sh -y --minimal`
workflow, then builds and checks the HTTP server. This option can install
system dependencies and native command aliases. No public listener, service,
credential, DNS record or scheduled update is created automatically.

On a prepared host, build the hosted Rust runtime and MCP wholly inside the
checkout without running package installers:

```bash
bash scripts/setup_ostadix_mcp_http.sh --build-runtime
```

When durable disk space is limited, place Cargo's intermediate files on another
filesystem, including a sufficiently large temporary filesystem:

```bash
OSTADIX_MCP_BUILD_CACHE=/tmp/ostadix-mcp-build \
  bash scripts/setup_ostadix_mcp_http.sh --build-runtime
```

The cache path must be absolute. Builds use its `runtime/` and `mcp/` target
directories, then atomically copy only the 14 declared runtime binaries and
the MCP binary into the normal checkout targets before creating aliases and
running the smoke. The installed release contains ordinary executable files
and continues running if the cache disappears after reboot. A later build
recreates the cache. Set the same variable in the updater's environment to use
this layout for managed releases. This option requires preinstalled build
dependencies and cannot be combined with `--with-runtime`; the canonical setup
workflow retains its own build directories. Allow enough temporary space for
compilation and durable space for the installed binaries and retained releases.

This builds the same native Rust command set as minimal setup, including `O`,
`o`, `olangc`, `ocorec`, `o-link`, `octl`, native node commands and the MCP
server. The C17 edition, Python reference edition setup and additional backend
packages belong to the full `setup.sh` workflow. A missing dependency makes
the build fail rather than silently installing it during an update.

If same-checkout runtime binaries already exist, the default command rebuilds
only MCP:

```bash
bash scripts/setup_ostadix_mcp_http.sh
bash scripts/setup_ostadix_mcp_http.sh --verify-only
```

The HTTP smoke launches a temporary loopback server and verifies actual MCP
requests, including the native O smoke. It does not deploy the service. Use
`--skip-smoke` only when deliberately producing an unverified build. The
script's `--help` describes all options, and it resolves its own repository
location even when launched from another working directory.

## Launch an authenticated local endpoint

Generate a secret outside the repository once. Keep this file when upgrading:

```bash
mkdir -p "$HOME/.config/ostadix-mcp"
(umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > "$HOME/.config/ostadix-mcp/token")
```

From the checkout root:

```bash
export O_LANG_ROOT="$PWD"
export O_BACKENDS_DIR="$PWD/backends"
export PATH="$PWD/target/release:$HOME/.cargo/bin:$PATH"
mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp \
  --transport http \
  --bind 127.0.0.1:8787 \
  --token-file "$HOME/.config/ostadix-mcp/token"
```

The endpoint is `http://127.0.0.1:8787/mcp`. HTTP authentication is required by
default: either supply a token file or set `OSTADIX_MCP_BEARER_TOKEN` in the
service environment. The token must contain at least 32 characters. A token
file avoids putting the credential in command-line arguments or shell history.
The default invocation without `--transport http` still uses stdio.

The process exposes a small unauthenticated liveness endpoint, which does not
list tools or run O programs:

```bash
curl --fail http://127.0.0.1:8787/healthz
```

For an explicitly unauthenticated local development session, replace
`--token-file ...` with `--allow-unauthenticated`. All clients authorized to
this endpoint receive the existing host execution tools and filesystem access
of the service account. Use a dedicated account or VM when that is the desired
execution boundary; this transport is not a per-user sandbox or a read-only
search connector.

The server is stateful. Clients must preserve the returned `Mcp-Session-Id`
and send the negotiated `MCP-Protocol-Version` on subsequent requests. Use one
server process behind the proxy; multiple replicas require session affinity.
Inactive sessions expire after 3,600 seconds by default. Configure
`--session-timeout-secs SECONDS`, or use `0` to disable this expiry.
Restarting a process ends its MCP sessions and managed jobs, so clients must
reconnect after an upgrade. Do not automatically repeat a tool call whose
completion is unknown.

## Give remote chat clients an HTTPS URL

Choose a DNS name pointing to the machine, install a TLS reverse proxy, and
allow it to listen on ports 80/443. [Caddy can provision HTTPS certificates
from the configured hostname](https://caddyserver.com/docs/quick-starts/reverse-proxy).
No particular hosting provider is required: this can be your own server,
reachable workstation, VM or another host you control.

Copy [Caddyfile](Caddyfile), replace `mcp.example.com` with your hostname, and
run it using your Caddy installation's service. Keep the native listener on
`127.0.0.1:8787` and add the public authority to its arguments:

```bash
mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp \
  --transport http --bind 127.0.0.1:8787 \
  --token-file "$HOME/.config/ostadix-mcp/token" \
  --allowed-host mcp.example.com
```

For a nonstandard external port, allow the full authority, such as
`mcp.example.com:8443`. Add repeated `--allowed-host` flags for additional
names. If a browser-based client sends `Origin`, add its exact approved origin
using `--allowed-origin https://client.example.com`. An origin has a scheme and
authority, with no URL path. Host validation and Origin validation are
independent.

The proxy must preserve `Authorization`, `Host`, `Mcp-Session-Id` and
`MCP-Protocol-Version`; it must support streaming responses and the MCP POST,
GET and DELETE methods. The checked-in [Caddy reverse proxy
configuration](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
uses default header forwarding and immediate flushing. Do not add response
caching or an interactive browser login redirect in front of `/mcp`.

### Add `/mcp` to an existing nginx website

Keep the website's existing HTTPS `server` block, certificate, document root
and other locations. Add only this exact location inside that block, replacing
`8787` if the native listener uses another port:

```nginx
location = /mcp {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Connection "";
    proxy_pass_request_headers on;
    proxy_pass_request_body on;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    client_max_body_size 16m;
}
```

There is deliberately no trailing slash or URI after the upstream port:
nginx forwards `/mcp` unchanged. Header forwarding retains MCP session and
protocol headers; methods including POST, GET, DELETE and OPTIONS reach the
server unchanged. Buffering and caching are disabled for streaming, and
upstream retries are disabled. See the [nginx proxy module
reference](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).

Add `--allowed-host website.example.com` to the native service. Use the
connector URL `https://website.example.com/mcp` without a trailing slash.
Check inherited site rules for redirects or method restrictions affecting this
location. Validate the configuration before reloading the existing nginx
service; on a Linux host with systemd:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

The native `/healthz` can remain loopback-only; it need not replace any website
route. Recheck both the site's normal page and the MCP URL after reload.

### Persistent public URL with Tailscale Funnel

On a Tailscale-enrolled host with Funnel enabled, inspect existing routing
before choosing a port:

```bash
tailscale serve status --json
tailscale funnel status --json
```

This example reserves an **unused** Funnel HTTPS port `8443`, leaving an
existing website or Serve listener on `443` alone. If `8443` already has a
handler, select an unused allowed port (`443`, `8443` or `10000`), or integrate
with your existing proxy deliberately. Do not reset the Serve/Funnel
configuration or replace an occupied listener.
Serve/Funnel visibility applies to the whole port: enabling Funnel on an
existing private Serve port makes that port public. See [Funnel requirements
and limitations](https://tailscale.com/docs/features/tailscale-funnel#requirements-and-limitations).

Keep the authenticated native service on `127.0.0.1:8787`, and add
`--allowed-host node.example-tailnet.ts.net:8443` using the actual hostname
reported by Tailscale. Then configure the dedicated listener:

```bash
tailscale funnel --bg --https=8443 http://127.0.0.1:8787
tailscale funnel status
```

Use the reported URL with `/mcp` appended, for example
`https://node.example-tailnet.ts.net:8443/mcp`. `--bg` retains the Funnel
configuration across reboots; the Ostadix service must also be installed using
the service instructions below. Funnel is publicly reachable and does not
replace the MCP bearer token or OAuth gateway. See the [official Funnel CLI
reference](https://tailscale.com/docs/reference/tailscale-cli/funnel).

To remove only this dedicated listener:

```bash
tailscale funnel --bg --https=8443 off
```

### Use a different local port

If `8787` is occupied, choose a free loopback port, for example `18787`. Change
the server's `--bind` to `127.0.0.1:18787`, the proxy upstream to
`http://127.0.0.1:18787`, and every scheduled or manual updater restart command
to include `--health-url http://127.0.0.1:18787/healthz`. For example:

```bash
curl --fail http://127.0.0.1:18787/healthz
MCP_BASE="$HOME/.local/share/ostadix-mcp"
python3 "$MCP_BASE/state/current/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" update \
  --restart systemd-user --service-name ostadix-mcp-http \
  --health-url http://127.0.0.1:18787/healthz
```

Apply the same arguments in the copied systemd units or generated launchd
plists. The external URL and `--allowed-host` refer to the proxy's public
authority, not this internal port.

### Configure the chat client

Configure a remote MCP client with these values, using its own configuration
format:

| Setting | Value |
| --- | --- |
| Transport | Streamable HTTP / HTTP MCP |
| URL | `https://mcp.example.com/mcp` |
| Header, when the client supports custom headers | `Authorization: Bearer <contents of token file>` |

**Authentication compatibility:** this server implements bearer-token
authentication, not an OAuth authorization server. Chatbot connector UIs that
only support OAuth and no-auth cannot use a bearer token unless they expose a
custom-header option. For an authenticated OAuth-only UI such as ChatGPT's
custom connector flow, place a compatible MCP OAuth gateway in front of this
server and configure that gateway's issuer, client registration and token
validation. The gateway must authenticate before forwarding, and either
forward a configured backend bearer token or be the exclusive route to a
backend explicitly started with `--allow-unauthenticated`. Caddy by itself
does not add OAuth.

The no-auth option works with no-auth remote MCP clients only when the server
was explicitly started with `--allow-unauthenticated`; a publicly reachable
instance then allows anyone who can reach it to invoke its tools. There is no
claim that this one URL is accepted by every chatbot, account plan or client
transport version. The independent smoke proves the protocol endpoint, not a
specific chatbot's UI registration or a real public TLS deployment.

## Upgrade manually or regularly

The tracked updater builds each incoming Git commit in its own release
checkout, runs the native HTTP smoke, then switches a `current` symlink. It
does not pull, reset or replace your development checkout. A failed build or
smoke leaves the previous release selected. Credentials and scheduler files
live outside these release directories.

Prepare a stable controller checkout and an initial release under your own
account. This assumes the prerequisites were installed above:

```bash
MCP_BASE="$HOME/.local/share/ostadix-mcp"
mkdir -p "$MCP_BASE"
git clone https://github.com/lostadi/OSTADIX.git "$MCP_BASE/controller"
python3 "$MCP_BASE/controller/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" update \
  --repo https://github.com/lostadi/OSTADIX.git --branch master
```

The chosen repository and branch are retained in updater state. Use a branch
containing this feature: cloning an older branch or commit without the HTTP
setup files cannot install it. The updater needs network access to Git and to
uncached locked build dependencies. It executes code from the configured
repository and branch under your service account.

To launch that release manually, use the stable runner, which derives the
runtime/backends paths from the selected release:

```bash
python3 "$MCP_BASE/controller/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" run -- \
  --transport http --bind 127.0.0.1:8787 \
  --token-file "$HOME/.config/ostadix-mcp/token" \
  --allowed-host mcp.example.com
```

Check or upgrade on demand:

```bash
python3 "$MCP_BASE/state/current/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" check
python3 "$MCP_BASE/state/current/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" status
python3 "$MCP_BASE/state/current/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" update
```

A plain `update` changes the selected release; an already-running process
continues using its old release until restarted. With a registered service,
pass `--restart systemd-user --service-name ostadix-mcp-http` or
`--restart launchd --service-name com.ostadix.mcp-http`. To roll back, invoke
`rollback` with the same restart options. Keep sufficient disk space for
source trees, compiled artifacts and the previous working release.

When restarting a service, the updater checks
`http://127.0.0.1:8787/healthz` for readiness. Change `--health-url` if your
listener address or port differs. A failed restart/readiness check restores
the previous selection and attempts to restart that release.

Scheduled checks and the manual commands above run the updater from the
current verified release, so updater code advances along with server code.
The controller checkout remains the bootstrap and stable service-launcher
location. Refresh that checkout and its copied service templates deliberately
when their configuration changes:

```bash
git -C "$MCP_BASE/controller" pull --ff-only
```

### Linux: systemd user service and daily updates

Create the token and initial release first. Copy the three unit templates,
then edit `--allowed-host mcp.example.com` in the server unit and adjust the
Python path or `PATH` if your dependencies are elsewhere:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp "$MCP_BASE/controller/deployment/mcp/ostadix-mcp-http.service" \
   "$MCP_BASE/controller/deployment/mcp/ostadix-mcp-http-update.service" \
   "$MCP_BASE/controller/deployment/mcp/ostadix-mcp-http-update.timer" \
   "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now ostadix-mcp-http.service
systemctl --user enable --now ostadix-mcp-http-update.timer
systemctl --user list-timers ostadix-mcp-http-update.timer
```

The timer checks daily with up to 30 minutes of jitter, and catches up after
an inactive period using systemd's
[`Persistent` timer behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).
Updates restart the service only after promotion. To keep user services
running after logout, an administrator can enable lingering for the selected
account with `loginctl enable-linger USER`. The templates do not require root
for builds or Ostadix execution.

```bash
journalctl --user -u ostadix-mcp-http.service -f
journalctl --user -u ostadix-mcp-http-update.service
systemctl --user start ostadix-mcp-http-update.service
```

### macOS: launchd user service and daily updates

Create the token and initial release first. Materialize the two checked-in
plist templates with absolute paths and your hostname. `launchd` does not
expand shell variables in `ProgramArguments`, so the following uses Python's
plist writer rather than relying on textual XML replacements:

```bash
MCP_BASE="$HOME/.local/share/ostadix-mcp" MCP_HOST=mcp.example.com python3 - <<'PY'
import os, pathlib, plistlib, sys
home = pathlib.Path.home()
base = pathlib.Path(os.environ['MCP_BASE']).resolve()
values = {
    '__HOME__': str(home), '__BASE__': str(base),
    '__PYTHON__': sys.executable, '__HOST__': os.environ['MCP_HOST'],
    '__PATH__': os.environ['PATH'],
}
def replace(value):
    if isinstance(value, str):
        for token, replacement in values.items():
            value = value.replace(token, replacement)
        return value
    if isinstance(value, list):
        return [replace(item) for item in value]
    if isinstance(value, dict):
        return {key: replace(item) for key, item in value.items()}
    return value
destination = home / 'Library/LaunchAgents'
destination.mkdir(parents=True, exist_ok=True)
for name in ('com.ostadix.mcp-http', 'com.ostadix.mcp-http-update'):
    source = base / 'controller/deployment/mcp' / (name + '.plist')
    with source.open('rb') as stream:
        config = replace(plistlib.load(stream))
    with (destination / (name + '.plist')).open('wb') as stream:
        plistlib.dump(config, stream)
PY
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.ostadix.mcp-http.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.ostadix.mcp-http-update.plist"
```

The server runs in the logged-in user's GUI domain. The updater runs when
loaded and every 86,400 seconds while that agent is loaded; it does not wake a
powered-off Mac. For an always-on headless host, use an administrator-managed
launch daemon or a Linux service instead. Inspect `server.log` and `update.log`
under `$MCP_BASE`; logs are ordinary files and can be rotated by your chosen
host policy.

### Disable scheduling without removing the installed connector

On Linux:

```bash
systemctl --user disable --now ostadix-mcp-http-update.timer
```

On macOS:

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.ostadix.mcp-http-update.plist"
```

Leave the server service loaded if you want to keep using its current
release. Manual update, status and rollback commands remain available.

## Move the connector to another host or directory

Rebuild on the destination from the same source commit, using its own native
toolchain and backend dependencies. Do not copy only `ostadix-mcp`: it depends
on the matching runtime, scripts and `backends/`. A move between CPU
architectures or operating systems requires a native rebuild. Optional tools,
SDKs and project data also need to exist on the destination for the same
execution capabilities to remain available.

For a managed installation, record the repository, branch and selected commit
on the source host:

```bash
MCP_BASE="$HOME/.local/share/ostadix-mcp"
cat "$MCP_BASE/state/config.json"
git -C "$MCP_BASE/state/current" rev-parse HEAD
python3 "$MCP_BASE/state/current/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" status
```

Create a **fresh** managed state on the destination, after installing the host
requirements above. Set these values to the recorded repository, branch and
full commit ID, then build that exact release:

```bash
MCP_REPO=https://github.com/lostadi/OSTADIX.git
MCP_BRANCH=master
MCP_COMMIT=PASTE_RECORDED_FULL_COMMIT_ID
MCP_BASE="$HOME/.local/share/ostadix-mcp"
mkdir -p "$MCP_BASE"
git clone --branch "$MCP_BRANCH" "$MCP_REPO" "$MCP_BASE/controller"
python3 "$MCP_BASE/controller/scripts/update_ostadix_mcp_http.py" \
  --state-dir "$MCP_BASE/state" update \
  --repo "$MCP_REPO" --branch "$MCP_BRANCH" --commit "$MCP_COMMIT"
```

The commit must still be reachable from the configured branch. `--commit`
selects this installation's release; it does not permanently pin future
updates. Leave scheduled updates disabled until cutover is complete. An
unpinned update afterward follows the configured branch.

Do not move `state/` wholesale or edit its verification receipts to make it
appear portable. Receipts include the absolute verified release root, and Git
worktrees refer to the managed repository's paths. There is no state relocation
command. The same fresh-build procedure applies when changing the managed
base directory on one machine. Preserve the old installation for rollback
until the replacement is verified.

Provision the destination credential separately. Either generate a new token
with the earlier command and update the clients, or copy the existing token
over authenticated SSH to retain their current credentials. For example, on
the destination, after checking the source host's SSH identity:

```bash
mkdir -p "$HOME/.config/ostadix-mcp"
chmod 700 "$HOME/.config/ostadix-mcp"
scp -p old-user@old-host:.config/ostadix-mcp/token \
  "$HOME/.config/ostadix-mcp/token"
chmod 600 "$HOME/.config/ostadix-mcp/token"
```

Keep credentials outside Git and release trees. An OAuth gateway has its own
configuration and credentials to provision separately. Copy any required
projects and durable data through your normal backup or transfer process,
and update absolute project paths, environment variables and service-account
permissions. Tools invoked through the new URL operate on the new host.

Install the destination's systemd or launchd templates using the instructions
above. Regenerate paths rather than copying a plist with the old username or
Python executable. Update the service's token path, allowed hosts/origins,
listener port and the updater's matching `--health-url`; configure its proxy
without replacing existing website or Serve routes.

Before redirecting clients, check local `/healthz`, then use an MCP client
against the new HTTPS `/mcp` URL with the intended authentication. Verify
initialization, tool listing, `o_env` and `o_smoke`, and a representative tool
that uses the destination's required backend. Also check that the existing
website still loads. The build smoke starts a separate temporary local
server; it does not test the deployed proxy or public URL.

For a custom domain, provision HTTPS on the destination, test it, then switch
the domain's DNS/proxy destination. Keeping the same public hostname and token
keeps the client configuration stable. A new Tailscale node normally has its
own Funnel hostname: use the URL that node reports and update the clients
unless you have deliberately retained the original public route. Reconnect
clients and repeat the authenticated checks after the switch.

MCP sessions, intent handles and managed jobs cannot move between server
processes. Finish or explicitly cancel outstanding work before cutover; retain
its outputs separately and do not automatically replay calls whose completion
is unknown. Keep the old service available until the new endpoint passes its
checks, then stop the old service and its updater. Enable updates on the new
host when ready.

For an unmanaged source checkout, a fresh clone at the recorded commit plus
`bash scripts/setup_ostadix_mcp_http.sh --build-runtime` is the corresponding
migration and includes the local HTTP smoke. Point `O_LANG_ROOT`,
`O_BACKENDS_DIR`, `PATH` and service commands at the new checkout, and follow
the same credential, proxy and client checks. Copying prebuilt artifacts from
a different host is not a substitute for this verification.
