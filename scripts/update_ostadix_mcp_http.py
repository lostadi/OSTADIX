#!/usr/bin/env python3
"""Build pinned MCP releases without modifying the developer checkout.

Examples (Python 3.10+, Git, and preinstalled compiler/runtime dependencies):
  python3 scripts/update_ostadix_mcp_http.py --state-dir ~/.local/state/ostadix-mcp-http update --repo https://github.com/lostadi/OSTADIX --branch master
  python3 scripts/update_ostadix_mcp_http.py check
  python3 scripts/update_ostadix_mcp_http.py update --restart systemd-user
  python3 scripts/update_ostadix_mcp_http.py rollback --restart systemd-user
  python3 scripts/update_ostadix_mcp_http.py run -- --transport http --token-file /path/to/token

Schedule the update command using cron, a systemd timer, or launchd. No scheduler
is installed by this program. Without --restart, the current process continues
running its original release until restarted. Restarting ends in-memory MCP
sessions, intent handles, and managed jobs; schedule restarts while idle.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


SERVER = Path("mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp")
RECEIPT = ".ostadix-mcp-release.json"
SCHEMA = "ostadix.mcp-http-release/v1"
DEFAULT_HEALTH_URL = "http://127.0.0.1:8787/healthz"
RUNTIME_OVERRIDES = {
    "OLANG", "O_LANG_ROOT", "O_BACKENDS_DIR", "OSTADIX_O_INFO_BIN",
    "OSTADIX_O_CLI_BIN", "OSTADIX_OCTL_BIN",
}


class UpdateError(RuntimeError):
    pass


def command(argv: list[str], *, cwd: Path | None = None, capture: bool = True,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    # Repository selection comes exclusively from argv, never inherited Git state.
    for key in list(environment):
        if key.startswith("GIT_") and key != "GIT_TERMINAL_PROMPT":
            environment.pop(key)
    result = subprocess.run(argv, cwd=cwd, env=environment, text=True,
                            capture_output=capture, check=False)
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        raise UpdateError(f"{argv[0]} exited {result.returncode}: {detail}")
    return result


def git(repository: Path, *args: str, check: bool = True) -> str:
    return command(["git", "-C", str(repository), *args], check=check).stdout.strip()


def clear_runtime_overrides(environment: dict[str, str]) -> None:
    for key in list(environment):
        if key in RUNTIME_OVERRIDES or (key.startswith("O_LANG_") and key.endswith("_BIN")):
            environment.pop(key)


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def validate_remote(value: str) -> str:
    if not value or value.startswith("-") or any(c.isspace() for c in value):
        raise UpdateError("repository must be one Git URL or absolute local repository path")
    if Path(value).is_absolute():
        path = Path(value).resolve(strict=True)
        git(path, "rev-parse", "--git-dir")
        return str(path)
    parsed = urlsplit(value)
    if parsed.scheme in {"https", "http", "ssh", "git", "file"}:
        if parsed.password:
            raise UpdateError("do not embed passwords in the repository URL; configure Git credentials")
        if parsed.scheme != "file" and not parsed.hostname:
            raise UpdateError("repository URL is missing its hostname")
        return value
    if re.fullmatch(r"[^/@:\s]+@[^/:\s]+:[^\s]+", value):
        return value
    raise UpdateError("unsupported repository URL; use HTTPS, SSH, or an absolute local path")


@contextmanager
def update_lock(state: Path):
    if (state / "update.lock").is_symlink():
        raise UpdateError("update.lock must not be a symlink")
    with (state / "update.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise UpdateError("another update or rollback is already running") from error
        yield


def configure(state: Path, repo: str | None, branch: str | None) -> dict:
    path = state / "config.json"
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))
        if config.get("schema") != SCHEMA:
            raise UpdateError("unrecognized updater configuration")
        if repo and validate_remote(repo) != config["repo"]:
            raise UpdateError("repository differs from this deployment; use a separate state directory")
        if branch and branch != config["branch"]:
            raise UpdateError("branch differs from this deployment; use a separate state directory")
        return config
    if not repo or not branch:
        raise UpdateError("first check/update requires --repo and --branch")
    remote = validate_remote(repo)
    command(["git", "check-ref-format", f"refs/heads/{branch}"])
    if branch.startswith("-"):
        raise UpdateError("invalid branch name")
    if Path(remote).is_absolute() and state.is_relative_to(Path(remote)):
        raise UpdateError("state directory must be outside the source repository")
    config = {"schema": SCHEMA, "repo": remote, "branch": branch}
    write_json(path, config)
    return config


def fetch_candidate(state: Path, config: dict, commit: str | None) -> tuple[Path, str]:
    repository = state / "repository.git"
    if repository.is_symlink():
        raise UpdateError("managed repository must not be a symlink")
    if not repository.exists():
        command(["git", "init", "--bare", str(repository)])
        git(repository, "remote", "add", "origin", config["repo"])
    if git(repository, "rev-parse", "--is-bare-repository") != "true":
        raise UpdateError("managed repository is not bare")
    if git(repository, "remote", "get-url", "origin") != config["repo"]:
        raise UpdateError("managed origin differs from pinned deployment repository")
    branch_ref = f"refs/remotes/origin/{config['branch']}"
    git(repository, "fetch", "--no-tags", "origin",
        f"+refs/heads/{config['branch']}:{branch_ref}")
    selected = git(repository, "rev-parse", "--verify", f"{branch_ref}^{{commit}}")
    if commit:
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
            raise UpdateError("--commit must be a hexadecimal commit ID on the configured branch")
        selected = git(repository, "rev-parse", "--verify", f"{commit}^{{commit}}")
        ancestor = command(["git", "-C", str(repository), "merge-base", "--is-ancestor",
                            selected, branch_ref], check=False)
        if ancestor.returncode:
            raise UpdateError("selected commit is not in the fetched branch history")
    return repository, selected


def release_at(state: Path, name: str) -> Path | None:
    link = state / name
    if not link.is_symlink():
        if link.exists():
            raise UpdateError(f"{link} is not an updater symlink")
        return None
    release = link.resolve(strict=True)
    if release.parent != state / "releases":
        raise UpdateError(f"{name} points outside managed releases")
    validate_release(release)
    return release


def validate_release(release: Path) -> dict:
    receipt = json.loads((release / RECEIPT).read_text(encoding="utf-8"))
    if (receipt.get("schema") != SCHEMA or receipt.get("commit") != release.name
            or not receipt.get("http_smoke_passed") or receipt.get("verified_root") != str(release)):
        raise UpdateError(f"release is not verified: {release}")
    if not (release / SERVER).is_file() or not os.access(release / SERVER, os.X_OK):
        raise UpdateError(f"release executable is missing: {release / SERVER}")
    return receipt


def set_link(state: Path, name: str, release: Path | None) -> None:
    destination = state / name
    if destination.exists() and not destination.is_symlink():
        raise UpdateError(f"refusing to replace non-symlink {destination}")
    if release is None:
        destination.unlink(missing_ok=True)
        return
    temporary = state / f".{name}.{uuid.uuid4().hex}"
    temporary.symlink_to(release.relative_to(state), target_is_directory=True)
    os.replace(temporary, destination)


def restart_service(mode: str, name: str | None) -> None:
    if mode == "none":
        return
    service = name or ("com.ostadix.mcp-http" if mode == "launchd" else "ostadix-mcp-http.service")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", service):
        raise UpdateError("invalid service name")
    if mode == "launchd":
        command(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{service}"])
    elif mode == "systemd-user":
        command(["systemctl", "--user", "restart", service])
    else:
        command(["systemctl", "restart", service])


def health_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment
            or any(character.isspace() for character in value)):
        raise argparse.ArgumentTypeError("health URL must be an HTTP(S) URL without credentials or fragment")
    try:
        parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError("health URL has an invalid port") from error
    return value


def health_timeout(value: str) -> float:
    timeout = float(value)
    if not 0 < timeout <= 30:
        raise argparse.ArgumentTypeError("health timeout must be greater than zero and at most 30 seconds")
    return timeout


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wait_for_health(url: str, timeout: float) -> None:
    """Require the connector's own health response, with no redirect acceptance."""
    def probe(remaining: float, outcome: queue.Queue) -> None:
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(url, timeout=min(2.0, remaining)) as response:
                if response.status == 200 and response.read(1024) == b"ostadix-mcp ok\n":
                    outcome.put(None)
                else:
                    outcome.put("unexpected HTTP status or health response body")
        except (HTTPError, URLError, OSError) as error:
            outcome.put(str(error))

    deadline = time.monotonic() + timeout
    last_error = "no response"
    while (remaining := deadline - time.monotonic()) > 0:
        outcome: queue.Queue = queue.Queue(maxsize=1)
        # A daemon probe bounds DNS lookup and slow response bodies as well as
        # socket connect/read operations; none can extend this readiness wait.
        threading.Thread(target=probe, args=(remaining, outcome), daemon=True).start()
        try:
            result = outcome.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty:
            last_error = "health request exceeded readiness deadline"
            break
        if result is None:
            return
        last_error = result
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.25, remaining))
    raise UpdateError(f"server failed health check at {url}: {last_error}")


def activate(state: Path, candidate: Path, restart: str, service_name: str | None,
             health_url: str = DEFAULT_HEALTH_URL, health_timeout: float = 15.0) -> None:
    old = release_at(state, "current")
    previous = release_at(state, "previous")
    if candidate == old:
        return
    set_link(state, "previous", old)
    set_link(state, "current", candidate)
    try:
        restart_service(restart, service_name)
        if restart != "none":
            wait_for_health(health_url, health_timeout)
    except (UpdateError, OSError) as error:
        set_link(state, "current", old)
        set_link(state, "previous", previous)
        recovery = ""
        if old is not None:
            try:
                restart_service(restart, service_name)
                wait_for_health(health_url, health_timeout)
            except (UpdateError, OSError) as retry_error:
                recovery = f"; restarting the prior release also failed: {retry_error}"
        raise UpdateError(f"restart failed; release selection restored: {error}{recovery}") from error


def build_candidate(state: Path, repository: Path, commit: str) -> Path:
    release = state / "releases" / commit
    for directory in ("releases", "staging", "logs"):
        path = state / directory
        if path.is_symlink():
            raise UpdateError(f"managed {directory} directory must not be a symlink")
        path.mkdir(mode=0o700, exist_ok=True)
    if release.is_symlink():
        raise UpdateError("release directory must not be a symlink")
    if release.exists():
        validate_release(release)
        return release
    staging = state / "staging" / f"{commit}-{uuid.uuid4().hex}"
    git(repository, "worktree", "add", "--detach", str(staging), commit)
    owned_path = staging
    logs: dict[str, str] = {}
    try:
        for phase, root, option in (("build", staging, "--build-runtime"),
                                    ("relocated-verify", release, "--verify-only")):
            if phase == "relocated-verify":
                git(repository, "worktree", "move", str(staging), str(release))
                owned_path = release
            installer = root / "scripts/setup_ostadix_mcp_http.sh"
            if not installer.is_file():
                raise UpdateError("candidate has no portable MCP installer; publish the HTTP deployment changes first")
            environment = os.environ.copy()
            # Keep builds and setup inside the detached candidate. Never inherit
            # another checkout's root, target directory, or executable overrides.
            clear_runtime_overrides(environment)
            for key in list(environment):
                if key.startswith("GIT_") or key == "CARGO_TARGET_DIR":
                    environment.pop(key)
            environment["O_LANG_ROOT"] = str(root)
            environment["O_BACKENDS_DIR"] = str(root / "backends")
            log = state / "logs" / f"{commit}-{phase}-{uuid.uuid4().hex}.log"
            logs[phase] = str(log)
            with log.open("x", encoding="utf-8") as output:
                result = subprocess.run(["bash", str(installer), "--root", str(root), option],
                                        cwd=root, env=environment, stdout=output,
                                        stderr=subprocess.STDOUT, check=False)
            if result.returncode:
                raise UpdateError(f"candidate {phase}/HTTP smoke failed ({result.returncode}); log: {log}")
            if not os.access(root / SERVER, os.X_OK):
                raise UpdateError(f"installer succeeded without an executable MCP server; log: {log}")
            if git(root, "rev-parse", "HEAD") != commit or git(root, "diff", "--name-only", "HEAD"):
                raise UpdateError(f"installer changed tracked source files; log: {log}")
        receipt = {"schema": SCHEMA, "commit": commit,
                   "built_at": datetime.now(timezone.utc).isoformat(),
                   "http_smoke_passed": True, "verified_root": str(release), "logs": logs}
        write_json(release / RECEIPT, receipt)
        return release
    except BaseException:
        # Only the worktree created by this invocation is removed. Other releases
        # and the developer's checkout are never reset, cleaned, or overwritten.
        cleanup = command(["git", "-C", str(repository), "worktree", "remove", "--force", str(owned_path)],
                          check=False)
        if cleanup.returncode:
            print(f"failed candidate cleanup: {cleanup.stderr.strip()}", file=sys.stderr)
        raise


def update(args: argparse.Namespace, state: Path) -> dict:
    config = configure(state, args.repo, args.branch)
    repository, commit = fetch_candidate(state, config, args.commit)
    current = release_at(state, "current")
    result = {"current": current.name if current else None, "candidate": commit,
              "update_available": current is None or current.name != commit}
    if args.action == "check" or not result["update_available"]:
        return result
    if current and not args.allow_rewind:
        ancestry = command(["git", "-C", str(repository), "merge-base", "--is-ancestor",
                            current.name, commit], check=False)
        if ancestry.returncode:
            raise UpdateError("candidate rewinds/diverges from current release; use rollback or explicit --allow-rewind")
    candidate = build_candidate(state, repository, commit)
    activate(state, candidate, args.restart, args.service_name, args.health_url, args.health_timeout)
    result["current"] = commit
    result["restart"] = args.restart
    result["process_restart_required"] = args.restart == "none"
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    default_state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "ostadix-mcp-http"
    parser.add_argument("--state-dir", type=Path, default=default_state)
    actions = parser.add_subparsers(dest="action", required=True)
    for action in ("check", "update"):
        sub = actions.add_parser(action, help="fetch branch and report" if action == "check" else "build, smoke, then atomically select a release")
        sub.add_argument("--repo", help="Git remote URL (required on first use)")
        sub.add_argument("--branch", help="exact branch (required on first use)")
        sub.add_argument("--commit", help="optional commit ID within the branch history")
        if action == "update":
            sub.add_argument("--allow-rewind", action="store_true")
            add_restart_arguments(sub)
    add_restart_arguments(actions.add_parser("rollback", help="swap current and previous verified releases"))
    actions.add_parser("status", help="show selected releases without network access")
    runner = actions.add_parser("run", help="exec the selected server with its own runtime and backends")
    runner.add_argument("server_args", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def add_restart_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--restart", choices=("none", "systemd-user", "systemd", "launchd"), default="none",
                        help="explicit restart ends MCP sessions/jobs; default leaves the running process alone")
    parser.add_argument("--service-name", help="systemd unit or launchd label")
    parser.add_argument("--health-url", type=health_url, default=DEFAULT_HEALTH_URL,
                        help="public healthz URL to verify after an explicit service restart")
    parser.add_argument("--health-timeout", type=health_timeout, default=15.0,
                        help="readiness deadline in seconds, greater than zero and at most 30 (default: 15)")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = args.state_dir.expanduser().resolve()
    try:
        if args.action in {"update", "check"}:
            state.mkdir(mode=0o700, parents=True, exist_ok=True)
            with update_lock(state):
                result = update(args, state)
        elif args.action == "rollback":
            with update_lock(state):
                previous = release_at(state, "previous")
                if previous is None:
                    raise UpdateError("no previous verified release is available")
                activate(state, previous, args.restart, args.service_name, args.health_url, args.health_timeout)
                result = {"current": previous.name, "restart": args.restart,
                          "process_restart_required": args.restart == "none"}
        elif args.action == "status":
            result = {name: str(release_at(state, name) or "") for name in ("current", "previous")}
        else:
            release = release_at(state, "current")
            if release is None:
                raise UpdateError("no verified release selected; run update first")
            environment = os.environ.copy()
            clear_runtime_overrides(environment)
            environment.update(O_LANG_ROOT=str(release), O_BACKENDS_DIR=str(release / "backends"))
            environment["PATH"] = f"{release / 'target/release'}{os.pathsep}{environment.get('PATH', '')}"
            server_args = args.server_args[1:] if args.server_args[:1] == ["--"] else args.server_args
            os.chdir(release)
            os.execve(str(release / SERVER), [str(release / SERVER), *server_args], environment)
            return 0
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (UpdateError, OSError, ValueError, KeyError) as error:
        print(f"ostadix-mcp update: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
