#!/usr/bin/env python3
"""Exercise ostadix-mcp's real URL transport, isolation, and process cleanup.

Uses only Python's standard library and a loopback listener. No public endpoint,
external chatbot, or reverse proxy is required or claimed by this check.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlsplit


EXPECTED_TOOLS = {
    "o_analyze_intent", "o_capabilities", "o_cli", "o_doctor", "o_env",
    "o_eval", "o_execute", "o_execute_intent", "o_information_inspect",
    "o_guide", "o_job_cancel", "o_job_list", "o_job_read", "o_job_status",
    "o_job_write", "o_olangc", "o_operation", "o_run", "o_runtimes",
    "o_search_run", "o_smoke",
}
VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
ALLOWED_ORIGIN = "http://localhost:9876"
URL_RE = re.compile(r"http://127\.0\.0\.1:\d+/mcp")


class SmokeError(RuntimeError):
    """A live HTTP transport assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def content_text(result: dict[str, Any]) -> str:
    return "\n".join(
        block["text"] for block in result.get("content", [])
        if block.get("type") == "text" and isinstance(block.get("text"), str)
    )


def content_object(result: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed = json.loads(content_text(result))
    except (ValueError, TypeError) as error:
        raise SmokeError(f"tool did not return a JSON object: {result}") from error
    require(isinstance(parsed, dict), f"tool returned non-object content: {parsed}")
    require(result.get("structuredContent", parsed) == parsed,
            "structuredContent disagrees with the JSON text")
    return parsed


class Server:
    def __init__(self, binary: Path, root: Path, args: list[str], timeout: float):
        env = os.environ.copy()
        env.pop("OSTADIX_MCP_BEARER_TOKEN", None)
        env.update(O_LANG_ROOT=os.fspath(root), O_BACKENDS_DIR=os.fspath(root / "backends"))
        self.timeout = timeout
        self.logs: list[str] = []
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.process = subprocess.Popen(
            [os.fspath(binary), "--transport", "http", "--bind", "127.0.0.1:0", *args],
            cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        )
        self.reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.logs.append(line.rstrip())
            self.lines.put(line)
        self.lines.put(None)

    def ready(self) -> str:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                break
            match = URL_RE.search(line)
            if match:
                return match.group(0)
        raise SmokeError(f"HTTP server did not become ready:\n{self.diagnostics()}")

    def diagnostics(self) -> str:
        return "\n".join(self.logs[-40:])

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired as error:
                self.process.kill()
                self.process.wait()
                raise SmokeError("HTTP server did not finish graceful shutdown") from error
        self.reader.join(timeout=2)
        if self.process.stderr is not None:
            self.process.stderr.close()


class Client:
    def __init__(self, url: str, token: str | None, timeout: float):
        self.url = urlsplit(url)
        self.token = token
        self.timeout = timeout
        self.session: str | None = None
        self.version: str | None = None
        self.sequence = 0

    def request(
        self, method: str, payload: dict[str, Any] | None = None, *,
        path: str = "/mcp", headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        outgoing = {"Accept": "application/json, text/event-stream"}
        if self.token is not None:
            outgoing["Authorization"] = f"Bearer {self.token}"
        if self.session is not None:
            outgoing["MCP-Session-Id"] = self.session
        if self.version is not None:
            outgoing["MCP-Protocol-Version"] = self.version
        body = None
        if payload is not None:
            outgoing["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        outgoing.update(headers or {})
        connection_type = (http.client.HTTPSConnection if self.url.scheme == "https"
                           else http.client.HTTPConnection)
        connection = connection_type(self.url.hostname, self.url.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=outgoing)
            response = connection.getresponse()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            if "text/event-stream" in response_headers.get("content-type", ""):
                # Priming events contain only an id/retry or empty data. Stop at
                # this request's JSON-RPC reply instead of waiting for SSE EOF.
                data: list[bytes] = []
                value: Any = None
                while True:
                    line = response.readline()
                    if not line:
                        break
                    if line.rstrip(b"\r\n") == b"":
                        if data:
                            encoded = b"\n".join(data).strip()
                            data.clear()
                            if encoded:
                                candidate = json.loads(encoded)
                                if payload is None or candidate.get("id") == payload.get("id"):
                                    value = candidate
                                    break
                    elif line.startswith(b"data:"):
                        data.append(line[5:].lstrip(b" ").rstrip(b"\r\n"))
                require(value is not None, "SSE stream ended without the JSON-RPC reply")
            else:
                raw = response.read().decode("utf-8", "replace")
                try:
                    value = json.loads(raw) if raw else None
                except ValueError:
                    value = raw
            return response.status, response_headers, value
        finally:
            connection.close()

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.sequence += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self.sequence, "method": method}
        if params is not None:
            payload["params"] = params
        status, _, reply = self.request("POST", payload)
        require(status == 200, f"{method}: HTTP {status}: {reply}")
        require(isinstance(reply, dict) and reply.get("id") == self.sequence,
                f"{method}: invalid response identity: {reply}")
        require("error" not in reply, f"{method}: JSON-RPC error: {reply}")
        result = reply.get("result")
        require(isinstance(result, dict), f"{method}: no result object: {reply}")
        return result

    def initialize(self, requested: str) -> None:
        self.sequence += 1
        status, headers, reply = self.request("POST", {
            "jsonrpc": "2.0", "id": self.sequence, "method": "initialize",
            "params": {"protocolVersion": requested, "capabilities": {},
                       "clientInfo": {"name": "ostadix-http-smoke", "version": "1"}},
        })
        require(status == 200 and isinstance(reply, dict) and "error" not in reply,
                f"initialize {requested} failed: HTTP {status}: {reply}")
        result = reply.get("result", {})
        self.version = result.get("protocolVersion")
        expected = "2025-11-25" if requested == "2026-07-28" else requested
        require(self.version == expected, f"initialize {requested} negotiated {self.version}")
        self.session = headers.get("mcp-session-id")
        require(bool(self.session), "initialize did not return an MCP session ID")
        require({"tools", "resources"}.issubset(result.get("capabilities", {})),
                "initialize omitted tools/resources capabilities")
        status, _, reply = self.request("POST", {
            "jsonrpc": "2.0", "method": "notifications/initialized",
        })
        require(status == 202, f"initialized notification: HTTP {status}: {reply}")

    def tool(self, name: str, arguments: dict[str, Any] | None = None, *, error: bool = False) -> dict[str, Any]:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        require((result.get("isError") is True) == error,
                f"{name}: unexpected error flag: {content_text(result)}")
        return result

    def delete(self) -> None:
        status, _, reply = self.request("DELETE")
        require(status in (200, 202, 204), f"session DELETE failed: HTTP {status}: {reply}")


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_until(predicate: Any, timeout: float, message: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise SmokeError(message)


def background_job(client: Client, marker: Path, timeout: float) -> tuple[str, int, int]:
    source = (
        "python^(\nimport os, time\nfrom pathlib import Path\n"
        f"Path({os.fspath(marker)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(120)\n__oval_result__ = 'finished'\n)_python\n"
    )
    job = content_object(client.tool("o_eval", {"source": source, "background": True, "timeout_secs": 120}))
    require(isinstance(job.get("job_id"), str), f"background call omitted job ID: {job}")
    wait_until(marker.is_file, timeout, "background Python backend did not write its ready marker")
    status = content_object(client.tool("o_job_status", {"job_id": job["job_id"]}))
    require(status.get("state") == "running", f"background job is not running: {status}")
    pid = status.get("pid")
    require(isinstance(pid, int) and pid > 0, f"background job omitted native PID: {status}")
    backend_pid = int(marker.read_text())
    require(process_exists(pid) and process_exists(backend_pid), "job or backend was not alive before cleanup")
    return job["job_id"], pid, backend_pid


def run_smoke(root: Path, binary: Path, timeout: float) -> None:
    with tempfile.TemporaryDirectory(prefix="ostadix-http-smoke-") as temporary:
        fixture = Path(temporary)
        token = secrets.token_urlsafe(48)
        token_file = fixture / "token"
        token_file.write_text(token + "\n", encoding="ascii")
        token_file.chmod(0o600)

        for arguments, reason in (
            ([], "HTTP startup without authentication"),
            (["--token-file", os.fspath(token_file), "--allowed-origin", "https://example.com/"],
             "HTTP startup with a path in the allowed Origin"),
        ):
            rejected = Server(binary, root, arguments, timeout)
            try:
                try:
                    code = rejected.process.wait(timeout=10)
                except subprocess.TimeoutExpired as error:
                    raise SmokeError(f"{reason} was not rejected") from error
                require(code != 0, f"{reason} succeeded")
            finally:
                rejected.stop()

        unauthenticated = Server(binary, root, ["--allow-unauthenticated"], timeout)
        try:
            public = Client(unauthenticated.ready(), None, timeout)
            public.initialize(VERSIONS[-1])
            public.delete()
        finally:
            unauthenticated.stop()
        print("HTTP authentication startup policy: PASS", flush=True)

        server = Server(binary, root, ["--token-file", os.fspath(token_file),
                                      "--allowed-origin", ALLOWED_ORIGIN], timeout)
        child_pids: set[int] = set()
        try:
            url = server.ready()
            unauth = Client(url, None, timeout)
            status, _, health = unauth.request("GET", path="/healthz")
            require(status == 200, f"public health endpoint: HTTP {status}: {health}")
            status, cors, _ = unauth.request("OPTIONS", headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,mcp-session-id",
            })
            require(status in (200, 204) and cors.get("access-control-allow-origin") == ALLOWED_ORIGIN,
                    f"browser CORS preflight failed: HTTP {status}: {cors}")
            ping = {"jsonrpc": "2.0", "id": 999, "method": "ping"}
            for credential in (None, "invalid-" + token):
                status, _, _ = Client(url, credential, timeout).request("POST", ping)
                require(status == 401, f"missing/invalid bearer token returned HTTP {status}")
            probe = Client(url, token, timeout)
            status, _, _ = probe.request("POST", ping, headers={"Origin": "https://untrusted.example"})
            require(status == 403, f"forbidden Origin returned HTTP {status}")
            status, _, _ = probe.request("POST", ping, headers={"Origin": "http://localhost:9877"})
            require(status == 403, f"same-host Origin with a different port returned HTTP {status}")
            status, _, _ = probe.request("POST", ping, headers={"Host": "untrusted.example"})
            require(status in (403, 421), f"forbidden Host returned HTTP {status}")
            print("HTTP authentication, Host, Origin, CORS, and health: PASS", flush=True)

            clients: list[Client] = []
            for version in (*VERSIONS, "2026-07-28"):
                client = Client(url, token, timeout)
                client.initialize(version)
                clients.append(client)
            require(len({client.session for client in clients}) == len(clients), "MCP sessions reused an identity")
            client, other = clients[:2]
            status, _, reply = client.request("POST", ping, headers={"Origin": ALLOWED_ORIGIN})
            require(status == 200 and isinstance(reply, dict) and "error" not in reply,
                    f"allowed Origin did not work: HTTP {status}: {reply}")
            for headers, params in (
                ({"MCP-Protocol-Version": "2026-07-28"}, {}),
                ({}, {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}}),
            ):
                status, _, _ = client.request("POST", {**ping, "params": params}, headers=headers)
                require(status == 400, f"stateless protocol request returned HTTP {status}")
            print("HTTP protocol negotiation and stateful routing: PASS", flush=True)

            tools = client.rpc("tools/list").get("tools", [])
            require({tool.get("name") for tool in tools} == EXPECTED_TOOLS, "HTTP tool inventory changed")
            resources = client.rpc("resources/list").get("resources", [])
            require("ostadix://capabilities" in {resource.get("uri") for resource in resources},
                    "HTTP resource inventory omitted capabilities")
            client.tool("o_env")
            executed = content_object(client.tool("o_execute", {"source": "python^( __oval_result__ = 6 * 7 )_python\n"}))
            native = executed.get("result", {})
            require(native.get("value") == {"t": "number", "v": {"kind": "int", "v": "42"}},
                    f"HTTP o_execute did not produce native 42: {executed}")
            require(executed.get("exit_code") == 0 and executed.get("state") == "completed",
                    f"HTTP o_execute lost successful process evidence: {executed}")
            smoke = content_text(client.tool("o_smoke"))
            require("SMOKE_OK" in smoke and "2" in smoke, f"HTTP o_smoke did not report 2: {smoke}")
            print("HTTP 21 tools, resources, o_execute=42, o_smoke=2: PASS", flush=True)

            job_id, pid, backend_pid = background_job(client, fixture / "delete-ready", timeout)
            child_pids.update((pid, backend_pid))
            own_jobs = content_object(client.tool("o_job_list")).get("jobs", [])
            foreign_jobs = content_object(other.tool("o_job_list")).get("jobs", [])
            require(job_id in {job.get("job_id") for job in own_jobs}, "session lost its background job")
            require(job_id not in {job.get("job_id") for job in foreign_jobs}, "job leaked into another session")
            other.tool("o_job_status", {"job_id": job_id}, error=True)
            client.delete()
            wait_until(lambda: not process_exists(pid) and not process_exists(backend_pid), timeout,
                       "session DELETE left its native process or backend alive")
            child_pids.difference_update((pid, backend_pid))
            status, _, _ = client.request("POST", ping)
            require(status == 404, f"deleted session remained usable: HTTP {status}")
            print("HTTP job isolation, retained session state, and DELETE cleanup: PASS", flush=True)

            _, pid, backend_pid = background_job(other, fixture / "shutdown-ready", timeout)
            child_pids.update((pid, backend_pid))
            # A client may declare a body and then stall indefinitely. Keep
            # this authenticated socket open throughout shutdown so graceful
            # termination cannot depend on the client completing or closing it.
            with socket.create_connection((other.url.hostname, other.url.port), timeout=timeout) as incomplete:
                incomplete.sendall((
                    "POST /mcp HTTP/1.1\r\n"
                    f"Host: {other.url.hostname}:{other.url.port}\r\n"
                    f"Authorization: Bearer {token}\r\n"
                    "Content-Type: application/json\r\n"
                    "Accept: application/json, text/event-stream\r\n"
                    "Content-Length: 1000\r\n\r\n{"
                ).encode("ascii"))
                status, _, _ = unauth.request("GET", path="/healthz")
                require(status == 200, "incomplete request blocked the HTTP listener")
                server.stop()
                require(server.process.returncode == 0,
                        f"HTTP shutdown exited {server.process.returncode}: {server.diagnostics()}")
                wait_until(lambda: not process_exists(pid) and not process_exists(backend_pid), timeout,
                           "HTTP server shutdown left its native process or backend alive")
            child_pids.difference_update((pid, backend_pid))
            print("HTTP graceful shutdown with incomplete request and process cleanup: PASS", flush=True)
        except Exception as error:
            raise SmokeError(f"{error}\nServer stderr:\n{server.diagnostics()}") from error
        finally:
            server.stop()
            # Only our recorded fixture processes are eligible for emergency
            # cleanup if a regression leaves them alive after the assertion.
            for pid in child_pids:
                if process_exists(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--server", "--binary", type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    binary = (args.server or root / "mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp").expanduser().resolve()
    if not binary.is_file():
        print(f"error: MCP binary not found: {binary}", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        run_smoke(root, binary, args.timeout)
    except (SmokeError, OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("ostadix-mcp HTTP release smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
