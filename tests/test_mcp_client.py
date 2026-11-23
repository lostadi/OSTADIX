"""Real Unix socket/process tests for the persistent short-lived-client bridge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ostadix_mcp_client.py"
SPEC = importlib.util.spec_from_file_location("ostadix_mcp_client", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
client = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = client
SPEC.loader.exec_module(client)

FAKE_SERVER = r'''
import json, os, pathlib, sys, threading, time
root = pathlib.Path(__file__).parent
with (root / "launches").open("a") as output:
    output.write(str(os.getpid()) + "\n")
lock = threading.Lock()
jobs = set()
cancelled = set()
def publish_request_marker(name, request_id):
    temporary = root / ("." + name + "." + str(threading.get_ident()))
    temporary.write_text(str(request_id))
    temporary.replace(root / name)
def send(value):
    with lock:
        print(json.dumps(value), flush=True)
def handle(message):
    request_id = message.get("id")
    method = message.get("method")
    if method == "notifications/cancelled":
        cancelled.add(message["params"]["requestId"])
        publish_request_marker("cancelled", message["params"]["requestId"])
        return
    if request_id is None:
        return
    if method == "initialize":
        if (root / "fail-initialize").exists():
            send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": "fixture initialize failure"}})
            return
        result = {"protocolVersion": message["params"]["protocolVersion"], "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call":
        name = message["params"]["name"]
        args = message["params"].get("arguments", {})
        if name == "block":
            publish_request_marker("blocking", request_id)
            deadline = time.monotonic() + args.get("delay", 5)
            while time.monotonic() < deadline and request_id not in cancelled:
                time.sleep(0.01)
        if name in ("delay", "o_run"):
            time.sleep(args.get("seconds", 0.1))
        if name == "o_eval" and args.get("background"):
            time.sleep(args.get("delay", 0.1))
            jobs.add(args["job_id"])
        if name == "mutation":
            (root / "mutation").write_text("executed")
        if name == "large":
            (root / "large-received").write_text(str(len(args["payload"])))
            args = {"bytes": len(args["payload"])}
        if name == "stderr":
            sys.stderr.write("x" * (256 * 1024))
            sys.stderr.flush()
        if name == "background":
            jobs.add(args["job_id"])
        if name == "die":
            os._exit(7)
        value = {"pid": os.getpid(), "name": name, "args": args, "jobs": sorted(jobs)}
        result = {"content": [{"type": "text", "text": json.dumps(value)}], "structuredContent": value, "isError": name == "fail"}
    else:
        result = {}
    send({"jsonrpc": "2.0", "id": request_id, "result": result})
for line in sys.stdin:
    message = json.loads(line)
    if message.get("params", {}).get("name") == "stall_input":
        handle(message)
        time.sleep(message["params"]["arguments"].get("seconds", 1))
        continue
    threading.Thread(target=handle, args=(message,), daemon=True).start()
if (root / "slow-shutdown").exists():
    time.sleep(0.6)
(root / "shutdown").write_text("stdin-closed")
'''


@unittest.skipUnless(os.name == "posix", "the bridge uses local Unix sockets")
class InstallationConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="omcp-config-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.binary = self.home / ".local/bin/ostadix-mcp"
        self.binary.parent.mkdir(parents=True)

    def root(self, name):
        root = self.home / name
        for relative in ("Cargo.toml", "backends/python_shim.py", "examples/hello.O"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        return root.resolve()

    def configuration(self, **environment):
        with patch.dict(os.environ, environment, clear=True), patch.object(Path, "home", return_value=self.home), patch.object(Path, "cwd", return_value=self.home):
            return client.Configuration.from_environment()

    def test_metadata_root_and_backends_with_explicit_overrides_and_session_isolation(self):
        installed, explicit = self.root("installed"), self.root("explicit")
        backends = self.home / "installed-backends"
        backends.mkdir()
        (self.binary.parent / "ostadix-install.json").write_text(json.dumps({
            "schema": 1, "repo_root": str(installed), "backends_dir": str(backends),
        }))
        inferred = self.configuration()
        self.assertEqual(inferred.binary, self.binary)
        self.assertEqual(inferred.root, installed)
        self.assertEqual(inferred.backends, backends.resolve())
        overridden = self.configuration(O_LANG_ROOT=str(explicit))
        self.assertEqual(overridden.root, explicit)
        self.assertEqual(overridden.backends, explicit / "backends")
        self.assertNotEqual(inferred.key, overridden.key)
        self.assertEqual(self.configuration(O_BACKENDS_DIR=str(explicit / "backends")).backends,
                         explicit / "backends")

    def test_canonical_home_root_precedes_legacy_and_bad_metadata_falls_back(self):
        canonical, _legacy = self.root("OSTADIX"), self.root("Ostadix-lang")
        (self.binary.parent / "ostadix-install.json").write_text("invalid json")
        self.assertEqual(self.configuration().root, canonical)
        self.assertEqual(self.configuration().backends, canonical / "backends")


class PersistentBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = tempfile.TemporaryDirectory(prefix="omcp-", dir="/tmp")
        self.root = Path(self.fixture.name).resolve()
        self.backends = self.root / "backends"
        self.backends.mkdir()
        self.binary = self.root / "fake-mcp"
        self.binary.write_text(f"#!{sys.executable}\n" + FAKE_SERVER)
        self.binary.chmod(0o700)
        self.config = client.Configuration(self.binary, self.root, self.backends, self.root / "bridge")

    def tearDown(self) -> None:
        try:
            stopped = client._result(client.request("bridge/stop", config=self.config, start=False, timeout=2))
            pids = [stopped[key] for key in ("bridge_pid", "mcp_pid") if key in stopped]
            deadline = time.monotonic() + 10
            # The daemon unlinks its socket before reaping the MCP child. Wait
            # for both processes so the fixture cannot write during rmtree.
            while (self.config.socket_path.exists() or any(client._process_exists(pid) for pid in pids)) and time.monotonic() < deadline:
                time.sleep(0.025)
            self.assertFalse(self.config.socket_path.exists(), "bridge leaked after stop")
            self.assertFalse(any(client._process_exists(pid) for pid in pids), "bridge process leaked after stop")
        finally:
            self.fixture.cleanup()

    def call(self, name: str, args: dict | None = None, timeout: float = 5) -> dict:
        return client._result(client.request("tools/call", {"name": name, "arguments": args or {}}, timeout, config=self.config))

    def wait_file(self, name: str, timeout: float = 5) -> Path:
        path = self.root / name
        deadline = time.monotonic() + timeout
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(path.exists(), f"fixture omitted {name}")
        return path

    def test_separate_cli_processes_share_background_session(self) -> None:
        environment = self.config.environment()
        first = subprocess.run([sys.executable, str(SCRIPT), "background", '{"job_id":"retained"}'], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        second = subprocess.run([sys.executable, str(SCRIPT), "echo", "{}"], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        first_value = json.loads(first.stdout)["structuredContent"]
        second_value = json.loads(second.stdout)["structuredContent"]
        self.assertEqual(first_value["pid"], second_value["pid"])
        self.assertEqual(second_value["jobs"], ["retained"])
        self.assertEqual((self.root / "launches").read_text().count("\n"), 1)

    def test_simultaneous_startup_launches_only_one_mcp(self) -> None:
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda number: self.call("echo", {"number": number}), range(4)))
        self.assertEqual(len({result["structuredContent"]["pid"] for result in results}), 1)
        self.assertEqual((self.root / "launches").read_text().count("\n"), 1)

    def test_inflight_calls_route_out_of_order_without_serializing(self) -> None:
        self.call("echo")
        with ThreadPoolExecutor(max_workers=2) as executor:
            slow = executor.submit(self.call, "block", {"delay": 0.8})
            self.wait_file("blocking")
            fast = executor.submit(self.call, "echo", {"message": "fast"})
            self.assertEqual(fast.result(timeout=0.5)["structuredContent"]["args"], {"message": "fast"})
            self.assertFalse(slow.done())
            self.assertEqual(slow.result(timeout=2)["structuredContent"]["name"], "block")

    def test_disconnection_cancels_only_its_request(self) -> None:
        connection = client._ensure_connection(self.config)
        connection.sendall(client._json_line({"method": "tools/call", "params": {"name": "block", "arguments": {"delay": 5}}, "timeout": 0}))
        active = self.wait_file("blocking").read_text()
        connection.close()
        self.assertEqual(self.wait_file("cancelled").read_text(), active)
        self.assertEqual(self.call("echo")["structuredContent"]["name"], "echo")

    def test_timeout_returns_error_and_cancellation_without_stderr_wait(self) -> None:
        self.call("stderr")
        started = time.monotonic()
        with self.assertRaisesRegex(client.BridgeError, "timed out"):
            self.call("block", {"delay": 5}, timeout=0.15)
        self.assertLess(time.monotonic() - started, 1.5)
        self.wait_file("cancelled")
        self.assertGreater((self.config.directory / f"{self.config.key}.stderr.log").stat().st_size, 200_000)
        self.assertEqual(self.call("echo")["structuredContent"]["name"], "echo")

    def test_nonreading_child_cannot_block_status_timeout_or_shutdown(self) -> None:
        self.call("stall_input", {"seconds": 10})
        started = time.monotonic()
        with self.assertRaisesRegex(client.BridgeError, "execution_uncertain"):
            self.call("large", {"payload": "x" * (2 * 1024 * 1024)}, timeout=0.2)
        status = client._result(client.request("bridge/status", config=self.config))
        self.assertTrue(status["running"])
        self.assertLess(time.monotonic() - started, 1.5)
        stopped = subprocess.run([sys.executable, str(SCRIPT), "--stop"], env=self.config.environment(), capture_output=True, text=True, timeout=10)
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertLess(time.monotonic() - started, 9)

    def test_timed_out_queued_mutation_is_never_sent_later(self) -> None:
        self.call("stall_input", {"seconds": 1})
        with self.assertRaisesRegex(client.BridgeError, "execution_uncertain"):
            self.call("large", {"payload": "x" * (2 * 1024 * 1024)}, timeout=0.15)
        with self.assertRaisesRegex(client.BridgeError, "cancelled_before_send"):
            self.call("mutation", timeout=0.15)
        self.wait_file("large-received")
        self.call("echo")
        self.assertFalse((self.root / "mutation").exists())

    def test_background_request_survives_disconnect_before_response(self) -> None:
        connection = client._ensure_connection(self.config)
        connection.sendall(client._json_line({"method": "tools/call", "params": {"name": "o_eval", "arguments": {"background": True, "job_id": "recoverable", "delay": 0.2}}, "timeout": 5}))
        connection.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if "recoverable" in self.call("echo")["structuredContent"]["jobs"]:
                break
            time.sleep(0.025)
        else:
            self.fail("background job disappeared with its short-lived caller")
        self.assertFalse((self.root / "cancelled").exists())

    def test_tool_error_and_raw_tool_catalog_are_preserved(self) -> None:
        result = self.call("fail")
        self.assertTrue(json.loads(client._render_tool(result))["isError"])
        catalog = client._result(client.request("tools/list", config=self.config))
        self.assertEqual(catalog["tools"][0]["name"], "echo")

    def test_explicit_unbounded_cli_and_tool_timeouts_complete(self) -> None:
        for flags, args in (
            (["--timeout", "0"], {"seconds": 0.15}),
            ([], {"seconds": 0.15, "timeout_secs": 0}),
        ):
            with self.subTest(flags=flags, args=args):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), *flags, "delay", json.dumps(args)],
                    env=self.config.environment(), capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["structuredContent"]["args"], args)

    def test_mcp_exit_does_not_leave_requests_waiting(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(client.BridgeError, "transport closed"):
            self.call("die", timeout=5)
        self.assertLess(time.monotonic() - started, 2)

    def test_stop_closes_mcp_stdin_and_reaps_the_child(self) -> None:
        status = client._result(client.request("bridge/status", config=self.config))
        result = subprocess.run([sys.executable, str(SCRIPT), "--stop"], env=self.config.environment(), capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)["stopped"])
        self.assertEqual(self.wait_file("shutdown").read_text(), "stdin-closed")
        with self.assertRaises(ProcessLookupError):
            os.kill(status["mcp_pid"], 0)

    def test_execution_defaults_do_not_inherit_transport_cutoff(self) -> None:
        # Compress the old fallback so the real socket/daemon regression runs
        # quickly; the native execution takes longer than that fallback.
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(client, "DEFAULT_TRANSPORT_TIMEOUT", 0.05), \
                patch.object(client.Configuration, "from_environment", return_value=self.config):
            for fields in ({}, {"timeout_secs": None}, {"timeout_secs": 0}):
                with self.subTest(fields=fields):
                    result = json.loads(client.call_tool("o_run", {"seconds": 0.15, **fields}))
                    self.assertFalse(result["isError"], result)
                    self.assertEqual(result["structuredContent"]["name"], "o_run")
            result = client._result(client.request(
                "tools/call", {"name": "o_run", "arguments": {"seconds": 0.15}},
                config=self.config,
            ))
            self.assertFalse(result["isError"], result)

    def test_explicit_environment_timeout_still_cancels_unbounded_execution(self) -> None:
        with patch.dict(os.environ, {"OSTADIX_MCP_CLIENT_TIMEOUT": "0.05"}, clear=True), \
                patch.object(client.Configuration, "from_environment", return_value=self.config):
            result = json.loads(client.call_tool("o_run", {"seconds": 0.3, "timeout_secs": 0}))
            self.assertTrue(result["isError"], result)
            self.assertIn("timed out after 0.05s", result["error"])
            self.wait_file("cancelled")

    def test_private_paths_and_instance_identity(self) -> None:
        self.call("echo")
        self.assertEqual(self.config.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.config.socket_path.stat().st_mode & 0o777, 0o700)
        changed = client.Configuration(self.binary, self.root, self.root / "other-backends", self.config.directory)
        self.assertNotEqual(self.config.key, changed.key)
        for path in self.config.directory.glob("*.log"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_old_shutdown_cannot_unlink_a_replacement_socket(self) -> None:
        old = self.call("echo")["structuredContent"]["pid"]
        (self.root / "slow-shutdown").touch()
        client.request("bridge/stop", config=self.config)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            connection = client._connect(self.config)
            if connection is None:
                break
            connection.close()
            time.sleep(0.01)
        else:
            self.fail("old listener did not close during shutdown")
        new = self.call("echo")["structuredContent"]["pid"]
        self.assertNotEqual(old, new)
        self.wait_file("shutdown")
        time.sleep(0.15)
        self.assertEqual(self.call("echo")["structuredContent"]["pid"], new)
        self.assertEqual((self.root / "launches").read_text().count("\n"), 2)

    def test_replacement_during_child_reap_survives_recycled_socket_identity(self) -> None:
        """Force the inode collision instead of depending on filesystem reuse."""
        bridge = client.StdioBridge(self.config)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        self.addCleanup(replacement.close)
        socket_identity = None
        replaced = False
        close_lock_held = []
        real_lstat = Path.lstat
        real_popen = subprocess.Popen
        lock_path = self.config.directory / f"{self.config.key}.lock"

        def bind(path):
            nonlocal socket_identity
            listener.bind(path)
            metadata = real_lstat(self.config.socket_path)
            socket_identity = (metadata.st_dev, metadata.st_ino)

        def close():
            with client._private_file(lock_path) as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    close_lock_held.append(True)
                else:
                    close_lock_held.append(False)
            listener.close()

        def accept():
            bridge.stopping.set()
            raise socket.timeout()

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            wait = process.wait

            def reap(*wait_args, **wait_kwargs):
                nonlocal replaced
                if not replaced:
                    # Model a new startup as soon as the old listener closes,
                    # while its child is still waiting to finish shutdown.
                    with client._private_file(lock_path) as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        client._remove_stale_socket(self.config)
                        replacement.bind(str(self.config.socket_path))
                        replacement.listen(1)
                        replaced = True
                return wait(*wait_args, **wait_kwargs)

            process.wait = reap
            return process

        def lstat(path, *args, **kwargs):
            metadata = real_lstat(path, *args, **kwargs)
            if replaced and path == self.config.socket_path:
                # A replacement Unix pathname inode may equal the removed
                # inode.  Make that collision deterministic for this lifecycle.
                return SimpleNamespace(st_dev=socket_identity[0], st_ino=socket_identity[1])
            return metadata

        wrapped_listener = Mock(wraps=listener)
        wrapped_listener.bind.side_effect = bind
        wrapped_listener.close.side_effect = close
        wrapped_listener.accept.side_effect = accept
        with patch.object(client.socket, "socket", return_value=wrapped_listener), \
                patch.object(client.subprocess, "Popen", side_effect=popen), \
                patch.object(Path, "lstat", lstat):
            bridge.run()
        self.assertTrue(replaced)
        self.assertTrue(self.config.socket_path.exists(), "old cleanup removed the replacement")
        self.assertEqual(close_lock_held, [True], "listener close must share startup ownership")
        # The replacement remains reachable after all old-child cleanup ended.
        with client._connect(self.config) as connection:
            self.assertIsNotNone(connection)
        self.config.socket_path.unlink()

    def test_initialize_failure_exits_without_waiting_for_startup_lock(self) -> None:
        (self.root / "fail-initialize").touch()
        started = time.monotonic()
        with self.assertRaisesRegex(client.BridgeError, "MCP bridge exited"):
            client._ensure_connection(self.config)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(self.config.socket_path.exists())
        (self.root / "fail-initialize").unlink()
        self.assertEqual(self.call("echo")["structuredContent"]["name"], "echo")

    def test_startup_timeout_releases_lock_before_waiting_for_daemon(self) -> None:
        def reap(**_kwargs):
            with client._private_file(self.config.directory / f"{self.config.key}.lock") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return 0

        daemon = Mock()
        daemon.poll.return_value = None
        daemon.wait.side_effect = reap
        with patch.object(client, "STARTUP_TIMEOUT", 0.05), \
                patch.object(client.subprocess, "Popen", return_value=daemon):
            with self.assertRaisesRegex(client.BridgeError, "timed out starting"):
                client._ensure_connection(self.config)
        daemon.terminate.assert_called_once()
        daemon.wait.assert_called_once_with(timeout=2)


class BridgeFormattingTests(unittest.TestCase):
    def test_default_transport_timeout_covers_requested_tool_timeout(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(client._tool_timeout({"timeout_secs": 3600}, None), 3630)
            self.assertEqual(client._tool_timeout({"timeout_secs": 30}, None), 600)
            self.assertEqual(client._tool_timeout({"timeout_secs": 3600}, 10), 10)
            self.assertEqual(client._tool_timeout({"timeout_secs": 0}, None), 0)
            self.assertEqual(client._tool_timeout({"timeout_secs": 30}, 0), 0)
            self.assertEqual(client._tool_timeout({"timeout_secs": 0}, 10), 10)

    def test_execution_tools_are_unbounded_for_omitted_null_and_zero_deadlines(self) -> None:
        tools = ("o_execute", "o_cli", "o_eval", "o_operation", "o_run", "o_olangc",
                 "o_analyze_intent", "o_execute_intent", "o_search_run",
                 "o_lean_check", "o_lean_verify")
        with patch.dict(os.environ, {}, clear=True):
            for tool in tools:
                for fields in ({}, {"timeout_secs": None}, {"timeout_secs": 0}):
                    for background in (False, True):
                        with self.subTest(tool=tool, fields=fields, background=background):
                            arguments = {"background": background, **fields}
                            self.assertEqual(client._tool_timeout(arguments, None, tool), 0)
                            self.assertEqual(client._request_timeout(
                                "tools/call", {"name": tool, "arguments": arguments}, None,
                            ), 0)
            self.assertEqual(client._tool_timeout({}, None, "o_env"), 600)
            self.assertEqual(client._request_timeout("tools/list", {}, None), 600)
            for fields in ({}, {"timeout_secs": None}, {"timeout_secs": 0}):
                self.assertEqual(client._tool_timeout({"mode": "formal", **fields}, None, "o_claim"), 0)
            self.assertEqual(client._tool_timeout({"mode": "citation"}, None, "o_claim"), 600)

    def test_explicit_client_deadlines_override_native_and_environment_defaults(self) -> None:
        with patch.dict(os.environ, {"OSTADIX_MCP_CLIENT_TIMEOUT": "15"}, clear=True):
            for requested in (None, 0, 3600):
                arguments = {"timeout_secs": requested}
                self.assertEqual(client._tool_timeout(arguments, None, "o_run"), 15)
                self.assertEqual(client._tool_timeout(arguments, 10, "o_run"), 10)
                self.assertEqual(client._tool_timeout(arguments, 0, "o_run"), 0)
        with patch.dict(os.environ, {"OSTADIX_MCP_CLIENT_TIMEOUT": "0"}, clear=True):
            self.assertEqual(client._tool_timeout({"timeout_secs": 30}, None, "o_run"), 0)

    def test_legacy_text_success_remains_text(self) -> None:
        self.assertEqual(client._render_tool({"content": [{"type": "text", "text": "SMOKE_OK"}], "isError": False}), "SMOKE_OK")

    def test_timeout_rejects_nan_infinity_negative_and_boolean(self) -> None:
        self.assertEqual(client._positive_timeout(0), 0)
        for value in (-1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(client.BridgeError):
                client._positive_timeout(value)


class RequestProgressTests(unittest.TestCase):
    def test_elapsed_and_distinct_requested_countdowns(self):
        self.assertEqual(
            client._progress_text("o_run", 3661.9, None, None),
            "[o_run] request elapsed 01:01:01 | no execution timeout",
        )
        value = client._progress_text("o_run", 1.2, 5, 3)
        self.assertIn("operation remaining ~00:00:04 (request clock)", value)
        self.assertIn("client remaining ~00:00:02 (request clock)", value)
        self.assertIn("remaining ~00:00:00", client._progress_text("o_run", 8, 5, None))
        with patch.dict(os.environ, {}, clear=True):
            for arguments in ({}, {"timeout_secs": None}, {"timeout_secs": 0}):
                progress = client._RequestProgress("o_run", arguments, None, False, io.StringIO())
                self.assertIsNone(progress.operation_timeout)
                self.assertIsNone(progress.client_timeout)
        with patch.dict(os.environ, {"OSTADIX_MCP_CLIENT_TIMEOUT": "5"}, clear=True):
            progress = client._RequestProgress("o_run", {"timeout_secs": 30}, None, False, io.StringIO())
            self.assertEqual(progress.operation_timeout, 30)
            self.assertEqual(progress.client_timeout, 5)
            overridden = client._RequestProgress("o_run", {}, 0, False, io.StringIO())
            self.assertIsNone(overridden.client_timeout)

    def test_cli_timer_uses_stderr_and_preserves_stdout_envelope(self):
        result = {"content": [], "structuredContent": {"answer": 42}, "isError": False}

        def complete(*args, **kwargs):
            time.sleep(0.04)
            return {"result": result}

        with patch.dict(os.environ, {}, clear=True), \
                patch.object(client.Configuration, "from_environment", return_value=Mock()), \
                patch.object(client, "PROGRESS_INTERVAL", 0.01), \
                patch.object(client, "request", side_effect=complete):
            for flags, terminal, expected in (([], False, False), ([], True, True),
                                               (["--progress"], False, True),
                                               (["--no-progress"], True, False)):
                with self.subTest(flags=flags, terminal=terminal), tempfile.TemporaryFile(mode="w+") as stderr:
                    stdout = io.StringIO()
                    stderr.isatty = lambda: terminal
                    with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                        self.assertEqual(client.main([*flags, "o_run", "{}"]), 0)
                    self.assertEqual(json.loads(stdout.getvalue()), result)
                    stderr.seek(0)
                    output = stderr.read()
                    if expected:
                        self.assertGreaterEqual(output.count("request elapsed"), 2)
                    else:
                        self.assertEqual(output, "")

    def test_timer_stops_on_success_error_and_keyboard_interrupt(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(client, "PROGRESS_INTERVAL", 0.01):
            for error in (None, client.BridgeError("failed"), KeyboardInterrupt()):
                with self.subTest(error=type(error).__name__), tempfile.TemporaryFile(mode="w+") as stream:
                    progress = client._RequestProgress("o_run", {}, None, True, stream)
                    try:
                        with progress:
                            time.sleep(0.03)
                            if error is not None:
                                raise error
                    except BaseException as caught:
                        self.assertIs(caught, error)
                    else:
                        self.assertIsNone(error, "the progress context swallowed the request exception")
                    self.assertTrue(progress.stopped.is_set())
                    self.assertIsNotNone(progress.thread)
                    self.assertFalse(progress.thread.is_alive())
                    stream.seek(0)
                    completed = stream.read()
                    time.sleep(0.02)
                    stream.seek(0)
                    self.assertEqual(stream.read(), completed)

    def test_failed_progress_stream_does_not_mask_request_error(self):
        stream = Mock()
        stream.fileno.side_effect = OSError("stderr closed")
        with patch.dict(os.environ, {}, clear=True):
            progress = client._RequestProgress("o_run", {}, None, True, stream)
            with self.assertRaisesRegex(client.BridgeError, "request failure"):
                with progress:
                    raise client.BridgeError("request failure")
            self.assertIsNone(progress.thread)

    @unittest.skipUnless(os.name == "posix", "uses POSIX pipe descriptors")
    def test_full_stderr_pipe_does_not_block_cli_result_or_interrupt(self):
        program = r'''
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("progress_fixture", sys.argv[1])
client = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = client
spec.loader.exec_module(client)
client.Configuration.from_environment = lambda: None
def request(*args, **kwargs):
    time.sleep(0.05)
    if sys.argv[2] == "error":
        raise client.BridgeError("fixture failure")
    if sys.argv[2] == "interrupt":
        raise KeyboardInterrupt()
    return {"result": {"content": [], "structuredContent": {"answer": 42}, "isError": False}}
client.request = request
try:
    status = client.main(["--progress", "o_run", "{}"])
except KeyboardInterrupt:
    print(json.dumps({"interrupted": True}))
    status = 0
raise SystemExit(status)
'''
        for outcome in ("success", "error", "interrupt"):
            with self.subTest(outcome=outcome):
                reader, writer = os.pipe()
                try:
                    os.set_blocking(writer, False)
                    while True:
                        try:
                            os.write(writer, b"x" * 4096)
                        except BlockingIOError:
                            break
                    os.set_blocking(writer, True)
                    original_flags = fcntl.fcntl(writer, fcntl.F_GETFL)
                    result = subprocess.run(
                        [sys.executable, "-c", program, str(SCRIPT), outcome],
                        stdout=subprocess.PIPE, stderr=writer, text=True, timeout=3,
                    )
                    self.assertEqual(fcntl.fcntl(writer, fcntl.F_GETFL), original_flags)
                    value = json.loads(result.stdout)
                    if outcome == "success":
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(value["structuredContent"]["answer"], 42)
                    elif outcome == "error":
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(value["error"], "fixture failure")
                    else:
                        self.assertEqual(result.returncode, 0)
                        self.assertTrue(value["interrupted"])
                finally:
                    os.close(writer)
                    os.close(reader)

    def test_call_tool_api_does_not_create_cli_progress(self):
        result = {"content": [{"type": "text", "text": "done"}], "isError": False}
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(client, "_RequestProgress", side_effect=AssertionError("CLI only")), \
                patch.object(client, "request", return_value={"result": result}):
            self.assertEqual(client.call_tool("o_run", {}), "done")

    def test_stalled_raw_progress_write_cannot_delay_request_cleanup(self):
        entered, release = client.threading.Event(), client.threading.Event()

        def stalled_write(*args):
            entered.set()
            release.wait(2)
            return 0

        with tempfile.TemporaryFile(mode="w+") as stream, \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(client.os, "write", side_effect=stalled_write):
            progress = client._RequestProgress("o_run", {}, None, True, stream)
            try:
                with self.assertRaisesRegex(client.BridgeError, "original failure"):
                    with progress:
                        self.assertTrue(entered.wait(1), "progress worker never attempted its write")
                        started = time.monotonic()
                        raise client.BridgeError("original failure")
                self.assertLess(time.monotonic() - started, 0.3)
            finally:
                release.set()
                progress.thread.join(timeout=1)
            self.assertFalse(progress.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
