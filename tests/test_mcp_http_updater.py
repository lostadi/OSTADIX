"""Release switching tests with local Git fixtures and a fake installer.

These tests exercise update isolation, failure handling, and rollback. Native
MCP HTTP behavior belongs to smoke_ostadix_mcp_http.py; no compiler or external
network is used by this test suite.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/update_ostadix_mcp_http.py"
SPEC = importlib.util.spec_from_file_location("mcp_http_updater", SCRIPT)
assert SPEC and SPEC.loader
updater = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = updater
SPEC.loader.exec_module(updater)

ALIASES_SCRIPT = SCRIPT.with_name("mcp_http_runtime_aliases.py")
ALIASES_SPEC = importlib.util.spec_from_file_location("mcp_http_runtime_aliases", ALIASES_SCRIPT)
assert ALIASES_SPEC and ALIASES_SPEC.loader
aliases = importlib.util.module_from_spec(ALIASES_SPEC)
sys.modules[ALIASES_SPEC.name] = aliases
ALIASES_SPEC.loader.exec_module(aliases)


class RuntimeAliasTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name).resolve()
        for name, content in (("O", b"raw evaluator\n"), ("o-cli", b"native command front door\n")):
            path = self.build / name
            path.write_bytes(content)
            path.chmod(0o755)

    def test_actual_filesystem_preserves_evaluator_and_selects_front_door(self) -> None:
        shared_name = aliases.case_insensitive_directory(self.build)
        command = aliases.create_runtime_aliases(self.build)
        self.assertEqual((self.build / "O").read_bytes(), b"raw evaluator\n")
        self.assertEqual((self.build / "ostadix-evaluator").read_bytes(), b"raw evaluator\n")
        self.assertEqual((self.build / command).read_bytes(), b"native command front door\n")
        self.assertEqual(command, "o-cli" if shared_name else "o")
        self.assertEqual(sorted(path.name for path in self.build.glob(".ostadix-case-*")), [])

    def test_case_sensitive_metadata_creates_separate_lowercase_cli_alias(self) -> None:
        copies = []
        # Emulate distinct inodes for upper/lower spellings, as on ordinary
        # Linux filesystems, even when this test runs on case-insensitive APFS.
        with patch.object(Path, "samefile", return_value=False), patch.object(
            aliases, "atomic_copy", side_effect=lambda source, target: copies.append(
                (target.name, source.read_bytes())
            )
        ):
            command = aliases.create_runtime_aliases(self.build)
        self.assertEqual(command, "o")
        self.assertEqual(copies, [
            ("ostadix-evaluator", b"raw evaluator\n"),
            ("o", b"native command front door\n"),
        ])

    def test_case_insensitive_metadata_never_replaces_shared_evaluator_name(self) -> None:
        with patch.object(Path, "samefile", return_value=True):
            self.assertEqual(aliases.create_runtime_aliases(self.build), "o-cli")
        self.assertEqual((self.build / "O").read_bytes(), b"raw evaluator\n")
        self.assertEqual((self.build / "ostadix-evaluator").read_bytes(), b"raw evaluator\n")

    def installer_fixture(self) -> tuple[Path, dict[str, str]]:
        root = self.build / "checkout with spaces"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        for name in ("setup_ostadix_mcp_http.sh", "mcp_http_runtime_aliases.py"):
            shutil.copyfile(SCRIPT.with_name(name), scripts / name)
        for name in ("Cargo.toml", "Cargo.lock", "backends/python_shim.py",
                     "mcp/ostadix_lang_mcp_server/Cargo.toml",
                     "mcp/ostadix_lang_mcp_server/Cargo.lock"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.97.1"\n')
        (scripts / "smoke_ostadix_mcp_http.py").write_text(textwrap.dedent('''\
            import argparse
            from pathlib import Path
            parser = argparse.ArgumentParser()
            parser.add_argument("--root"); parser.add_argument("--server")
            args = parser.parse_args()
            build = Path(args.root) / "target/release"
            assert (build / "O").read_bytes() == b"raw evaluator\\n"
            assert (build / "ostadix-evaluator").read_bytes() == b"raw evaluator\\n"
            assert (build / "o-cli").read_bytes() == b"native command front door\\n"
            assert Path(args.server).is_file()
            print("fixture HTTP smoke preserved evaluator")
        '''))
        (scripts / "smoke_ostadix_mcp_oauth.py").write_text(
            (scripts / "smoke_ostadix_mcp_http.py").read_text()
        )
        tools = self.build / "fake-tools"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text(textwrap.dedent('''\
            #!/usr/bin/env python3
            from pathlib import Path
            import json, os, sys
            args = sys.argv[1:]
            assert args[0] == "+1.97.1" and "--locked" in args
            build = Path(args[args.index("--target-dir") + 1]) / "release"
            build.mkdir(parents=True, exist_ok=True)
            (build / "deps").mkdir(exist_ok=True)
            (build / "deps/uncopied-intermediate").write_text("compiler intermediate")
            with open(os.environ["MCP_FAKE_CARGO_LOG"], "a") as log:
                log.write(json.dumps(str(build.parent)) + "\\n")
            bins = [args[index + 1] for index, value in enumerate(args) if value == "--bin"]
            for name in bins or ["ostadix-mcp"]:
                executable = build / name
                content = {"O": b"raw evaluator\\n", "o-cli": b"native command front door\\n"}.get(name, b"fixture executable\\n")
                executable.write_bytes(content)
                executable.chmod(0o755)
        '''))
        cargo.chmod(0o755)
        environment = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}")
        environment.pop("OSTADIX_MCP_BUILD_CACHE", None)
        environment["MCP_FAKE_CARGO_LOG"] = str(self.build / "cargo-targets.jsonl")
        return root, environment

    def run_installer(self, root: Path, environment: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
        outcome = subprocess.run(
            ["bash", str(root / "scripts/setup_ostadix_mcp_http.sh"), "--root", str(root), *args],
            cwd=self.build, env=environment, capture_output=True, text=True,
        )
        self.assertEqual(outcome.returncode, 0, outcome.stdout + outcome.stderr)
        return outcome

    def test_full_installer_preserves_distinct_evaluator_and_front_door_bytes(self) -> None:
        root, environment = self.installer_fixture()
        outcome = self.run_installer(root, environment, "--build-runtime")
        self.assertIn("fixture HTTP smoke preserved evaluator", outcome.stdout)
        build = root / "target/release"
        shared_name = aliases.case_insensitive_directory(build)
        command = "o-cli" if shared_name else "o"
        self.assertEqual((build / command).read_bytes(), b"native command front door\n")
        self.assertEqual((build / "O").read_bytes(), b"raw evaluator\n")

    def test_external_cache_leaves_self_contained_binaries_after_cache_removal(self) -> None:
        root, environment = self.installer_fixture()
        cache = self.build / "temporary cache with spaces"
        environment["OSTADIX_MCP_BUILD_CACHE"] = str(cache)
        build = root / "target/release"
        build.mkdir(parents=True)
        untouched = self.build / "previous-executable"
        untouched.write_bytes(b"preserve symlink target\n")
        for name in ("O", "ostadix-evaluator"):
            (build / name).symlink_to(untouched)
        self.run_installer(root, environment, "--build-runtime")
        self.assertEqual(untouched.read_bytes(), b"preserve symlink target\n")
        self.assertFalse((build / "O").is_symlink())
        self.assertFalse((build / "ostadix-evaluator").is_symlink())
        targets = [json.loads(line) for line in Path(environment["MCP_FAKE_CARGO_LOG"]).read_text().splitlines()]
        self.assertEqual(targets, [str(cache / "runtime"), str(cache / "mcp")])
        runtime_names = {"O", "o-cli", "olangc", "ocorec", "o-link", "o-unlink", "ogit", "o-live-host",
                         "o-node", "octl", "o-registry", "o-info", "ostadix-device", "ocore-kernel-world-record"}
        self.assertTrue(all((build / name).is_file() for name in runtime_names))
        self.assertFalse((build / "deps").exists())
        mcp_build = root / "mcp/ostadix_lang_mcp_server/target/release"
        self.assertEqual({path.name for path in mcp_build.iterdir()}, {"ostadix-mcp"})
        self.assertFalse((mcp_build / "ostadix-mcp").is_symlink())
        shutil.rmtree(cache)
        outcome = self.run_installer(root, environment, "--verify-only")
        self.assertIn("fixture HTTP smoke preserved evaluator", outcome.stdout)
        self.assertFalse(cache.exists())
        self.assertEqual((build / "O").read_bytes(), b"raw evaluator\n")
        self.assertEqual((mcp_build / "ostadix-mcp").read_bytes(), b"fixture executable\n")

    def test_relative_cache_is_rejected_before_building(self) -> None:
        root, environment = self.installer_fixture()
        environment["OSTADIX_MCP_BUILD_CACHE"] = "relative-cache"
        outcome = subprocess.run(
            ["bash", str(root / "scripts/setup_ostadix_mcp_http.sh"), "--build-runtime"],
            cwd=self.build, env=environment, capture_output=True, text=True,
        )
        self.assertEqual(outcome.returncode, 2)
        self.assertIn("must be an absolute path", outcome.stderr)
        self.assertFalse(Path(environment["MCP_FAKE_CARGO_LOG"]).exists())


class UpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name).resolve()
        self.repo = base / "developer"
        self.repo.mkdir()
        self.state = base / "deployment"
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Updater fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        scripts = self.repo / "scripts"
        scripts.mkdir()
        (self.repo / "backends").mkdir()
        (self.repo / "backends/.keep").write_text("")
        (self.repo / "README").write_text("tracked source\n")
        (self.repo / "behavior").write_text("success")
        (scripts / "setup_ostadix_mcp_http.sh").write_text(
            '#!/bin/sh\nexec python3 "$(dirname "$0")/fixture_installer.py" "$@"\n'
        )
        (scripts / "fixture_installer.py").write_text(textwrap.dedent('''\
            import json, os
            from pathlib import Path
            import sys
            root = Path(sys.argv[sys.argv.index("--root") + 1])
            assert "--build-runtime" in sys.argv or "--verify-only" in sys.argv
            assert "--with-runtime" not in sys.argv
            assert os.environ["O_LANG_ROOT"] == str(root)
            assert "CARGO_TARGET_DIR" not in os.environ
            behavior = (root / "behavior").read_text()
            root_log = root / "verification-roots.json"
            roots = json.loads(root_log.read_text()) if root_log.exists() else []
            roots.append(str(root))
            root_log.write_text(json.dumps(roots))
            if behavior == "fail":
                print("simulated HTTP smoke failure")
                sys.exit(23)
            if behavior == "relocation-fail" and "--verify-only" in sys.argv:
                print("simulated relocated HTTP smoke failure")
                sys.exit(24)
            if behavior == "mutate":
                (root / "README").write_text("changed tracked source")
            server = root / "mcp/ostadix_lang_mcp_server/target/release/ostadix-mcp"
            if "--build-runtime" in sys.argv:
                server.parent.mkdir(parents=True)
                server.write_text("#!/usr/bin/env python3\\nimport json, os, sys\\nprint(json.dumps({'root': os.environ.get('O_LANG_ROOT'), 'token': os.environ.get('OSTADIX_MCP_TOKEN'), 'olang': os.environ.get('OLANG'), 'args': sys.argv[1:]}))\\n")
                server.chmod(0o700)
            else:
                assert server.exists()
            (root / "installer-ran").write_text("smoke passed")
        '''))
        self.first = self.commit("initial")

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", ".")
        self.git("commit", "-m", message)
        return self.git("rev-parse", "HEAD")

    def invoke(self, *args: str, success: bool = True) -> tuple[str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = updater.main(["--state-dir", str(self.state), *args])
        self.assertEqual(code, 0 if success else 1, out.getvalue() + err.getvalue())
        return out.getvalue(), err.getvalue()

    def initial_update(self) -> None:
        self.invoke("update", "--repo", str(self.repo), "--branch", "main")

    def next_commit(self, behavior: str = "success") -> str:
        (self.repo / "behavior").write_text(behavior)
        (self.repo / "version").write_text("second")
        return self.commit("next")

    def selected(self, name: str = "current") -> str | None:
        release = updater.release_at(self.state, name)
        return release.name if release else None

    def test_build_and_switch_never_modify_dirty_developer_checkout(self) -> None:
        (self.repo / "README").write_text("user uncommitted changes\n")
        (self.repo / "personal.txt").write_text("do not touch")
        before = self.git("status", "--porcelain")
        with patch.dict(os.environ, {"CARGO_TARGET_DIR": str(self.repo / "external-target"),
                                     "O_LANG_ROOT": "/wrong/root"}):
            self.initial_update()
        self.assertEqual(self.selected(), self.first)
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(self.git("branch", "--show-current"), "main")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.first)
        self.assertEqual((self.repo / "README").read_text(), "user uncommitted changes\n")
        self.assertEqual((self.state / "current/README").read_text(), "tracked source\n")
        self.assertFalse((self.repo / "external-target").exists())
        self.assertFalse((self.repo / "installer-ran").exists())
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        roots = json.loads((self.state / "current/verification-roots.json").read_text())
        self.assertEqual(Path(roots[0]).parent, self.state / "staging")
        self.assertEqual(roots[1], str(self.state / "releases" / self.first))
        self.assertEqual(len(roots), 2)

    def test_check_fetches_without_build_or_selection(self) -> None:
        out, _ = self.invoke("check", "--repo", str(self.repo), "--branch", "main")
        self.assertEqual(json.loads(out)["candidate"], self.first)
        self.assertFalse((self.state / "releases").exists())
        self.assertFalse((self.state / "current").exists())

    def test_failed_build_or_smoke_preserves_current_and_retains_log(self) -> None:
        self.initial_update()
        failed = self.next_commit("fail")
        _, err = self.invoke("update", success=False)
        self.assertIn("build/HTTP smoke failed", err)
        self.assertEqual(self.selected(), self.first)
        self.assertIsNone(self.selected("previous"))
        self.assertFalse((self.state / "releases" / failed).exists())
        self.assertEqual(list((self.state / "staging").iterdir()), [])
        logs = list((self.state / "logs").glob(f"{failed}-*.log"))
        self.assertEqual(len(logs), 1)
        self.assertIn("simulated HTTP smoke failure", logs[0].read_text())

    def test_installer_cannot_change_tracked_candidate_sources(self) -> None:
        self.initial_update()
        self.next_commit("mutate")
        _, err = self.invoke("update", success=False)
        self.assertIn("changed tracked source", err)
        self.assertEqual(self.selected(), self.first)

    def test_failed_relocated_verification_preserves_selection_and_removes_release(self) -> None:
        self.initial_update()
        failed = self.next_commit("relocation-fail")
        _, err = self.invoke("update", success=False)
        self.assertIn("relocated-verify/HTTP smoke failed", err)
        self.assertEqual(self.selected(), self.first)
        self.assertFalse((self.state / "releases" / failed).exists())
        self.assertEqual(list((self.state / "staging").iterdir()), [])
        logs = list((self.state / "logs").glob(f"{failed}-relocated-verify-*.log"))
        self.assertIn("relocated HTTP smoke failure", logs[0].read_text())

    def test_upgrade_then_rollback_swaps_verified_releases_without_rebuild(self) -> None:
        self.initial_update()
        second = self.next_commit()
        self.invoke("update")
        self.assertEqual((self.selected(), self.selected("previous")), (second, self.first))
        logs = list((self.state / "logs").iterdir())
        self.invoke("rollback")
        self.assertEqual((self.selected(), self.selected("previous")), (self.first, second))
        self.assertEqual(list((self.state / "logs").iterdir()), logs)

    def test_restart_failure_restores_both_links_and_restarts_prior_release(self) -> None:
        self.initial_update()
        self.next_commit()
        with patch.object(updater, "restart_service", side_effect=[updater.UpdateError("failed restart"), None]) as restart, patch.object(updater, "wait_for_health") as health:
            _, err = self.invoke("update", "--restart", "systemd-user", success=False)
        self.assertIn("release selection restored", err)
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(self.selected(), self.first)
        self.assertIsNone(self.selected("previous"))
        health.assert_called_once()

    def test_failed_health_rolls_back_even_if_service_restart_command_succeeds(self) -> None:
        self.initial_update()
        self.next_commit()
        with patch.object(updater, "restart_service") as restart, patch.object(updater, "wait_for_health", side_effect=[updater.UpdateError("not ready"), None]) as health:
            _, err = self.invoke("update", "--restart", "systemd-user", "--health-timeout", "0.1", success=False)
        self.assertIn("release selection restored", err)
        self.assertEqual(self.selected(), self.first)
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(health.call_count, 2)

    def test_successful_restart_requires_health_confirmation(self) -> None:
        self.initial_update()
        second = self.next_commit()
        with patch.object(updater, "restart_service") as restart, patch.object(updater, "wait_for_health") as health:
            self.invoke("update", "--restart", "systemd-user", "--health-url", "http://127.0.0.1:9999/healthz")
        self.assertEqual(self.selected(), second)
        restart.assert_called_once()
        health.assert_called_once_with("http://127.0.0.1:9999/healthz", 15.0)

    def test_same_commit_is_noop_and_does_not_restart(self) -> None:
        self.initial_update()
        with patch.object(updater, "build_candidate") as build, patch.object(updater, "restart_service") as restart:
            out, _ = self.invoke("update", "--restart", "systemd-user")
        self.assertFalse(json.loads(out)["update_available"])
        build.assert_not_called()
        restart.assert_not_called()

    def test_repo_or_branch_changes_are_rejected(self) -> None:
        self.initial_update()
        _, err = self.invoke("update", "--branch", "different", success=False)
        self.assertIn("branch differs", err)
        _, err = self.invoke("update", "--repo", "https://example.invalid/other", success=False)
        self.assertIn("repository differs", err)
        self.assertEqual(self.selected(), self.first)

    def test_managed_origin_tampering_is_rejected_before_fetch(self) -> None:
        self.initial_update()
        updater.git(self.state / "repository.git", "remote", "set-url", "origin", "https://example.invalid/changed")
        _, err = self.invoke("update", success=False)
        self.assertIn("managed origin differs", err)
        self.assertEqual(self.selected(), self.first)

    def test_pinned_commit_and_explicit_rewind(self) -> None:
        second = self.next_commit()
        self.invoke("update", "--repo", str(self.repo), "--branch", "main", "--commit", self.first[:12])
        self.assertEqual(self.selected(), self.first)
        self.invoke("update")
        self.assertEqual(self.selected(), second)
        _, err = self.invoke("update", "--commit", self.first, success=False)
        self.assertIn("rewinds/diverges", err)
        self.assertEqual(self.selected(), second)
        self.invoke("update", "--commit", self.first, "--allow-rewind")
        self.assertEqual(self.selected(), self.first)

    def test_noncommit_argument_is_rejected(self) -> None:
        self.initial_update()
        _, err = self.invoke("check", "--commit", "HEAD~1", success=False)
        self.assertIn("hexadecimal commit ID", err)

    def test_concurrent_update_is_rejected(self) -> None:
        self.initial_update()
        with updater.update_lock(self.state):
            _, err = self.invoke("update", success=False)
        self.assertIn("another update", err)

    def test_current_cannot_point_outside_managed_releases(self) -> None:
        self.initial_update()
        (self.state / "current").unlink()
        (self.state / "current").symlink_to(self.repo)
        _, err = self.invoke("status", success=False)
        self.assertIn("outside managed releases", err)

    def test_run_uses_selected_runtime_and_preserves_auth_config(self) -> None:
        self.initial_update()
        environment = dict(os.environ, O_LANG_ROOT="/wrong/root", OLANG="/wrong/O",
                           OSTADIX_MCP_TOKEN="fixture-token")
        result = subprocess.run([sys.executable, str(SCRIPT), "--state-dir", str(self.state),
                                 "run", "--", "--transport", "http"],
                                text=True, capture_output=True, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["root"], str(self.state / "releases" / self.first))
        self.assertEqual(payload["token"], "fixture-token")
        self.assertIsNone(payload["olang"])
        self.assertEqual(payload["args"], ["--transport", "http"])


class HealthTests(unittest.TestCase):
    def server(self, bodies: list[bytes]):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = bodies[min(len(requests), len(bodies) - 1)]
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}/healthz", requests

    def test_health_waits_for_specific_connector_response(self) -> None:
        url, requests = self.server([b"not ready", b"ostadix-mcp ok\n"])
        updater.wait_for_health(url, 1.0)
        self.assertEqual(requests, ["/healthz", "/healthz"])

    def test_wrong_response_has_bounded_deadline(self) -> None:
        url, _ = self.server([b"ok from some unrelated server"])
        with self.assertRaisesRegex(updater.UpdateError, "failed health check"):
            updater.wait_for_health(url, 0.05)

    def test_stalled_health_request_obeys_overall_deadline(self) -> None:
        release_probe = threading.Event()

        def stalled_open(*args, **kwargs):
            release_probe.wait(2.0)
            raise updater.URLError("probe released")

        with patch.object(updater, "build_opener") as make_opener:
            make_opener.return_value.open.side_effect = stalled_open
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(updater.UpdateError, "readiness deadline"):
                    updater.wait_for_health("http://127.0.0.1/healthz", 0.05)
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                release_probe.set()

    def test_url_and_timeout_validation(self) -> None:
        for url in ("file:///etc/passwd", "http://user:password@example.org/healthz", "http://example.org/#x"):
            with self.assertRaises(argparse.ArgumentTypeError):
                updater.health_url(url)
        for timeout in ("0", "31", "-1", "nan", "inf"):
            with self.assertRaises(argparse.ArgumentTypeError):
                updater.health_timeout(timeout)


if __name__ == "__main__":
    unittest.main()
