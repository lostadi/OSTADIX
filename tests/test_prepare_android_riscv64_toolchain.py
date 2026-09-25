"""Isolated source preparation must preserve inputs and reject unsupported joins."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prepare_android_riscv64_toolchain", ROOT / "scripts/prepare_android_riscv64_toolchain.py")
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
WORKSPACE_LOCK = tool.workspace_lock


class PreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.library = self.root / "original-library"
        self.library.mkdir()
        (self.library / "Cargo.toml").write_text(
            '[workspace]\nmembers = []\n[patch.crates-io]\n'
            'rustc-std-workspace-core = { path = "rustc-std-workspace-core" }\n')
        (self.library / "LICENSE-MIT").write_text("upstream license\n")
        self.std = self.crate("0.2.185")
        self.app = self.crate("0.2.186")
        self.mcp = self.crate("0.2.189")
        self.std_lock = self.library / "Cargo.lock"
        self.write_lock(self.std_lock, self.std)
        self.app_lock = self.root / "application.lock"
        self.write_lock(self.app_lock, self.app)
        self.mcp_lock = self.root / "mcp.lock"
        self.write_lock(self.mcp_lock, self.mcp)
        self.args = argparse.Namespace(
            output=self.root / "prepared", lock=[self.app_lock, self.mcp_lock],
            rustc="unused-rustc", cargo="unused-cargo", rust_library=self.library,
            archive_dir=[self.cache], offline=True, ndk_cc=None)
        identity = {"rustc": "/recorded/rustc", "cargo": "/recorded/cargo",
                    "rustc_verbose_version": "test fixture", "cargo_verbose_version": "test fixture",
                    "sysroot": str(self.root / "installed-toolchain")}
        self.identity = patch.object(tool, "compiler_identity", return_value=identity)
        self.identity.start()
        self.addCleanup(self.identity.stop)
        locate = patch.object(tool, "workspace_lock", return_value=self.app_lock)
        locate.start()
        self.addCleanup(locate.stop)

    def crate(self, version: str, unexpected: bool = False) -> dict:
        constants = "\n".join(f"pub const {name}: c_int = 0x{digits};"
                              for name, digits in tool.FLAGS.items()) + "\n"
        if unexpected:
            constants = constants.replace("0x40000;", "0o40000;", 1)
        files = {"Cargo.toml": f'[package]\nname = "libc"\nversion = "{version}"\n',
                 str(tool.LIBC_SOURCE): constants, "LICENSE-MIT": "retain upstream notices\n",
                 "other.rs": "unchanged\n"}
        archive = self.cache / f"libc-{version}.crate"
        with tarfile.open(archive, "w:gz") as target:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"libc-{version}/{name}")
                info.size = len(data)
                target.addfile(info, io.BytesIO(data))
        return {"name": "libc", "version": version, "source": tool.REGISTRY,
                "checksum": hashlib.sha256(archive.read_bytes()).hexdigest()}

    def write_lock(self, path: Path, package: dict) -> None:
        path.write_text("# retained lock comment\nversion = 4\n\n[[package]]\n"
                        + "".join(f"{key} = {json.dumps(value)}\n" for key, value in package.items())
                        + '\n[[package]]\nname = "unrelated"\nversion = "1.0.0"\n')

    def test_multiple_exact_versions_and_derived_std_preserve_every_input(self) -> None:
        before = tool.tree_hashes(self.root)
        result = tool.prepare(self.args)
        self.assertEqual([c["version"] for c in result["crates"]], ["0.2.185", "0.2.186", "0.2.189"])
        for path, digest in before.items():
            self.assertEqual(tool.sha256(self.root / path), digest, path)
        for record in result["crates"]:
            crate = Path(record["path"])
            text = (crate / tool.LIBC_SOURCE).read_text()
            for name, digits in tool.FLAGS.items():
                self.assertIn(f"pub const {name}: c_int = 0o{digits};", text)
            self.assertEqual((crate / "LICENSE-MIT").read_text(), "retain upstream notices\n")
        derived = self.args.output / "rust-library"
        patch_entry = tool.read_toml(derived / "Cargo.toml")["patch"]["crates-io"]["libc"]
        self.assertEqual(patch_entry["version"], "=0.2.185")
        self.assertEqual(Path(patch_entry["path"]).name, "libc-0.2.185")
        expected = tool.read_toml(self.std_lock)
        expected["package"][0].pop("source")
        expected["package"][0].pop("checksum")
        self.assertEqual(tool.read_toml(derived / "Cargo.lock"), expected)
        env = json.loads((self.args.output / "build-environment.json").read_text())
        self.assertEqual(env["environment"]["__CARGO_TESTS_ONLY_SRC_ROOT"], str(derived))
        self.assertFalse(result["supported_execution"])
        self.assertEqual(result["status"], "prepared_only")
        self.assertEqual(result["ndk_header_check"], "not_run")
        for application in result["applications"]:
            paths = tool.read_toml(Path(application["paths_config"]))["paths"]
            self.assertEqual(len(paths), 1)
            self.assertEqual(Path(paths[0]).name, "libc-" + application["version"])

    def test_checksum_failure_uses_real_archive_bytes(self) -> None:
        archive = self.cache / "libc-0.2.186.crate"
        archive.write_bytes(archive.read_bytes() + b"corruption")
        original = self.app_lock.read_bytes()
        with self.assertRaisesRegex(tool.PreparationError, "checksum mismatch"):
            tool.prepare(self.args)
        self.assertEqual(self.app_lock.read_bytes(), original)
        self.assertEqual(json.loads((self.args.output / "status.json").read_text())["status"], "failed")

    def test_refuses_unexpected_or_already_corrected_constants(self) -> None:
        self.write_lock(self.app_lock, self.crate("0.2.186", unexpected=True))
        with self.assertRaisesRegex(tool.PreparationError, "unexpected O_DIRECT"):
            tool.prepare(self.args)

    def test_refuses_existing_output_without_touching_it(self) -> None:
        self.args.output.mkdir()
        marker = self.args.output / "keep"
        marker.write_bytes(b"keep")
        with self.assertRaisesRegex(tool.PreparationError, "output already exists"):
            tool.prepare(self.args)
        self.assertEqual(list(self.args.output.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_refuses_missing_archive_offline_without_network(self) -> None:
        # Exclude the real user's cache so the test is independent of that cache.
        (self.cache / "libc-0.2.186.crate").unlink()
        with patch.dict("os.environ", {"CARGO_HOME": str(self.root / "empty-cargo")}), \
             patch.object(tool.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(tool.PreparationError, "offline archive missing"):
                tool.prepare(self.args)
        network.assert_not_called()

    def test_conflicting_same_version_checksums_rejected_before_output(self) -> None:
        conflict = dict(self.app, checksum="f" * 64)
        self.write_lock(self.mcp_lock, conflict)
        with self.assertRaisesRegex(tool.PreparationError, "conflicting locked checksums"):
            tool.prepare(self.args)
        self.assertFalse(self.args.output.exists())

    def test_existing_std_libc_patch_is_not_overwritten(self) -> None:
        manifest = self.library / "Cargo.toml"
        manifest.write_text(manifest.read_text() + 'libc = { path = "existing" }\n')
        before = manifest.read_bytes()
        with self.assertRaisesRegex(tool.PreparationError, "already patches libc"):
            tool.prepare(self.args)
        self.assertEqual(manifest.read_bytes(), before)

    def test_rejects_archive_escape_even_when_checksum_matches(self) -> None:
        archive = self.cache / "escape.crate"
        with tarfile.open(archive, "w:gz") as target:
            info = tarfile.TarInfo("libc-0.2.186/../../escape")
            info.size = 1
            target.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(tool.PreparationError, "unexpected crate archive member"):
            tool.extract_crate(archive, "0.2.186", self.root / "out")
        self.assertFalse((self.root / "escape").exists())

    def test_run_keeps_literal_action_and_recorded_source_environment(self) -> None:
        tool.prepare(self.args)
        arguments = ["build", "--locked", "--offline", "-Z", "build-std", "--target",
                     tool.TARGET, "--message-format=json", "--bin", "O"]
        with patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as run, \
             patch("sys.stderr", new=io.StringIO()):
            result = tool.run_prepared(self.args.output, ["--", *arguments])
        self.assertEqual(result, 7)
        self.assertEqual(run.call_args.args[0], ["/recorded/cargo", "--config",
                         str(self.args.output / "paths-override-0.2.186.toml"), *arguments])
        self.assertEqual(run.call_args.kwargs["env"]["__CARGO_TESTS_ONLY_SRC_ROOT"],
                         str(self.args.output / "rust-library"))
        receipt = json.loads(next(self.args.output.glob("run-*.json")).read_text())
        self.assertEqual(receipt["exit_status"], 7)
        self.assertFalse(receipt["supported_execution"])
        self.assertTrue(receipt["locks_unchanged"])
        self.assertEqual(receipt["application_libc_version"], "0.2.186")

    def test_run_selects_mcp_exact_version_and_refuses_unprepared_lock(self) -> None:
        tool.prepare(self.args)
        args = ["check", "--locked", "--target=" + tool.TARGET, "-Zbuild-std"]
        with patch.object(tool, "workspace_lock", return_value=self.mcp_lock), \
             patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, \
             patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(tool.run_prepared(self.args.output, args), 0)
        self.assertEqual(Path(run.call_args.args[0][2]).name, "paths-override-0.2.189.toml")
        self.app_lock.write_text(self.app_lock.read_text() + "# changed\n")
        with self.assertRaisesRegex(tool.PreparationError, "was not prepared or has changed"):
            tool.run_prepared(self.args.output, args)

    def test_refuses_multiple_libc_versions_in_one_workspace(self) -> None:
        self.app_lock.write_text(self.app_lock.read_text() + '\n[[package]]\n' +
                                 ''.join(f'{k} = {json.dumps(v)}\n' for k, v in self.mcp.items()))
        with self.assertRaisesRegex(tool.PreparationError, "multiple libc versions in one workspace"):
            tool.prepare(self.args)
        self.assertFalse(self.args.output.exists())

    def test_run_refuses_missing_build_std_and_changed_sources(self) -> None:
        tool.prepare(self.args)
        args = ["check", "--locked", "--target=" + tool.TARGET]
        with self.assertRaisesRegex(tool.PreparationError, "explicit -Z build-std"):
            tool.run_prepared(self.args.output, args)
        (self.args.output / "crates/libc-0.2.186" / tool.LIBC_SOURCE).write_text("changed")
        with self.assertRaisesRegex(tool.PreparationError, "source tree changed"):
            tool.run_prepared(self.args.output, [*args, "-Zbuild-std"])

    def test_refuses_output_inside_installed_source(self) -> None:
        self.args.output = self.library / "new-output"
        with self.assertRaisesRegex(tool.PreparationError, "outside the installed toolchain"):
            tool.prepare(self.args)
        self.assertFalse(self.args.output.exists())

    def test_test_arguments_cannot_satisfy_cargo_guard_flags(self) -> None:
        with self.assertRaisesRegex(tool.PreparationError, "explicit --target"):
            tool.run_prepared(self.root, ["test", "--", "--target", tool.TARGET,
                                          "--locked", "-Zbuild-std"])

    def test_run_requires_std_component_and_no_conflicting_build_std_flags(self) -> None:
        for flags in (["-Zbuild-std=core"], ["-Zbuild-std", "-Zbuild-std=core"]):
            with self.subTest(flags=flags), self.assertRaisesRegex(tool.PreparationError, "including std"):
                tool.run_prepared(self.root, ["build", "--target", tool.TARGET, "--locked", *flags])

    def test_workspace_lookup_honors_manifest_path_as_literal_argument(self) -> None:
        manifest = self.library / "Cargo.toml"
        # Use the original function because other run tests isolate Cargo lookup.
        with patch.object(tool, "command_output", return_value=str(manifest)) as lookup:
            lock = WORKSPACE_LOCK("/recorded/cargo", ["check", "--manifest-path", "name with spaces/Cargo.toml"])
        self.assertEqual(lock, self.std_lock)
        self.assertEqual(lookup.call_args.args[0][-2:], ["--manifest-path", "name with spaces/Cargo.toml"])


if __name__ == "__main__":
    unittest.main()
