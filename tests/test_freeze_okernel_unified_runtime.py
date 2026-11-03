"""Frozen runtime entry/capture contracts, without tmux or QEMU execution."""
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_freezer_test", ROOT / "scripts/freeze_okernel_unified_runtime.py")
freezer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(freezer)
SPEC = importlib.util.spec_from_file_location("runtime_capture_helpers", ROOT / "scripts/verify_okernel_two_domains_repro.py")
repro = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repro)


class FrozenRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="frozen unified runtime ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.entry = self.root / "okernel-unified"
        self.entry.write_text(freezer.ENTRY)
        self.entry.chmod(0o555)
        payload = self.root / "runtime/scripts/okernel_unified_world.py"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"frozen runtime fixture; never executed\n")
        files = repro.inventory(self.root, ("runtime", "okernel-unified"))
        self.manifest = {"schema": freezer.SCHEMA, "passed": True,
                         "host_python": repro.identity(Path(sys.executable).resolve()),
                         "admitted_manifest": {"sha256": "a" * 64},
                         "inventory": {name: {key: value[key] for key in ("bytes", "sha256")} for name, value in files.items()}}
        self.save()

    def save(self):
        repro.write_json(self.root / "runtime.json", self.manifest)

    def invoke(self, *args):
        return subprocess.run([sys.executable, "-B", str(self.entry), *args], capture_output=True, text=True)

    def load_entry(self):
        loader = SourceFileLoader("frozen_runtime_entry_test", str(self.entry))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_check_is_readonly_and_binds_all_retained_files(self):
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = self.invoke("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Frozen unified runtime: PASS", result.stdout)
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
        payload = self.root / "runtime/scripts/okernel_unified_world.py"
        payload.write_bytes(b"changed source")
        result = self.invoke("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime file changed", result.stderr)

    def test_explicit_state_required_without_auto_seeding(self):
        result = self.invoke("start")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--state is required", result.stderr)
        self.assertFalse((self.root / "head.json").exists())
        self.assertFalse((self.root / "domain.lock").exists())

    def test_entry_cannot_override_captured_build_or_qemu(self):
        for option in ("--build", "--qemu"):
            result = self.invoke("--state", "/private/state", "start", option, "/mutable/checkout")
            self.assertEqual(result.returncode, 2)
            self.assertIn("unrecognized arguments", result.stderr)

    def test_entry_executes_only_own_launcher_build_and_qemu(self):
        module = self.load_entry()
        sentinel = RuntimeError("captured exec; no process launched")
        with patch.object(sys, "argv", [str(self.entry), "run", "--state", "/explicit/private state", "--detach"]), \
                patch.object(module.os, "execve", side_effect=sentinel) as execute, \
                patch.object(module.shutil, "which", return_value="host prerequisite"):
            with self.assertRaisesRegex(RuntimeError, "captured exec"):
                module.main()
        executable, argv, environment = execute.call_args.args
        self.assertEqual(executable, "/bin/bash")
        self.assertEqual(argv[1], str(self.root / "runtime/scripts/okernel-unified-console.sh"))
        self.assertEqual(argv[argv.index("--state") + 1], "/explicit/private state")
        self.assertEqual(argv[argv.index("--build") + 1], str(self.root / "build"))
        self.assertEqual(argv[argv.index("--qemu") + 1], str(self.root / "tools/bin/qemu-system-aarch64"))
        self.assertEqual(argv[-2:], ["start", "--detach"])
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(environment["OKERNEL_UNIFIED_HOST_PYTHON"], str(Path(sys.executable).resolve()))

    def test_entry_rejects_escaped_inventory_and_matching_symlink_bytes(self):
        item = next(name for name in self.manifest["inventory"] if name.startswith("runtime/"))
        original = self.root / item
        copy = self.root / "outside"
        copy.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(copy)
        result = self.invoke("check")
        self.assertIn("inventory symlink", result.stderr)
        self.manifest["inventory"]["../escape"] = self.manifest["inventory"][item]
        del self.manifest["inventory"][item]
        self.save()
        result = self.invoke("check")
        self.assertIn("invalid runtime inventory path", result.stderr)

    def test_capture_tree_materializes_firmware_file_links_and_refuses_directory_links(self):
        source = self.root / "data"
        source.mkdir()
        outside = self.root / "firmware.bin"
        outside.write_bytes(b"original firmware fixture")
        (source / "firmware.bin").symlink_to(outside)
        target = self.root / "captured-data"
        result = freezer.capture_tree(source, target, repro)
        self.assertEqual(result["firmware.bin"]["original"]["sha256"], repro.identity(outside)["sha256"])
        self.assertFalse((target / "firmware.bin").is_symlink())
        self.assertEqual((target / "firmware.bin").stat().st_mode & 0o777, 0o444)
        (source / "directory-link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory symlinks"):
            freezer.capture_tree(source, self.root / "second-capture", repro)

    def test_live_observation_never_discovers_or_adopts_default_state(self):
        state = self.root / "package-domain"
        session = state / "unified-session-fixture"
        session.mkdir(parents=True)
        repro.write_json(state / "fork.json", {"schema": "ostadix.okernel-state-fork/v1", "ok": True, "output": str(state)})
        repro.write_json(session / "result.json", {"schema": "ostadix.unified-world-session/v1", "qemu_pid": os.getpid()})
        with self.assertRaisesRegex(ValueError, "explicitly isolated"):
            freezer.inspect_private_process(session, {}, Path("/usr/bin/qemu-system-aarch64"), repro)

    def test_packager_refuses_existing_output_before_tool_or_state_actions(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/freeze_okernel_unified_runtime.py"),
                                 "--build", str(self.root), "--output", str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("new directory", result.stderr)
        self.assertFalse((self.root / "tools").exists())


if __name__ == "__main__":
    unittest.main()
