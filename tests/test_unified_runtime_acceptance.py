"""Frozen-runtime acceptance oracles; no tmux server, QEMU or guest is run.

The one real PTY child is a tiny host terminal fixture. Process maps and ELF
headers are explicit private fixtures, not evidence of an actually owned VM.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("unified_runtime_acceptance_test",
                                             ROOT / "scripts/verify_okernel_unified_runtime.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class RuntimeOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="frozen-runtime-oracle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()

    def file(self, name, data=b"checked fixture"):
        path = self.runtime / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o444)
        return path

    def inventory(self):
        names = ("okernel-unified", "runtime/scripts/okernel_unified_world.py",
                 "runtime/scripts/okernel_package_domain.py", "runtime/scripts/okernel_native_volume.py",
                 "runtime/scripts/okernel-unified-console.sh", "runtime/ocore/guest/plan9/unified/protocol.py",
                 "tools/native/qemu-system-aarch64", "tools/bin/qemu-system-aarch64")
        inventory = {}
        for name in names:
            path = self.file(name)
            inventory[name] = {key: module.identity(path)[key] for key in ("bytes", "sha256")}
        manifest = {"schema": module.RUNTIME_SCHEMA, "passed": True, "inventory": inventory}
        (self.runtime / "runtime.json").write_text(json.dumps(manifest))
        return manifest

    def test_inventory_requires_all_exact_regular_captured_files(self):
        manifest = self.inventory()
        module.validate_inventory(self.runtime, manifest)
        extra = self.file("runtime/uncaptured.py")
        with self.assertRaisesRegex(ValueError, "uncaptured"):
            module.validate_inventory(self.runtime, manifest)
        extra.unlink()
        path = self.runtime / "runtime/scripts/okernel_unified_world.py"
        path.chmod(0o600)
        path.write_bytes(b"different source")
        path.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "identity"):
            module.validate_inventory(self.runtime, manifest)

    def test_inventory_rejects_escape_and_matching_symlink_bytes(self):
        manifest = self.inventory()
        manifest["inventory"]["../outside"] = {"bytes": 0, "sha256": "a" * 64}
        with self.assertRaisesRegex(ValueError, "escaped"):
            module.validate_inventory(self.runtime, manifest)
        del manifest["inventory"]["../outside"]
        native = self.runtime / "tools/native/qemu-system-aarch64"
        outside = self.root / "native-copy"
        outside.write_bytes(native.read_bytes())
        native.unlink()
        native.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            module.validate_inventory(self.runtime, manifest)

    def test_fork_validation_never_accepts_default_or_configured_working_state(self):
        state = self.root / "isolated"
        state.mkdir()
        (state / "fork.json").write_text(json.dumps({"schema": "ostadix.okernel-state-fork/v1",
                                                    "ok": True, "output": str(state)}))
        module.validate_private_fork(state, self.root / "default/package-domain")
        with self.assertRaisesRegex(ValueError, "working/default"):
            module.validate_private_fork(state, state)
        with patch.dict(os.environ, {"OSTADIX_OKERNEL_STATE": str(self.root)}):
            with self.assertRaisesRegex(ValueError, "working/default"):
                module.validate_private_fork(self.root / "package-domain", state / "default")

    def test_group_write_adds_no_foreign_primary_or_supplementary_principal(self):
        uid = os.geteuid()
        current = SimpleNamespace(pw_uid=uid, pw_gid=123)
        owner_group = SimpleNamespace(gr_mem=[])
        with patch.object(module.grp, "getgrgid", return_value=owner_group), \
                patch.object(module.pwd, "getpwall", return_value=[current]):
            self.assertTrue(module.private_owner_group(123))
            self.root.chmod(0o775)
            self.assertEqual(module.protected_directory(self.root), self.root)
            self.root.chmod(0o777)
            with self.assertRaises(ValueError):
                module.protected_directory(self.root)
            self.root.chmod(0o700)
        outsider = SimpleNamespace(pw_uid=uid + 100, pw_gid=123)
        with patch.object(module.grp, "getgrgid", return_value=owner_group), \
                patch.object(module.pwd, "getpwall", return_value=[current, outsider]):
            self.assertFalse(module.private_owner_group(123))
        with patch.object(module.grp, "getgrgid", return_value=SimpleNamespace(gr_mem=["foreign"])), \
                patch.object(module.pwd, "getpwall", return_value=[current]), \
                patch.object(module.pwd, "getpwnam", return_value=outsider):
            self.assertFalse(module.private_owner_group(123))

    def test_complete_line_oracle_cannot_accept_echoed_commands_partial_or_old_offsets(self):
        marker = b"FRESH_nonce"
        self.assertFalse(module.exact_line(b"okernel> printf FRESH_nonce\n", marker))
        self.assertFalse(module.exact_line(marker, marker))
        self.assertTrue(module.exact_line(b"\r\nFRESH_nonce\r\n", marker))
        old = b"FRESH_nonce\n"
        self.assertFalse(module.exact_line((old + b"new output\n")[len(old):], marker))

    def test_saved_pair_requires_new_selected_head_quiescence_and_exact_parent(self):
        state = self.root / "state"
        session = state / "unified-session-fixture"
        before = {"disk": {"sha256": "a" * 64}, "namespace": {"sha256": "b" * 64}}
        after = {"schema": "ostadix.package-domain-disk-head/v2", "session": str(session),
                 "previous": before["disk"], "previous_namespace": before["namespace"],
                 "disk": {"sha256": "c" * 64}, "namespace": {"sha256": "d" * 64}}
        record = {"schema": module.SESSION_SCHEMA, "ok": True, "after": after,
                  "paired_snapshot": True, "virtual_cpu_stopped": True, "native_operations_quiescent": True}
        module.validate_saved_pair(state, session, before, after, record)
        for name in ("paired_snapshot", "virtual_cpu_stopped", "native_operations_quiescent"):
            with self.subTest(flag=name), self.assertRaises(ValueError):
                module.validate_saved_pair(state, session, before, after, dict(record, **{name: False}))
        changed = dict(after, previous_namespace={"sha256": "e" * 64})
        with self.assertRaises(ValueError):
            module.validate_saved_pair(state, session, before, changed, dict(record, after=changed))

    @staticmethod
    def elf(machine):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = machine.to_bytes(2, "little")
        return bytes(header)

    def process_fixture(self):
        native = self.file("tools/native/qemu-system-aarch64", self.elf(62))
        library = self.file("tools/lib/libfixture.so.1", self.elf(62) + b"library")
        interpreter = self.root / "host-interpreter"
        interpreter.write_bytes(self.elf(62) + b"declared loader")
        state = self.root / "state"
        session = state / "unified-session-fixture"
        (session / "inputs").mkdir(parents=True)
        kernel = session / "inputs/monitor.elf"
        kernel.write_bytes(self.elf(183))
        record = {"schema": module.SESSION_SCHEMA, "controller_pid": 10, "qemu_pid": 20,
                  "inputs": {"monitor.elf": module.identity(kernel)}}
        manifest = {"inventory": {str(path.relative_to(self.runtime)): module.identity(path) for path in (native, library)},
                    "host_elf_interpreters": {str(interpreter): module.identity(interpreter)}}
        proc = self.root / "proc"
        process = proc / "20"
        process.mkdir(parents=True)
        (process / "exe").symlink_to(native)
        (process / "status").write_text("Name:\tqemu-fixture\nPPid:\t10\n")
        fields = ["S"] + ["0"] * 19
        fields[19] = "12345"
        (process / "stat").write_text("20 (qemu (fixture)) " + " ".join(fields))
        (process / "cmdline").write_bytes(b"\0".join(os.fsencode(x) for x in
            (native, "-smp", "1", "-kernel", kernel)) + b"\0")
        paths = (native, library, interpreter, kernel)
        (process / "maps").write_text("".join("1000-2000 r-xp 0 00:00 1 " + str(path) + "\n" for path in paths))
        return state, session, record, manifest, proc, process, library, interpreter

    def test_owned_process_requires_pane_parent_native_engine_and_captured_elf_paths(self):
        state, session, record, manifest, proc, process, library, _ = self.process_fixture()
        with patch.object(module, "R9_MONITOR", record["inputs"]["monitor.elf"]["sha256"]):
            result = module.inspect_owned_qemu(self.runtime, manifest, state, session, record, 10, proc)
            self.assertEqual((result["pid"], result["start_ticks"]), (20, 12345))
            with self.assertRaisesRegex(ValueError, "positively bound"):
                module.inspect_owned_qemu(self.runtime, manifest, state, session, record, 11, proc)
            outside = self.root / "same-bytes-unfrozen.so"
            outside.write_bytes(library.read_bytes())
            with (process / "maps").open("a") as stream:
                stream.write("2000-3000 r-xp 0 00:00 1 " + str(outside) + "\n")
            with self.assertRaisesRegex(ValueError, "outside captured"):
                module.inspect_owned_qemu(self.runtime, manifest, state, session, record, 10, proc)

    def test_declared_interpreter_must_really_be_mapped_and_parent_must_match(self):
        state, session, record, manifest, proc, process, _, interpreter = self.process_fixture()
        with patch.object(module, "R9_MONITOR", record["inputs"]["monitor.elf"]["sha256"]):
            original = (process / "maps").read_text()
            (process / "maps").write_text("".join(line for line in original.splitlines(True) if str(interpreter) not in line))
            with self.assertRaisesRegex(ValueError, "interpreter was not observed"):
                module.inspect_owned_qemu(self.runtime, manifest, state, session, record, 10, proc)
            (process / "maps").write_text(original)
            (process / "status").write_text("Name:\tfixture\nPPid:\t99\n")
            with self.assertRaisesRegex(ValueError, "not the private controller"):
                module.inspect_owned_qemu(self.runtime, manifest, state, session, record, 10, proc)

    def test_real_host_pty_fixture_has_controlling_foreground_tty_and_restores_termios(self):
        code = """import os,sys,termios,tty
assert os.isatty(0) and os.tcgetpgrp(0)==os.getpgrp()
before=termios.tcgetattr(0)
try:
 tty.setraw(0);os.write(1,b'HOST_PTY_READY\\n')
 data=b''
 while len(data)<2:data+=os.read(0,2-len(data))
 assert data==b'\\x02d'
finally:termios.tcsetattr(0,termios.TCSADRAIN,before)
"""
        terminal = module.AttachedTerminal([sys.executable, "-B", "-c", code], os.environ.copy(), self.root)
        try:
            deadline = time.monotonic() + 3
            while b"HOST_PTY_READY" not in (self.root / "terminal.raw").read_bytes():
                self.assertLess(time.monotonic(), deadline)
                terminal.pump()
            self.assertTrue(terminal.detach(timeout=3)["full_termios_restored"])
        finally:
            terminal.close()


if __name__ == "__main__":
    unittest.main()
