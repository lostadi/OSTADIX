"""Actual cp + original Clang fixtures for a cache-only provenance mechanism.

The fixture controller really executes the selected compiler and binds observed
output lifetimes. It is NOT production frontend admission or O-core lowering.
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "ocore_native_copy.py"
spec = importlib.util.spec_from_file_location("ocore_native_copy", MODULE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
CLANG = Path(os.environ.get("NATIVE_COPY_TEST_CLANG") or shutil.which("clang") or "/missing-clang").resolve()
CP = Path(os.environ.get("NATIVE_COPY_TEST_CP") or shutil.which("cp") or "/missing-cp").resolve()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class OriginalCompilerJournal(m.VerifiedProducerInventory):
    """Trusted fixture source, populated only by actual successful Clang calls.

    There is no load_json/record_claim method. Ordinary receipt dictionaries are
    never accepted. Production must use its registered independently verified
    producer events, not instantiate this authored fixture as runtime provenance.
    """
    def __init__(self):
        self._outputs = {}
        self.executions = []

    def compile_original(self, root: Path, *, assembly=False):
        source = root / ("source.s" if assembly else "source.c")
        output = root / "source.o"
        source.write_text(".text\n.globl original_symbol\noriginal_symbol:\n ret\n" if assembly else "long original_symbol(long x) { return x + 7; }\n")
        source_before, _ = m.snapshot(source)
        tool_before, _ = m.snapshot(CLANG)
        argv = [str(CLANG), "-c", str(source), "-o", str(output)]
        native = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        completed = time.monotonic_ns()
        source_after, _ = m.snapshot(source)
        tool_after, _ = m.snapshot(CLANG)
        if native.returncode != 0 or source_before != source_after or tool_before != tool_after:
            raise AssertionError("original fixture compiler or inputs changed: " + native.stderr.decode(errors="replace"))
        identity, _ = m.snapshot(output)
        row = {"kind": "actual-original-clang-fixture", "argv": argv,
               "source_before": source_before.as_dict(), "source_after": source_after.as_dict(),
               "tool": tool_before.as_dict(), "output": identity.as_dict(),
               "completed_mono_ns": completed, "native_returncode": native.returncode,
               "stdout_hex": native.stdout.hex(), "stderr_hex": native.stderr.hex()}
        journal_sha = hashlib.sha256(m.canonical_json(row)).hexdigest()
        owner = m.OwnerRecord(identity, completed, "fixture-" + journal_sha[:16], journal_sha,
                              True, False, False,
                              ("original-assembly-unlowered",) if assembly else ("original-C-not-O-core-lowered",))
        self._outputs[identity] = owner
        self.executions.append(row)
        return output

    def predecessor(self, source, before_mono_ns):
        owner = self._outputs.get(source)
        if owner is not None and owner.completed_mono_ns < before_mono_ns:
            return owner
        return None


class NativeCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CLANG.is_file() or not CP.is_file():
            raise RuntimeError("required actual original Clang and cp are missing; no skip")
        cls.session = Path(tempfile.mkdtemp(prefix="native-copy-tests-", dir=os.environ.get("NATIVE_COPY_TEST_OUTPUT")))
        cls.identity_before = {str(path): sha(path) for path in (CLANG, CP, MODULE)}
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        after = {str(path): sha(path) for path in (CLANG, CP, MODULE)}
        if after != cls.identity_before:
            raise AssertionError("original tool/helper bytes changed")
        (cls.session / "fixture-results.json").write_bytes(m.canonical_json({
            "schema": "ostadix.native-copy-actual-fixtures/v1", "tools_before": cls.identity_before,
            "tools_after": after, "production_registered": False,
            "ocore_lowering_qualified": False, "records": cls.records}))
        print("ACTUAL_FIXTURE_DIRECTORY=" + str(cls.session), flush=True)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=self.session))
        self.inventory = OriginalCompilerJournal()
        self.registry = self.root / "registry.json"
        self.registry.write_text('{"schema":"private-fixture-only","registered":false}\n')
        self.pins = m.Pins(CP, sha(CP), sha(MODULE), self.registry, sha(self.registry))
        self.controller = m.CaptureController(pins=self.pins, inventory=self.inventory, evidence=self.root / "evidence")
        self.outcomes = []

    def tearDown(self):
        self.records.append({"case": self._testMethodName, "root": str(self.root),
                             "compiler_executions": self.inventory.executions,
                             "operations": [{"event": o.event, "returncode": o.returncode,
                                             "spawn_error": type(o.spawn_error).__name__ if o.spawn_error else None,
                                             "receipt": str(o.receipt) if o.receipt else None,
                                             "capture_errors": o.capture_errors} for o in self.outcomes]})

    def run_copy(self, source="source.o", destination="installed.o", *, extra=(), callback=None, controller=None):
        controller = controller or self.controller
        argv = ["cp", *extra, str(source), str(destination)]
        result = controller.observe_copy(argv, cwd=self.root, on_started=callback)
        self.outcomes.append(result)
        return result

    def require_unowned(self, result, controller=None):
        controller = controller or self.controller
        with self.assertRaises(m.EvidenceError):
            controller.verify_transfer(result)
        try:
            facts = controller.verify_observation(result)
        except m.EvidenceError:
            return
        self.assertFalse(facts["source_owned"])
        self.assertFalse(facts["destination_causality_qualified"])
        # A genuine operation without a matching source lifetime is observable,
        # but cannot invent a predecessor. Corrupt observations must still fail.
        self.assertFalse(facts["predecessor_source_owned"])

    def test_actual_compiler_then_cp_binds_path_lifetime_and_preserves_unlowered(self):
        output = self.inventory.compile_original(self.root)
        result = self.run_copy()
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "installed.o").read_bytes(), output.read_bytes())
        edge = self.controller.verify_observation(result)
        self.assertFalse(edge["source_owned"])
        self.assertFalse(edge["destination_causality_qualified"])
        self.assertTrue(edge["predecessor_source_owned"])
        with self.assertRaisesRegex(m.EvidenceError, "exclusive output window"):
            self.controller.verify_transfer(result)
        self.assertFalse(edge["ocore_lowered"])
        self.assertFalse(edge["llvm_replay_complete"])
        self.assertFalse(edge["production_registered"])
        self.assertEqual(edge["predecessor_unsupported"], ["original-C-not-O-core-lowered"])
        receipt = json.loads(result.receipt.read_bytes())
        self.assertEqual(receipt["argv"], ["cp", "source.o", "installed.o"])
        self.assertEqual(receipt["stdio"], "inherited-unmodified")
        self.assertIsNone(receipt["observations"]["destination_before"])

    def test_real_startup_assembly_transfer_stays_unsupported(self):
        self.inventory.compile_original(self.root, assembly=True)
        result = self.run_copy()
        edge = self.controller.verify_observation(result)
        self.assertEqual(edge["predecessor_unsupported"], ["original-assembly-unlowered"])
        self.assertFalse(edge["ocore_lowered"])
        self.assertFalse(edge["llvm_replay_complete"])

    def test_overwrite_is_observed_including_previous_destination(self):
        self.inventory.compile_original(self.root)
        destination = self.root / "installed.o"
        destination.write_bytes(b"old\x00payload")
        result = self.run_copy()
        self.controller.verify_observation(result)
        before = json.loads(result.receipt.read_bytes())["observations"]["destination_before"]
        self.assertEqual(before["sha256"], hashlib.sha256(b"old\x00payload").hexdigest())

    def test_literal_double_dash_preserves_exact_argv(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy(extra=("--",))
        self.controller.verify_observation(result)
        self.assertEqual(json.loads(result.receipt.read_bytes())["argv"], ["cp", "--", "source.o", "installed.o"])

    def test_same_bytes_already_at_destination_still_needs_real_copy(self):
        self.inventory.compile_original(self.root)
        (self.root / "installed.o").write_bytes((self.root / "source.o").read_bytes())
        result = self.run_copy()
        self.controller.verify_observation(result)
        self.assertEqual(result.returncode, 0)

    def test_no_source_owner_from_arbitrary_self_consistent_earlier_json(self):
        source = self.root / "source.o"
        source.write_bytes(b"opaque identical bytes")
        fake_owner = {"source_owned": True, "ocore_lowered": True,
                      "output": m.snapshot(source)[0].as_dict(), "completed_mono_ns": 1}
        with self.assertRaises(TypeError):
            m.CaptureController(pins=self.pins, inventory={"verified_earlier": [fake_owner]}, evidence=self.root / "fake")
        result = self.run_copy()
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def test_pasted_identical_bytes_at_another_source_path_cannot_borrow_owner(self):
        self.inventory.compile_original(self.root)
        pasted = self.root / "pasted.o"
        pasted.write_bytes((self.root / "source.o").read_bytes())
        result = self.run_copy(source=pasted.name)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def test_replaced_source_inode_with_identical_payload_cannot_borrow_owner(self):
        self.inventory.compile_original(self.root)
        original = self.root / "source.o"
        replacement = self.root / "replacement"
        replacement.write_bytes(original.read_bytes())
        replacement.replace(original)
        result = self.run_copy()
        self.require_unowned(result)

    def test_mutated_then_restored_same_inode_bytes_do_not_restore_owner_lifetime(self):
        self.inventory.compile_original(self.root)
        original = self.root / "source.o"
        content = original.read_bytes()
        old = original.stat()
        original.write_bytes(b"other")
        original.write_bytes(content)
        os.utime(original, ns=(old.st_atime_ns, old.st_mtime_ns))
        result = self.run_copy()
        self.require_unowned(result)

    def test_unobserved_output_and_pasted_receipt_cannot_mint_observation(self):
        self.inventory.compile_original(self.root)
        shutil.copyfile(self.root / "source.o", self.root / "installed.o")
        fake = self.root / "forged.json"
        fake.write_text('{"schema":"ostadix.observed-native-copy/v1","eligible_observation":true}\n')
        outcome = m.CopyOutcome("forged", 0, None, fake, (), object())
        self.require_unowned(outcome)
        with self.assertRaises(m.EvidenceError):
            self.controller.verify_observation(json.loads(fake.read_bytes()))

    def test_genuine_receipt_not_transferable_to_another_controller(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        other = m.CaptureController(pins=self.pins, inventory=self.inventory, evidence=self.root / "other")
        self.require_unowned(result, other)

    def test_genuine_event_cannot_be_reused_with_a_forged_handle(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        fake = dataclasses.replace(result, _binding=object())
        self.require_unowned(fake)

    def test_modified_receipt_cannot_gain_claimed_predecessor(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        result.receipt.chmod(0o600)
        receipt = json.loads(result.receipt.read_bytes())
        receipt["source_owned"] = True
        receipt["predecessor"] = {"completed": 1, "ocore_lowered": True}
        result.receipt.write_bytes(m.canonical_json(receipt))
        self.require_unowned(result)

    def test_changed_immutable_blob_fails_verification(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        payload = json.loads(result.receipt.read_bytes())
        blob = self.controller.evidence / "blobs" / payload["observations"]["source_before"]["sha256"]
        blob.chmod(0o600)
        blob.write_bytes(b"tampered")
        self.require_unowned(result)

    def test_tool_pin_mismatch_does_not_skip_or_rewrite_original_cp(self):
        self.inventory.compile_original(self.root)
        pins = dataclasses.replace(self.pins, tool_sha256="0" * 64)
        other = m.CaptureController(pins=pins, inventory=self.inventory, evidence=self.root / "other")
        result = self.run_copy(controller=other)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "installed.o").read_bytes(), (self.root / "source.o").read_bytes())
        self.require_unowned(result, other)

    def test_observer_pin_mismatch_does_not_skip_original(self):
        self.inventory.compile_original(self.root)
        other = m.CaptureController(pins=dataclasses.replace(self.pins, observer_sha256="0" * 64), inventory=self.inventory, evidence=self.root / "other")
        result = self.run_copy(controller=other)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result, other)

    def test_registry_pin_mismatch_does_not_skip_original(self):
        self.inventory.compile_original(self.root)
        other = m.CaptureController(pins=dataclasses.replace(self.pins, registry_sha256="0" * 64), inventory=self.inventory, evidence=self.root / "other")
        result = self.run_copy(controller=other)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result, other)

    def test_registry_mutation_during_operation_invalidates_observation(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy(callback=lambda pid: self.registry.write_bytes(b"changed registry"))
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def test_source_mutation_during_actual_operation_invalidates_observation(self):
        self.inventory.compile_original(self.root)
        def mutate(pid):
            source = self.root / "source.o"
            source.chmod(0o600)
            source.chmod(0o644)
        result = self.run_copy(callback=mutate)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def test_copy_failure_preserves_original_status(self):
        result = self.run_copy(source="missing.o")
        original = subprocess.run(["cp", "missing.o", "installed.o"], executable=str(CP), cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, original.returncode)
        self.assertEqual(result.returncode, 1)
        self.require_unowned(result)

    def test_directory_operation_remains_original_and_unclassified(self):
        source = self.root / "source-dir"
        source.mkdir()
        (source / "payload").write_bytes(b"original")
        result = self.run_copy(source="source-dir", destination="copy-dir", extra=("-r",))
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "copy-dir/payload").read_bytes(), b"original")
        self.require_unowned(result)

    def test_source_symlink_original_cp_runs_without_ownership(self):
        self.inventory.compile_original(self.root)
        (self.root / "alias.o").symlink_to("source.o")
        result = self.run_copy(source="alias.o")
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def test_destination_symlink_original_effect_is_not_rewritten(self):
        self.inventory.compile_original(self.root)
        (self.root / "real-dest").write_bytes(b"old")
        (self.root / "installed.o").symlink_to("real-dest")
        result = self.run_copy()
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "real-dest").read_bytes(), (self.root / "source.o").read_bytes())
        self.require_unowned(result)

    def test_missing_tool_preserves_spawn_failure(self):
        self.inventory.compile_original(self.root)
        other = m.CaptureController(pins=dataclasses.replace(self.pins, tool=self.root / "missing-cp"), inventory=self.inventory, evidence=self.root / "other")
        result = self.run_copy(controller=other)
        self.assertIsNone(result.returncode)
        self.assertIsInstance(result.spawn_error, FileNotFoundError)
        self.require_unowned(result, other)
        with self.assertRaises(FileNotFoundError):
            result.forward_native_outcome()

    def test_capture_persistence_failure_preserves_actual_success(self):
        self.inventory.compile_original(self.root)
        blocked = self.root / "blocked"
        blocked.write_bytes(b"not a directory")
        other = m.CaptureController(pins=self.pins, inventory=self.inventory, evidence=blocked)
        result = self.run_copy(controller=other)
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.receipt)
        self.assertTrue((self.root / "installed.o").is_file())
        self.require_unowned(result, other)

    def test_unavailable_controller_hook_does_not_retry_or_skip_cp(self):
        self.inventory.compile_original(self.root)
        def failure(pid):
            raise RuntimeError("failed diagnostic hook")
        result = self.run_copy(callback=failure)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result)

    def _driver(self, arguments, *, pid_file=None):
        driver = self.root / "driver.py"
        # The child driver inherits binary stdio. No capture/replay is performed
        # inside the wrapper; the test runner compares native process pipes.
        driver.write_text("""import importlib.util,json,sys\nfrom pathlib import Path\nspec=importlib.util.spec_from_file_location('copy_observer',sys.argv[1]);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)\nclass NoOwners(m.VerifiedProducerInventory):\n def predecessor(self,*args): return None\nargs=json.loads(sys.argv[2]);pins=m.Pins(Path(args['tool']),args['tool_sha'],args['observer_sha'],Path(args['registry']),args['registry_sha'])\nc=m.CaptureController(pins=pins,inventory=NoOwners(),evidence=Path(args['evidence']))\ndef started(pid):\n if args.get('pid_file'): Path(args['pid_file']).write_text(str(pid))\no=c.observe_copy(args['argv'],cwd=Path(args['cwd']),on_started=started,relay_parent_signals=True);o.forward_native_outcome()\n""")
        args = {"tool": str(CP), "tool_sha": sha(CP), "observer_sha": sha(MODULE),
                "registry": str(self.registry), "registry_sha": sha(self.registry),
                "evidence": str(self.root / "driver-evidence"), "cwd": str(self.root),
                "argv": arguments, "pid_file": str(pid_file) if pid_file else None}
        return [sys.executable, str(driver), str(MODULE), json.dumps(args)]

    def test_unclassified_verbose_output_status_and_streams_are_exact(self):
        source = self.root / "binary source"
        source.write_bytes(bytes(range(256)) + b"\x00\xff\r\n")
        argv = ["cp", "-v", "binary source", "binary destination"]
        original = subprocess.run(argv, executable=str(CP), cwd=self.root, input=b"untouched input", capture_output=True)
        (self.root / "binary destination").unlink()
        observed = subprocess.run(self._driver(argv), input=b"untouched input", capture_output=True)
        self.assertEqual((observed.returncode, observed.stdout, observed.stderr),
                         (original.returncode, original.stdout, original.stderr))
        self.assertEqual((self.root / "binary destination").read_bytes(), source.read_bytes())
        receipt = json.loads(next((self.root / "driver-evidence").glob("*.json")).read_bytes())
        self.assertEqual(receipt["argv"], argv)
        self.assertFalse(receipt["eligible_observation"])

    def test_failure_stderr_and_status_are_byte_exact(self):
        argv = ["cp", "absent\N{LATIN SMALL LETTER E WITH ACUTE}", "destination"]
        original = subprocess.run(argv, executable=str(CP), cwd=self.root, input=b"", capture_output=True)
        observed = subprocess.run(self._driver(argv), input=b"", capture_output=True)
        self.assertEqual((observed.returncode, observed.stdout, observed.stderr),
                         (original.returncode, original.stdout, original.stderr))

    def test_original_signal_outcome_is_forwarded_not_fabricated_exit143(self):
        fifo = self.root / "input-fifo"
        os.mkfifo(fifo)
        native = subprocess.Popen(["cp", "input-fifo", "native-destination"], executable=str(CP), cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        native.send_signal(signal.SIGTERM)
        _, native_error = native.communicate(timeout=5)
        self.assertEqual(native.returncode, -signal.SIGTERM)
        child_pid = self.root / "owned-child.pid"
        wrapper = subprocess.Popen(self._driver(["cp", "input-fifo", "wrapped-destination"], pid_file=child_pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not child_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not child_pid.exists():
            wrapper.kill()
            self.fail("controller did not observe owned cp child")
        os.kill(int(child_pid.read_text()), signal.SIGTERM)
        wrapped_out, wrapped_error = wrapper.communicate(timeout=5)
        self.assertEqual(wrapper.returncode, native.returncode)
        self.assertEqual(wrapped_out, b"")
        self.assertEqual(wrapped_error, native_error)
        receipt = json.loads(next((self.root / "driver-evidence").glob("*.json")).read_bytes())
        self.assertEqual(receipt["native_returncode"], -signal.SIGTERM)
        self.assertEqual(receipt["native_signal"], signal.SIGTERM)
        self.assertFalse(receipt["eligible_observation"])

    def test_trusted_inventory_future_completion_does_not_establish_causality(self):
        self.inventory.compile_original(self.root)
        identity = next(iter(self.inventory._outputs))
        original = self.inventory._outputs[identity]
        class BrokenInventory(m.VerifiedProducerInventory):
            def predecessor(inner, source, before):
                return dataclasses.replace(original, completed_mono_ns=before + 1)
        other = m.CaptureController(pins=self.pins, inventory=BrokenInventory(), evidence=self.root / "future")
        result = self.run_copy(controller=other)
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result, other)

    def test_trusted_inventory_wrong_path_is_rejected_even_with_equal_digest(self):
        self.inventory.compile_original(self.root)
        original = next(iter(self.inventory._outputs.values()))
        class BrokenInventory(m.VerifiedProducerInventory):
            def predecessor(inner, source, before):
                return dataclasses.replace(original, output=dataclasses.replace(source, path=source.path + ".other"))
        other = m.CaptureController(pins=self.pins, inventory=BrokenInventory(), evidence=self.root / "wrong")
        result = self.run_copy(controller=other)
        self.require_unowned(result, other)

    def test_unowned_predecessor_flags_cannot_be_promoted_by_copy(self):
        self.inventory.compile_original(self.root)
        original = next(iter(self.inventory._outputs.values()))
        class UnownedInventory(m.VerifiedProducerInventory):
            def predecessor(inner, source, before):
                return dataclasses.replace(original, source_owned=False)
        other = m.CaptureController(pins=self.pins, inventory=UnownedInventory(), evidence=self.root / "unowned")
        result = self.run_copy(controller=other)
        self.require_unowned(result, other)

    def test_tool_changes_during_operation_preserve_original_but_reject_edge(self):
        self.inventory.compile_original(self.root)
        private_cp = self.root / "actual-cp"
        shutil.copyfile(CP, private_cp)
        private_cp.chmod(0o755)
        other = m.CaptureController(pins=dataclasses.replace(self.pins, tool=private_cp), inventory=self.inventory, evidence=self.root / "changed-tool")
        result = self.run_copy(controller=other, callback=lambda pid: private_cp.chmod(0o700))
        self.assertEqual(result.returncode, 0)
        self.require_unowned(result, other)

    def test_same_source_and_destination_preserves_original_failure(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy(destination="source.o")
        native = subprocess.run(["cp", "source.o", "source.o"], executable=str(CP), cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, native.returncode)
        self.assertNotEqual(result.returncode, 0)
        self.require_unowned(result)

    def _wait_for_pid(self, path, process):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not path.exists():
            process.kill()
            process.communicate(timeout=5)
            self.fail("controller did not observe its original child")
        return int(path.read_text())

    def _group_signal_comparison(self, number):
        os.mkfifo(self.root / "group-fifo")
        native = subprocess.Popen(["cp", "group-fifo", "native-dest"], executable=str(CP), cwd=self.root,
                                  start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Wait until the actual reference blocks in open on the FIFO. It has
        # already exec'd and is alive; no guessed sleep determines its result.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if (Path("/proc") / str(native.pid) / "comm").read_text().strip() == CP.name:
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.01)
        os.killpg(native.pid, number)
        native_out, native_err = native.communicate(timeout=5)
        pid_file = self.root / "group-child.pid"
        wrapper = subprocess.Popen(self._driver(["cp", "group-fifo", "wrapped-dest"], pid_file=pid_file),
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._wait_for_pid(pid_file, wrapper)
        os.killpg(wrapper.pid, number)
        wrapped_out, wrapped_err = wrapper.communicate(timeout=5)
        self.assertEqual((wrapper.returncode, wrapped_out, wrapped_err),
                         (native.returncode, native_out, native_err))
        self.assertEqual(native.returncode, -number)
        receipt = json.loads(next((self.root / "driver-evidence").glob("*.json")).read_bytes())
        self.assertEqual(receipt["native_returncode"], -number)
        self.assertEqual(receipt["parent_signal_policy"], "relay-at-most-once-per-signal")
        self.assertEqual(receipt["parent_signals_received"], [number])
        self.assertLessEqual(receipt["parent_signals_forwarded"].count(number), 1)

    def test_whole_owned_process_group_sigint_matches_original_no_traceback(self):
        self._group_signal_comparison(signal.SIGINT)

    def test_whole_owned_process_group_sigterm_matches_original_no_traceback(self):
        self._group_signal_comparison(signal.SIGTERM)

    def test_parent_only_sigterm_relays_to_owned_child_and_matches_signal(self):
        os.mkfifo(self.root / "parent-fifo")
        pid_file = self.root / "parent-child.pid"
        wrapper = subprocess.Popen(self._driver(["cp", "parent-fifo", "parent-destination"], pid_file=pid_file),
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._wait_for_pid(pid_file, wrapper)
        wrapper.send_signal(signal.SIGTERM)
        stdout, stderr = wrapper.communicate(timeout=5)
        self.assertEqual((wrapper.returncode, stdout, stderr), (-signal.SIGTERM, b"", b""))
        receipt = json.loads(next((self.root / "driver-evidence").glob("*.json")).read_bytes())
        self.assertEqual(receipt["native_returncode"], -signal.SIGTERM)
        self.assertEqual(receipt["parent_signals_forwarded"], [signal.SIGTERM])

    def test_original_sigkill_can_be_forwarded_without_illegal_handler_call(self):
        os.mkfifo(self.root / "kill-fifo")
        pid_file = self.root / "kill-child.pid"
        wrapper = subprocess.Popen(self._driver(["cp", "kill-fifo", "kill-destination"], pid_file=pid_file),
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child = self._wait_for_pid(pid_file, wrapper)
        os.kill(child, signal.SIGKILL)
        stdout, stderr = wrapper.communicate(timeout=5)
        self.assertEqual((wrapper.returncode, stdout, stderr), (-signal.SIGKILL, b"", b""))
        receipt = json.loads(next((self.root / "driver-evidence").glob("*.json")).read_bytes())
        self.assertEqual(receipt["native_returncode"], -signal.SIGKILL)

    def test_malformed_typed_predecessor_records_are_rejected(self):
        self.inventory.compile_original(self.root)
        original = next(iter(self.inventory._outputs.values()))
        for field, value in (("source_owned", "true"), ("ocore_lowered", 1),
                             ("llvm_replay_complete", "yes"), ("verified_journal_sha256", "not-a-hash"),
                             ("producer_event", ""), ("unsupported", ["bad-type"]), ("completed_mono_ns", "old")):
            with self.subTest(field=field):
                class BrokenInventory(m.VerifiedProducerInventory):
                    def predecessor(inner, source, before):
                        return dataclasses.replace(original, **{field: value})
                other = m.CaptureController(pins=self.pins, inventory=BrokenInventory(), evidence=self.root / ("bad-" + field))
                result = self.run_copy(controller=other, destination="bad-" + field + ".o")
                self.require_unowned(result, other)

    def test_real_original_compiler_and_copy_do_not_assert_exclusive_output_window(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        facts = self.controller.verify_observation(result)
        self.assertTrue(facts["predecessor_source_owned"])
        self.assertFalse(facts["source_owned"])
        self.assertFalse(facts["destination_causality_qualified"])
        with self.assertRaisesRegex(m.EvidenceError, "exclusive output window"):
            self.controller.verify_transfer(result)

    def test_json_or_caller_flag_cannot_enable_output_ownership(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        with self.assertRaises(TypeError):
            self.controller.verify_transfer(result, source_owned=True)
        with self.assertRaises(TypeError):
            self.controller.verify_transfer(result, exclusive_window={"all_writers_managed": True})
        with self.assertRaises(m.EvidenceError):
            self.controller.verify_transfer(result)

    def test_after_cp_pasted_replacement_inode_never_gains_output_ownership(self):
        self.inventory.compile_original(self.root)
        witness = {}
        def replace_after_original_exit(pid):
            # Wait on the actual owned child without reaping it or guessing a
            # sleep, then emulate a separate untracked writer at the precise
            # old vulnerable boundary before the observer snapshots the output.
            fd = os.pidfd_open(pid)
            try:
                ready = select.poll();ready.register(fd, select.POLLIN)
                self.assertTrue(ready.poll(5000), "actual cp did not exit")
            finally:
                os.close(fd)
            destination = self.root / "installed.o"
            witness["cp_created_inode"] = destination.stat().st_ino
            replacement = self.root / "pasted-identical.o"
            replacement.write_bytes((self.root / "source.o").read_bytes())
            replacement.replace(destination)
            witness["untracked_replacement_inode"] = destination.stat().st_ino
        result = self.run_copy(callback=replace_after_original_exit)
        self.assertEqual(result.returncode, 0)
        self.assertNotEqual(witness["cp_created_inode"], witness["untracked_replacement_inode"])
        facts = self.controller.verify_observation(result)
        self.assertEqual(facts["destination"]["inode"], witness["untracked_replacement_inode"])
        self.assertFalse(facts["source_owned"])
        self.assertFalse(facts["destination_causality_qualified"])
        with self.assertRaisesRegex(m.EvidenceError, "exclusive output window"):
            self.controller.verify_transfer(result)
        (self.root / "replacement-witness.json").write_bytes(m.canonical_json({
            **witness, "native_returncode": result.returncode,
            "observed_facts": facts, "transfer_admitted": False}))

    def test_forward_normal_original_exit_code(self):
        self.inventory.compile_original(self.root)
        result = self.run_copy()
        with self.assertRaises(SystemExit) as context:
            result.forward_native_outcome()
        self.assertEqual(context.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
