"""Reject crossed identities against the actual Mode 13 source closure."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TypedKernelIdentityTests(unittest.TestCase):
    def test_process_is_not_capability_and_generation_domains_stay_distinct(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec")).resolve()
        self.assertTrue(compiler.is_file(), "current O-core compiler required")
        retained = os.environ.get("OCORE_TYPED_IDENTITY_EVIDENCE_DIR")
        if retained:
            output = Path(retained)
            output.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="typed-kernel-identities-")
            self.addCleanup(temporary.cleanup)
            output = Path(temporary.name)
        frozen = output / "ocorec"
        shutil.copyfile(compiler, frozen)
        frozen.chmod(0o755)
        arguments = output / "build-arguments.json"
        capture = output / "capture-compiler"
        capture.write_text(
            "#!" + sys.executable + "\nimport json,sys\n"
            "from pathlib import Path\n"
            "Path(" + repr(str(arguments)) + ").write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(91)\n"
        )
        capture.chmod(0o755)
        environment = dict(os.environ, OCOREC_BIN=str(capture), OCORE_PROBE_MODE="13",
                           OCORE_BUILD_DIR=str(output / "source-closure"))
        built = subprocess.run(["bash", str(ROOT / "ocore/kernel/build.sh")], cwd=ROOT,
                               env=environment, capture_output=True, timeout=120)
        (output / "capture.stdout").write_bytes(built.stdout)
        (output / "capture.stderr").write_bytes(built.stderr)
        self.assertEqual(built.returncode, 91, built.stderr.decode(errors="replace"))
        source_arguments = json.loads(arguments.read_text())
        source_arguments[source_arguments.index("--emit") + 1] = "mir"
        source_arguments = [argument for argument in source_arguments
                            if argument not in ("--function-sections", "--data-sections", "--keep-asm")]
        # These are the same real bounded-view owners used by Modes 19/24.
        # Type rejection must reach their actual APIs, not a stand-in signature.
        source_arguments.extend(str(ROOT / "ocore/runtime/x86_64" / name)
                                for name in ("personality_memory_view.oc", "delegated_resource.oc",
                                             "personality_bounded_rpc.oc"))
        production_sources = [Path(argument) for argument in source_arguments if argument.endswith(".oc")]
        source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in production_sources}
        cases = [
            ("process-as-capability", "ProcessHandle", "runtime::capability::CapabilityHandle", """
use runtime::process::ProcessHandle;
use runtime::capability::CSpaceHandle;
use runtime::capability::validate_for_owner_typed;
unsafe fn wrong(owner: CSpaceHandle, process: ProcessHandle) -> u64 {
    return validate_for_owner_typed(owner, process, 3, 8);
}
"""),
            ("cspace-generation-as-capability-generation", "CSpaceGeneration",
             "runtime::capability::CapabilityGeneration", """
use runtime::capability::CSpaceGeneration;
use runtime::capability::CapabilityGeneration;
fn accept(value: CapabilityGeneration) -> void {}
fn wrong(value: CSpaceGeneration) -> void { accept(value); }
"""),
            ("process-as-request", "ProcessHandle", "runtime::personality_rpc::PersonalityRequestHandle", """
use runtime::process::ProcessHandle;
use runtime::address_space::AddressSpaceHandle;
use runtime::capability::CSpaceHandle;
use runtime::personality_memory_view::create_typed;
unsafe fn wrong(process: ProcessHandle, address: AddressSpaceHandle, service: CSpaceHandle, result: *mut u64) -> u64 {
    return create_typed(process, process, address, 4096, 1, 1, service, result);
}
"""),
            ("resource-as-view", "DelegatedResourceHandle", "runtime::personality_memory_view::MemoryViewHandle", """
use runtime::delegated_resource::DelegatedResourceHandle;
use runtime::personality_memory_view::cancel_typed;
unsafe fn wrong(resource: DelegatedResourceHandle) -> u64 { return cancel_typed(resource); }
"""),
            ("view-as-rpc-request", "MemoryViewHandle", "runtime::personality_rpc::PersonalityRequestHandle", """
use runtime::personality_memory_view::MemoryViewHandle;
use runtime::process::ProcessHandle;
use runtime::personality_rpc::can_reply_typed;
unsafe fn wrong(view: MemoryViewHandle, process: ProcessHandle) -> u64 { return can_reply_typed(view, process, 0); }
"""),
        ]
        results = []
        for label, found, wanted, body in cases:
            source = output / (label + ".oc")
            source.write_text("module kernel::typed_identity_negative;\n" + body)
            argv = list(source_arguments)
            argv[argv.index("-o") + 1] = str(output / (label + ".mir"))
            command = [str(frozen), str(source), *argv]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            (output / (label + ".stdout")).write_bytes(result.stdout)
            (output / (label + ".stderr")).write_bytes(result.stderr)
            diagnostic = result.stderr.decode(errors="replace")
            self.assertNotEqual(result.returncode, 0, label)
            self.assertIn("expected `" + wanted + "`", diagnostic)
            self.assertIn("::" + found + "`", diagnostic)
            results.append({"case": label, "argv": command, "exit_code": result.returncode,
                            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                            "type_error_observed": True})
        report = {"scope": "compiler rejection; kernel execution is a separate gate",
                  "compiler_sha256": hashlib.sha256(frozen.read_bytes()).hexdigest(),
                  "source_sha256": source_hashes,
                  "cases": results}
        self.assertEqual(source_hashes,
                         {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in production_sources}, "source closure changed during rejection checks")
        (output / "identity-rejections.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
