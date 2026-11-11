"""Focused regressions for the manifest-driven native evidence registry."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/release_evidence.py"
SPEC = importlib.util.spec_from_file_location("release_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_evidence
SPEC.loader.exec_module(release_evidence)

REFERENCE_SPEC = importlib.util.spec_from_file_location(
    "readme_reference", ROOT / "scripts/check_readme_reference.py"
)
assert REFERENCE_SPEC is not None and REFERENCE_SPEC.loader is not None
readme_reference = importlib.util.module_from_spec(REFERENCE_SPEC)
REFERENCE_SPEC.loader.exec_module(readme_reference)


class G2Aarch64EvidenceTests(unittest.TestCase):
    def manifest(self):
        return release_evidence.load_manifest()

    def g2(self, manifest):
        return next(
            gate
            for gate in manifest["gate"]
            if gate["id"] == release_evidence.G2_AARCH64_GATE_ID
        )

    def test_checked_in_manifest_has_one_required_bounded_g2_gate(self):
        manifest = self.manifest()
        self.assertEqual(manifest["schema_version"], 2)
        gates = release_evidence.validated_gates(manifest)
        matches = [
            gate
            for gate in gates
            if gate["id"] == release_evidence.G2_AARCH64_GATE_ID
        ]
        self.assertEqual(len(matches), 1)
        gate = matches[0]
        self.assertTrue(gate["required"])
        self.assertEqual(gate["evidence_class"], "qemu_tcg_aarch64")
        self.assertEqual(gate["script"], release_evidence.G2_AARCH64_SCRIPT)
        self.assertIn("qemu-system-aarch64", gate["required_tools"])
        self.assertTrue(
            release_evidence.G2_AARCH64_REQUIRED_TOOLS
            <= set(gate["required_tools"])
        )

    def test_missing_aarch64_gate_cannot_leave_portable_aggregate_green(self):
        manifest = copy.deepcopy(self.manifest())
        gate = self.g2(manifest)
        gate["id"] = "renamed-nonqualifying-gate"
        gate["evidence_class"] = "portable_tcg"
        gate["required_tools"].append("qemu-system-x86_64")
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "exactly one qemu_tcg_aarch64 gate",
        ):
            release_evidence.validated_gates(manifest)

    def test_missing_aarch64_qemu_tool_is_rejected(self):
        manifest = copy.deepcopy(self.manifest())
        self.g2(manifest)["required_tools"].remove("qemu-system-aarch64")
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "qemu-system-aarch64.*qemu_tcg_aarch64",
        ):
            release_evidence.validated_gates(manifest)

    def test_missing_attestation_or_rebuild_tool_is_rejected(self):
        for tool in ("cmp", "git", "shasum"):
            with self.subTest(tool=tool):
                manifest = copy.deepcopy(self.manifest())
                self.g2(manifest)["required_tools"].remove(tool)
                with self.assertRaisesRegex(
                    release_evidence.EvidenceError,
                    "world-g2-aarch64-native required_tools is missing",
                ):
                    release_evidence.validated_gates(manifest)

    def test_false_physical_hardware_claim_is_rejected(self):
        manifest = copy.deepcopy(self.manifest())
        self.g2(manifest)["positive_claims"] = [
            "Physical AArch64 and SMMU isolation are proven"
        ]
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "positive claims differ from the bounded AArch64 QEMU/TCG contract",
        ):
            release_evidence.validated_gates(manifest)

    def test_linux_or_plan9_boot_claim_is_rejected(self):
        manifest = copy.deepcopy(self.manifest())
        self.g2(manifest)["nonclaims"][1] = (
            "This gate boots Linux and Plan 9 under a general foreign ABI"
        )
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "nonclaims must preserve.*foreign-OS",
        ):
            release_evidence.validated_gates(manifest)

    def test_missing_gate_script_fails_validation(self):
        gate = {
            "script": "ocore/kernel/definitely-absent-g2-gate.sh",
        }
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "required gate script is missing",
        ):
            release_evidence.validate_gate_scripts([gate])

    def test_g2_transcript_requires_every_marker_exactly_once(self):
        gate = {
            "id": release_evidence.G2_AARCH64_GATE_ID,
            "script": release_evidence.G2_AARCH64_SCRIPT,
            "expected_markers": list(release_evidence.G2_AARCH64_EXPECTED_MARKERS),
        }
        transcript = "\n".join(gate["expected_markers"]).encode("utf-8")
        gate_id, marker_count = release_evidence.verify_transcript(
            [gate], gate["script"], transcript
        )
        self.assertEqual(gate_id, release_evidence.G2_AARCH64_GATE_ID)
        self.assertEqual(marker_count, len(release_evidence.G2_AARCH64_EXPECTED_MARKERS))

        duplicated = transcript + b"\n" + gate["expected_markers"][-1].encode()
        with self.assertRaisesRegex(
            release_evidence.EvidenceError,
            "marker counts must each equal 1",
        ):
            release_evidence.verify_transcript([gate], gate["script"], duplicated)

    def test_ci_installs_and_runs_the_manifest_bound_aarch64_gate(self):
        manifest = self.manifest()
        gates = release_evidence.validated_gates(manifest)
        gate = self.g2(manifest)
        self.assertIn(gate, gates)
        release_evidence.validate(gates)

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("qemu-system-arm", workflow)


class AggregateOwnershipTests(unittest.TestCase):
    def test_ocore_reproducibility_gate_targets_the_engine_and_runs_one_test(self):
        root_source = (ROOT / "boot-and-test.sh").read_text(encoding="utf-8")
        mirror_source = (ROOT / "okernel-multikernel/boot-and-test.sh").read_text(
            encoding="utf-8"
        )
        self.assertEqual(root_source, mirror_source)
        self.assertNotIn("--package o-lang --lib", root_source)
        self.assertEqual(root_source.count("--package ostadix-api --lib"), 1)
        self.assertEqual(
            root_source.count(
                "ocore::driver::tests::"
                "ocore_object_is_byte_reproducible_across_source_directories"
            ),
            1,
        )
        self.assertIn("test result: ok. 1 passed; 0 failed;", root_source)


class InstalledCliClaimGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = (ROOT / "scripts/check_release_claims.sh").read_text(encoding="utf-8")
        function = "require_fixed() {" + script.split("require_fixed() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        block = script.split("# INSTALLED_CLI_SMOKE_CLAIMS_BEGIN\n", 1)[1].split("# INSTALLED_CLI_SMOKE_CLAIMS_END", 1)[0]
        cls.guard = "set -eu\nfail=0\n" + function + block + '\nexit "$fail"\n'
        cls.smoke = (ROOT / "scripts/smoke-project-hgraph.sh").read_text(encoding="utf-8")

    def run_guard(self, smoke):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/smoke-project-hgraph.sh").write_text(smoke, encoding="utf-8")
            return subprocess.run(["bash", "-c", self.guard], cwd=root,
                                  text=True, capture_output=True, timeout=15)

    def test_current_debug_install_smoke_satisfies_production_guard(self):
        result = self.run_guard(self.smoke)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_release_build_dependencies_fail_the_production_guard(self):
        changes = (
            ('--bin O --bin olangc --bin o-cli', '--bin olangc --bin o-cli'),
            ('--build-dir "$ROOT/target/debug"', '--build-dir "$ROOT/target/release"'),
            ('PATH="$installed_local_bin:$installed_cargo_bin:/usr/bin:/bin"',
             'PATH="$installed_local_bin:$installed_cargo_bin:$ROOT/target/release:/usr/bin:/bin"'),
        )
        for original, replacement in changes:
            with self.subTest(original=original):
                self.assertIn(original, self.smoke)
                result = self.run_guard(self.smoke.replace(original, replacement))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("WORLD CONTRACT DRIFT", result.stdout)


class ProjectExecutionClaimGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = (ROOT / "scripts/check_release_claims.sh").read_text(encoding="utf-8")
        function = "require_fixed() {" + script.split("require_fixed() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        block = script.split("# PROJECT_EXECUTION_CLAIMS_BEGIN\n", 1)[1].split("# PROJECT_EXECUTION_CLAIMS_END", 1)[0]
        cls.guard = "set -eu\nfail=0\n" + function + block + '\nexit "$fail"\n'
        cls.requirements = re.findall(r"require_fixed (\S+) \\\n    '([^']+)' \\\n    '([^']+)'", block)
        if len(cls.requirements) < 27:
            raise AssertionError("current execution/history guard lost protected contracts")
        if len(cls.requirements) != block.count("require_fixed "):
            raise AssertionError("a current project guard requirement escaped regression coverage")
        cls.surfaces = {file: (ROOT / file).read_text(encoding="utf-8") for file, _, _ in cls.requirements}

    def run_guard(self, surfaces):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for file, contents in surfaces.items():
                path = root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            return subprocess.run(["bash", "-c", self.guard], cwd=root,
                text=True, capture_output=True, timeout=15)

    def test_current_execution_and_history_contracts_satisfy_guard(self):
        result = self.run_guard(self.surfaces)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_contract_removal_fails_the_production_guard(self):
        for file, required, reason in self.requirements:
            with self.subTest(file=file, contract=required):
                self.assertIn(required, self.surfaces[file])
                changed = dict(self.surfaces)
                changed[file] = changed[file].replace(required, "contract omitted for regression test")
                result = self.run_guard(changed)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(reason, result.stdout)


class PreservedReadmeReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = (ROOT / "docs/REFERENCE.md").read_bytes()
        cls.link_map = (ROOT / "docs/readme-link-map.json").read_bytes()

    def test_exact_original_is_reconstructed_without_git_history(self):
        original = readme_reference.reconstruct_original(self.reference, self.link_map)
        self.assertEqual(len(original), 361547)
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         "3b18f2ef35c2c4449662aa185f1f798918110faab490540ee3aec7483a6b057c")
        # Recorded offsets are characters, not UTF-8 bytes.
        self.assertNotEqual(len(original), len(original.decode("utf-8")))

    def test_header_body_link_and_truncation_tampering_fail_closed(self):
        variants = (
            self.reference.replace(b"preserved source snapshot", b"amended source snapshot", 1),
            self.reference.replace(b".././assets/olang-logo.png", b".././assets/altered-logo.png", 1),
            self.reference + b"\nextra source content\n",
            self.reference[:-1],
        )
        for changed in variants:
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()):
                self.assertNotEqual(changed, self.reference)
                with self.assertRaises(readme_reference.ReferenceError):
                    readme_reference.reconstruct_original(changed, self.link_map)

    def test_link_map_cannot_redefine_original_or_hide_body_changes(self):
        for field in ("original_sha256", "reference_body_sha256", "link_relocations"):
            changed = json.loads(self.link_map)
            changed[field] = [] if field == "link_relocations" else "0" * 64
            with self.subTest(field=field), self.assertRaises(readme_reference.ReferenceError):
                readme_reference.reconstruct_original(self.reference, json.dumps(changed).encode())

    def test_cli_works_in_a_non_git_directory_and_rejects_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs/REFERENCE.md").write_bytes(self.reference)
            (root / "docs/readme-link-map.json").write_bytes(self.link_map)
            command = [sys.executable, "-B", str(ROOT / "scripts/check_readme_reference.py"),
                       "--root", str(root)]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("148 link relocations", result.stdout)
            (root / "docs/REFERENCE.md").unlink()
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("PRESERVED README DRIFT", result.stderr)

    def test_production_claim_guard_checks_reconstruction_once(self):
        script = (ROOT / "scripts/check_release_claims.sh").read_text()
        self.assertEqual(script.count("python3 scripts/check_readme_reference.py"), 1)
        self.assertEqual(script.count("python3 scripts/release_evidence.py validate"), 1)


class RootReadmeClaimGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = (ROOT / "scripts/check_release_claims.sh").read_text()
        functions = ""
        for name in ("require_fixed", "require_line"):
            functions += name + "() {" + script.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        block = script.split("# ROOT_README_CLAIMS_BEGIN\n", 1)[1].split("# ROOT_README_CLAIMS_END", 1)[0]
        cls.guard = "set -eu\nfail=0\n" + functions + block + '\nexit "$fail"\n'
        cls.readme = (ROOT / "README.md").read_text()

    def run_guard(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(source)
            return subprocess.run(["bash", "-c", self.guard], cwd=root,
                                  capture_output=True, text=True, timeout=10)

    def test_concise_root_surfaces_satisfy_guard(self):
        result = self.run_guard(self.readme)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_direct_link_and_exact_byline_remain_required(self):
        for path in ("docs/CURRENT_CONTRACT.md", "docs/CLAIMS.md", "docs/REFERENCE.md",
                     "docs/OSTADIX_WORLD.md", "docs/HOSTED_WORLD_REFERENCE_PROFILE.md",
                     "evidence/world_alpha_gates.toml"):
            with self.subTest(path=path):
                changed = self.readme.replace("(" + path + ")", "(missing-contract)")
                self.assertNotEqual(changed, self.readme)
                result = self.run_guard(changed)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        changed = self.readme.replace("*By Lee Daghlar Ostadi*",
                                      "Maintainer note: *By Lee Daghlar Ostadi*")
        self.assertNotEqual(changed, self.readme)
        result = self.run_guard(changed)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


class SetupLocalInstallClaimGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = (ROOT / "scripts/check_release_claims.sh").read_text()
        cls.block = script.split("# SETUP_LOCAL_INSTALL_CLAIMS_BEGIN\n", 1)[1].split(
            "# SETUP_LOCAL_INSTALL_CLAIMS_END", 1)[0]
        cls.setup = (ROOT / "setup.sh").read_text()

    def run_guard(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "setup.sh").write_text(source)
            command = 'ROOT="$1"\nfail=0\n' + self.block + '\nexit "$fail"\n'
            return subprocess.run(["bash", "-c", command, "setup-claim-test", str(root)],
                                  capture_output=True, text=True, timeout=15)

    def test_current_array_based_setup_routes_full_and_runtime_only_profiles(self):
        result = self.run_guard(self.setup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lost_c_runtime_only_dry_run_or_repository_route_is_rejected(self):
        for before, after in (("--include-c", "--without-c"),
                              ("--runtime-only", "--wrong-runtime-only"),
                              ("--dry-run", "--wrong-dry-run"),
                              ("$HOME/.local/bin", "$HOME/.wrong-bin"),
                              ("scripts/install_native_binaries.py", "scripts/wrong-installer.py")):
            changed = self.setup.replace(before, after)
            with self.subTest(option=before):
                self.assertNotEqual(changed, self.setup)
                result = self.run_guard(changed)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("WORLD CONTRACT DRIFT", result.stdout + result.stderr)


class NativeCInstallClaimGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = (ROOT / "scripts/check_release_claims.sh").read_text()
        cls.block = script.split("# NATIVE_INSTALLER_CLAIMS_BEGIN\n", 1)[1].split(
            "# NATIVE_INSTALLER_CLAIMS_END", 1)[0]
        cls.installer = (ROOT / "scripts/install_native_binaries.py").read_text()

    def run_guard(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/install_native_binaries.py").write_text(source)
            command = 'ROOT="$1"\nfail=0\n' + self.block + '\nexit "$fail"\n'
            return subprocess.run(["bash", "-c", command, "installer-claim-test", str(root)],
                                  capture_output=True, text=True, timeout=15)

    def test_c_front_doors_are_planned_for_posix_and_exe_without_writing_destination(self):
        result = self.run_guard(self.installer)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_missing_c_front_door_is_rejected(self):
        for alias in ("o-c", "olangc-c"):
            changed = self.installer.replace('"' + alias + '"', '"wrong-c-alias"')
            with self.subTest(alias=alias):
                self.assertNotEqual(changed, self.installer)
                result = self.run_guard(changed)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("lost a C front door", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
