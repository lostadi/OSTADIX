"""Infrastructure controls; passing these does not qualify any original runtime."""

import copy
import contextlib
import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock
import types


PATH = Path(__file__).resolve().parents[1] / "tools/ocore-runtime/acceptance/check_runtime.py"
SPEC = importlib.util.spec_from_file_location("original_runtime_acceptance", PATH)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def profile():
    return {"schema": acceptance.SCHEMA, "name": "infrastructure-control-only",
            "implementation": {"kind": "compiler", "upstream_url": "https://example.invalid/original.git", "revision": "1" * 40,
                               "source_checkout": "/original", "recipe": {"path": "/recipe.json", "sha256": "2" * 64}, "build_step": "original-build"},
            "requirements": {"delivery": "native", "resource_profile": "ostadix-kernel", "compiler_output_routing": True,
                             "jit_generation": False, "jit_publication": False, "jit_invalidation": False},
            "targets": [{"id": "required-real-target", "target": "riscv64-unknown-none", "native_target": None, "jobs": 1,
                         "unit_inventory": "unit-inventory.json", "frontend_tools": {}, "import_profiles": {}, "provider_profiles": [],
                         "programs": [{"name": "original", "kind": "program", "required_units": ["body", "data"], "reference_output": "original", "upstream_targets": ["test-all"], "behavior_driver": None}]}]}


def captures():
    return {"capture_complete": True, "unit_roles_complete": True, "unclassified_unit_ids": [], "lowering_unit_ids": ["a", "b"],
            "units": [{"id": "a"}, {"id": "b"}], "required_units": [{"id": "body", "captured_unit_ids": ["a"]}, {"id": "data", "captured_unit_ids": ["b"]}]}


def diagnostic_target(architecture="riscv64", abi="lp64d"):
    return {"target": architecture + "-unknown-none",
            "native_target": {"triple": architecture + "-unknown-linux-gnu", "pointer_bits": 64,
                              "little_endian": True, "abi": abi}}

def diagnostic_elf(machine=243, flags=4):
    # Complete ELF64 ET_REL envelope with one null section; no machine code claim.
    header = bytearray(128)
    header[:7] = b"\x7fELF\x02\x01\x01"
    for offset, size, value in [(16, 2, 1), (18, 2, machine), (20, 4, 1),
                                (40, 8, 64), (48, 4, flags), (52, 2, 64),
                                (58, 2, 64), (60, 2, 1)]:
        header[offset:offset + size] = value.to_bytes(size, "little")
    return bytes(header)

class OriginalRuntimeAcceptanceControls(unittest.TestCase):

    def test_diagnostic_object_identity_uses_consumed_stream_without_artifact_reopen(self):
        with tempfile.TemporaryDirectory(prefix="ocore-elf-consumed-") as directory:
            obj = Path(directory) / "diagnostic.o"
            data = diagnostic_elf(); obj.write_bytes(data)
            with mock.patch.object(acceptance, "artifact", side_effect=AssertionError("separate artifact reopen")) as reopened:
                result = acceptance.check_diagnostic_object(obj, diagnostic_target())
            reopened.assert_not_called()
            self.assertEqual({key: result[key] for key in ("path", "bytes", "sha256")},
                             {"path": str(obj.resolve()), "bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
            self.assertEqual(result["elf_machine"], 243)


    def test_diagnostic_object_rejects_replacement_during_stream_consumption(self):
        with tempfile.TemporaryDirectory(prefix="ocore-elf-replace-") as directory:
            obj = Path(directory) / "diagnostic.o"; obj.write_bytes(diagnostic_elf())
            before = acceptance.artifact(obj); before_stat = obj.stat()
            replacement = Path(directory) / "replacement.o"
            replacement.write_bytes(diagnostic_elf(62, 0))
            observations = {"reads": 0, "replacements": 0}
            original_open = Path.open
            @contextlib.contextmanager
            def replacing_open(path, *args, **kwargs):
                with original_open(path, *args, **kwargs) as stream:
                    proxy = mock.Mock(wraps=stream)
                    def read(size=-1):
                        observations["reads"] += 1
                        data = stream.read(size)
                        if replacement.exists():
                            replacement.replace(obj)
                            observations["replacements"] += 1
                        return data
                    proxy.read.side_effect = read
                    yield proxy
            with mock.patch.object(Path, "open", replacing_open):
                with self.assertRaisesRegex(acceptance.Unmet, "changed while consuming ELF bytes"):
                    acceptance.check_diagnostic_object(obj, diagnostic_target())
            self.assertGreaterEqual(observations["reads"], 1)
            self.assertEqual(observations["replacements"], 1)
            self.assertNotEqual((before_stat.st_dev, before_stat.st_ino),
                                (obj.stat().st_dev, obj.stat().st_ino))
            self.assertNotEqual(acceptance.artifact(obj)["sha256"], before["sha256"])
            self.assertEqual(int.from_bytes(obj.read_bytes()[18:20], "little"), 62)


    def test_diagnostic_object_rejects_same_inode_mutation_during_stream_consumption(self):
        with tempfile.TemporaryDirectory(prefix="ocore-elf-mutate-") as directory:
            obj = Path(directory) / "diagnostic.o"; obj.write_bytes(diagnostic_elf())
            before = acceptance.artifact(obj); before_stat = obj.stat()
            observations = {"reads": 0, "mutations": 0}
            original_open = Path.open
            @contextlib.contextmanager
            def mutating_open(path, *args, **kwargs):
                with original_open(path, *args, **kwargs) as stream:
                    proxy = mock.Mock(wraps=stream)
                    def read(size=-1):
                        observations["reads"] += 1
                        data = stream.read(size)
                        if observations["mutations"] == 0:
                            with original_open(obj, "r+b") as writer:
                                writer.seek(127); writer.write(b"x"); writer.flush()
                            info = obj.stat()
                            os.utime(obj, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
                            observations["mutations"] += 1
                        return data
                    proxy.read.side_effect = read
                    yield proxy
            with mock.patch.object(Path, "open", mutating_open):
                with self.assertRaisesRegex(acceptance.Unmet, "changed while consuming ELF bytes"):
                    acceptance.check_diagnostic_object(obj, diagnostic_target())
            self.assertGreaterEqual(observations["reads"], 1)
            self.assertEqual(observations["mutations"], 1)
            after_stat = obj.stat(); after = acceptance.artifact(obj)
            self.assertEqual((before_stat.st_dev, before_stat.st_ino),
                             (after_stat.st_dev, after_stat.st_ino))
            self.assertEqual(before["bytes"], after["bytes"])
            self.assertNotEqual(before["sha256"], after["sha256"])
            self.assertEqual(obj.read_bytes()[-1:], b"x")
            self.assertEqual(int.from_bytes(obj.read_bytes()[18:20], "little"), 243)


    def test_readmit_unit_returns_the_exact_validated_diagnostic_object_pin(self):
        original_check = acceptance.check_diagnostic_object; captures = []
        def observing_check(path, target):
            result = original_check(path, target); captures.append(copy.deepcopy(result))
            return result
        with tempfile.TemporaryDirectory(prefix="ocore-readmit-object-pin-") as directory:
            with mock.patch.object(acceptance, "check_diagnostic_object", observing_check):
                result = self._diagnostic_readmission_with_inert_commands(Path(directory))
            self.assertEqual(len(captures), 1)
            self.assertEqual(result["diagnostic_object_profile"], captures[0])
            expected = {key: captures[0][key] for key in ("path", "bytes", "sha256")}
            self.assertEqual(result["fresh_owned_diagnostic_object"], expected)
            self.assertEqual(acceptance.artifact(expected["path"]), expected)
            self.assertIs(result["complete_olangc_artifact"], False)


    def test_readmit_unit_rejects_object_replacement_after_profile_validation(self):
        original_check = acceptance.check_diagnostic_object; captures = []
        def replacing_check(path, target):
            result = original_check(path, target)
            before = acceptance.artifact(path); before_stat = Path(path).stat()
            replacement = Path(path).with_name("replacement-after-validation.o")
            replacement.write_bytes(diagnostic_elf(62, 0)); replacement.replace(path)
            after = acceptance.artifact(path); after_stat = Path(path).stat()
            captures.append({"validated": copy.deepcopy(result), "before": before, "after": after,
                "inode_before": (before_stat.st_dev, before_stat.st_ino),
                "inode_after": (after_stat.st_dev, after_stat.st_ino),
                "machine_after": int.from_bytes(Path(path).read_bytes()[18:20], "little")})
            return result
        with tempfile.TemporaryDirectory(prefix="ocore-readmit-replace-") as directory:
            with mock.patch.object(acceptance, "check_diagnostic_object", replacing_check):
                with self.assertRaisesRegex(acceptance.Unmet, "file bytes differ from pin"):
                    self._diagnostic_readmission_with_inert_commands(Path(directory))
            self.assertEqual(len(captures), 1)
            captured = captures[0]
            self.assertEqual(captured["validated"]["elf_machine"], 243)
            self.assertEqual({key: captured["validated"][key] for key in ("path", "bytes", "sha256")}, captured["before"])
            self.assertNotEqual(captured["inode_before"], captured["inode_after"])
            self.assertNotEqual(captured["before"]["sha256"], captured["after"]["sha256"])
            self.assertEqual(captured["machine_after"], 62)
            self.assertEqual(acceptance.artifact(captured["after"]["path"]), captured["after"])


    def test_readmit_unit_rejects_mismatched_validated_identity(self):
        original_check = acceptance.check_diagnostic_object
        for field, value in (("sha256", "0" * 64), ("bytes", 129)):
            captures = []
            with self.subTest(field=field):
                def mismatched_check(path, target):
                    genuine = original_check(path, target)
                    returned = dict(genuine); returned[field] = value
                    captures.append({"genuine": copy.deepcopy(genuine), "returned": copy.deepcopy(returned),
                                     "actual": acceptance.artifact(path)})
                    return returned
                with tempfile.TemporaryDirectory(prefix="ocore-readmit-mismatch-") as directory:
                    with mock.patch.object(acceptance, "check_diagnostic_object", mismatched_check):
                        with self.assertRaisesRegex(acceptance.Unmet, "file bytes differ from pin"):
                            self._diagnostic_readmission_with_inert_commands(Path(directory))
                    self.assertEqual(len(captures), 1)
                    captured = captures[0]
                    self.assertEqual(captured["returned"][field], value)
                    self.assertNotEqual(captured["genuine"][field], value)
                    self.assertEqual(captured["genuine"]["elf_machine"], 243)
                    self.assertEqual({key: captured["genuine"][key] for key in ("path", "bytes", "sha256")}, captured["actual"])
                    self.assertEqual(acceptance.artifact(captured["actual"]["path"]), captured["actual"])


    def test_diagnostic_object_accepts_matching_implemented_isa_headers(self):
        with tempfile.TemporaryDirectory(prefix="ocore-elf-envelope-") as directory:
            obj = Path(directory) / "diagnostic.o"
            for architecture, machine, flags, abi in [("x86_64", 62, 0, None),
                    ("aarch64", 183, 0, None), ("riscv64", 243, 4, "lp64d"),
                    ("riscv64", 243, 5, "lp64d"), ("riscv64", 243, 0, "lp64")]:
                with self.subTest(architecture=architecture, flags=flags):
                    obj.write_bytes(diagnostic_elf(machine, flags))
                    checked = acceptance.check_diagnostic_object(obj, diagnostic_target(architecture, abi))
                    self.assertEqual(checked["elf_machine"], machine)
                    self.assertEqual(checked["elf_flags"], flags)
                    self.assertEqual(checked["sha256"], acceptance.digest(obj))


    def test_diagnostic_object_rejects_wrong_isa_abi_and_malformed_envelopes(self):
        baseline = diagnostic_elf()
        controls = {"magic-only": b"\x7fELF", "former-synthetic-magic-only": b"\x7fELFsynthetic-control-only",
                    "wrong-machine": diagnostic_elf(62), "wrong-riscv-float-abi": diagnostic_elf(flags=0),
                    "unsupported-riscv-flags": diagnostic_elf(flags=12), "truncated-section": baseline[:-1]}
        for name, offset, value in [("elf32", 4, b"\x01"), ("big-endian", 5, b"\x02"),
                ("ident-version", 6, b"\x00"), ("executable", 16, b"\x02\x00"),
                ("header-version", 20, b"\x00"), ("header-size", 52, b"\x00"),
                ("section-stride", 58, b"\x00"), ("missing-sections", 60, b"\x00"),
                ("invalid-shstrndx", 62, b"\x02\x00")]:
            altered = bytearray(baseline); altered[offset:offset + len(value)] = value
            controls[name] = bytes(altered)
        with tempfile.TemporaryDirectory(prefix="ocore-elf-negative-") as directory:
            obj = Path(directory) / "diagnostic.o"
            for name, data in controls.items():
                with self.subTest(name=name):
                    obj.write_bytes(data)
                    with self.assertRaises(acceptance.Unmet):
                        acceptance.check_diagnostic_object(obj, diagnostic_target())


    def test_diagnostic_object_rejects_missing_target_validation_profile(self):
        with tempfile.TemporaryDirectory(prefix="ocore-elf-profile-") as directory:
            obj = Path(directory) / "diagnostic.o"; obj.write_bytes(diagnostic_elf())
            controls = [diagnostic_target("unimplemented"), diagnostic_target("i686"),
                        diagnostic_target("armv7"), diagnostic_target("riscv64", "unsupported-abi")]
            for field, value in [("pointer_bits", 32), ("little_endian", False), ("triple", "x86_64-unknown-linux-gnu")]:
                target = diagnostic_target(); target["native_target"][field] = value; controls.append(target)
            for target in controls:
                with self.subTest(target=target):
                    with self.assertRaises(acceptance.Unmet):
                        acceptance.check_diagnostic_object(obj, target)


    def _diagnostic_readmission_with_inert_commands(self, directory):
        # Exercise the actual Runner method with inert command/Reader doubles.
        # This is object receipt binding evidence, never real compiler admission.
        target = diagnostic_target(); target["import_profiles"] = {}
        raw = directory / "original.ll"; raw.write_bytes(b"inert LLVM identity control")
        module = {"target": target["native_target"],
                  "provenance": {"input_sha256": acceptance.digest(raw)}}
        claimed = directory / "claimed.json"; claimed.write_text(json.dumps(module))
        compiler = directory / "inert-compiler"; compiler.write_bytes(b"inert command test double, never executed")
        parser = directory / "inert-parser"; parser.write_bytes(b"inert parser test double, never executed")
        class Reader:
            def read(self, path): return {"inert_reader": True}
        class Inventory:
            def check_inventory(self, original, canonical): return {"inert_inventory": True}
        class Harness:
            tools = {"ocorec": acceptance.artifact(compiler),
                     "llvm_library": acceptance.artifact(parser)}
            reader = Reader(); inventory = Inventory()
            def command(self, argv, cwd, label):
                if argv[1:] == ["--help"]:
                    stdout = cwd / (label + ".stdout"); stdout.write_text("legacy inert compiler help\n")
                    stderr = cwd / (label + ".stderr"); stderr.write_bytes(b"")
                    return {"exit_code": 0, "inert_command": True,
                            "stdout": acceptance.artifact(stdout), "stderr": acceptance.artifact(stderr)}
                if "--verify-native" in argv:
                    output = Path(argv[argv.index("--receipt") + 1])
                    output.write_text(json.dumps({"verified": True,
                        "module_sha256": acceptance.digest(argv[1])}))
                else:
                    output = Path(argv[argv.index("-o") + 1])
                    if argv[argv.index("--emit") + 1] == "mir":
                        output.write_text(json.dumps(module))
                    else: output.write_bytes(diagnostic_elf())
                return {"exit_code": 0, "inert_command": True}
        return acceptance.Runner.readmit_unit(Harness(), {"llvm_ir": acceptance.artifact(raw)},
                    acceptance.artifact(claimed), target, directory)

    def test_original_recipe_required_rule_cannot_be_removed_from_capture(self):
        original = {"coverage": {"required_units": [{"id": "body"}, {"id": "cold"}]}}
        forged = {"required_units": [{"id": "body", "captured_unit_ids": ["body"]}]}
        with self.assertRaisesRegex(acceptance.Unmet, "ORIGINAL recipe"):
            acceptance.check_recipe_partition(original, forged)

    def test_required_rule_source_cannot_be_substituted(self):
        original = {"coverage": {"required_units": [{"id": "body", "source": "body.c"}]}}
        forged = {"required_units": [{"id": "body", "source": "rewrite.c", "captured_unit_ids": ["body"]}]}
        with self.assertRaisesRegex(acceptance.Unmet, "rule changed"):
            acceptance.check_recipe_partition(original, forged)

    def test_unverified_evidence_is_never_a_green_stage(self):
        class Harness:
            record = {}
            def save(self): pass
        harness = Harness(); target = {"stages": []}
        def unsupported(): raise acceptance.Unverified("not independently reconstructed")
        row = acceptance.Runner.stage(harness, target, "capture", unsupported)
        self.assertEqual(row["status"], "UNVERIFIED")

    def test_profile_configuration_is_not_qualification(self):
        self.assertEqual(acceptance.validate_profile(profile())["name"], "infrastructure-control-only")
        with self.assertRaisesRegex(acceptance.Unmet, "complete runtime artifact"):
            acceptance.complete_artifact_gate({"artifact_complete": False}, {"artifact_complete": False})

    def test_required_zero_target_matrix_is_not_a_pass(self):
        value = profile(); value["targets"] = []
        with self.assertRaisesRegex(acceptance.Unmet, "cannot be empty"):
            acceptance.validate_profile(value)

    def test_tls_import_profile_preserves_the_declared_string(self):
        value = profile()
        declared = {"--tls-profile": "linux-elf-static-nonpreemptive-v1"}
        value["targets"][0]["import_profiles"] = declared.copy()
        self.assertEqual(acceptance.validate_profile(value)["targets"][0]["import_profiles"], declared)

    def test_unknown_or_malformed_import_profiles_are_rejected(self):
        invalid = [[], None, {"--tls-profil": "x"}, {"--tls-profile=x": "x"},
                   {"--tls-profile": "x", "--unknown-profile": "x"}]
        invalid += [{"--tls-profile": value} for value in [None, 1, True, [], {}]]
        for declaration in invalid:
            with self.subTest(declaration=declaration):
                value = profile(); value["targets"][0]["import_profiles"] = declaration
                with self.assertRaises(acceptance.Unmet):
                    acceptance.validate_profile(value)

    def test_compiler_output_routing_cannot_be_silently_disabled(self):
        value = profile(); value["requirements"]["compiler_output_routing"] = False
        with self.assertRaisesRegex(acceptance.Unmet, "cannot be disabled"):
            acceptance.validate_profile(value)

    def test_all_jit_paths_are_required_for_jit_engine(self):
        value = profile(); value["implementation"]["kind"] = "jit_engine"
        with self.assertRaisesRegex(acceptance.Unmet, "all generated-code gates"):
            acceptance.validate_profile(value)

    def test_supplied_runtime_executable_is_not_an_input_contract(self):
        value = profile(); value["supplied_runtime_executable"] = "/foreign/runtime"
        with self.assertRaisesRegex(acceptance.Unmet, "profile fields differ"):
            acceptance.validate_profile(value)

    def test_handwritten_runtime_and_implementation_ir_interpreter_modes_are_not_accepted(self):
        for mode in ["handwritten-runtime", "implementation-ir-interpreter"]:
            with self.subTest(mode=mode):
                value = profile(); value["implementation"]["kind"] = mode
                with self.assertRaisesRegex(acceptance.Unmet, "implementation role"):
                    acceptance.validate_profile(value)

    def test_original_required_units_cannot_be_silently_dropped(self):
        with self.assertRaisesRegex(acceptance.Unmet, "silently omits"):
            acceptance.check_selected_units(captures(), {"units": [{"id": "a"}]})

    def test_zero_imports_cannot_qualify_a_runtime(self):
        with self.assertRaisesRegex(acceptance.Unmet, "silently omits"):
            acceptance.check_selected_units(captures(), {"units": []})

    def test_duplicate_native_unit_cannot_replace_a_missing_unit(self):
        with self.assertRaisesRegex(acceptance.Unmet, "duplicate native"):
            acceptance.check_selected_units(captures(), {"units": [{"id": "a"}, {"id": "a"}]})

    def test_partial_original_capture_is_not_admitted(self):
        value = captures(); value["capture_complete"] = False
        with self.assertRaisesRegex(acceptance.Unmet, "capture/role inventory incomplete"):
            acceptance.check_selected_units(value, {"units": [{"id": "a"}, {"id": "b"}]})

    def test_program_graph_cannot_drop_data_or_initializer_unit(self):
        programs = copy.deepcopy(profile()["targets"][0]["programs"]); programs[0]["required_units"] = ["body"]
        with self.assertRaisesRegex(acceptance.Unmet, "drops required"):
            acceptance.check_program_graph(captures(), programs)

    def test_program_graph_is_not_complete_artifact_admission(self):
        proof = acceptance.check_program_graph(captures(), profile()["targets"][0]["programs"])
        self.assertEqual(proof["required_units_accounted"], 2)
        self.assertIs(proof["complete_olangc_artifact"], False)

    def test_target_abi_and_profiles_must_match_exactly(self):
        target = {"triple": "riscv64-unknown-linux-gnu", "abi": "lp64d", "data_layout": "original"}
        for field, bad in [("triple", "x86_64-unknown-linux-gnu"), ("abi", "lp64"), ("data_layout", "substituted")]:
            with self.subTest(field=field):
                altered = dict(target, **{field: bad})
                with self.assertRaisesRegex(acceptance.Unmet, "profile mismatch"):
                    acceptance.check_target({"target": altered}, target)

    def test_missing_actual_target_profile_is_red(self):
        with self.assertRaisesRegex(acceptance.Unmet, "not pinned"):
            acceptance.check_target({"target": {}}, None)

    def test_forged_complete_flags_do_not_admit_supplied_manifests_or_manual_links(self):
        with self.assertRaisesRegex(acceptance.Unmet, "public olangc whole-runtime artifact validator"):
            acceptance.complete_artifact_gate({"artifact_complete": True}, {"artifact_complete": True})


    def test_recipe_floor_allows_exact_finalized_inventory_additions(self):
        original = {"coverage": {"required_units": [{"id": "body", "source": "body.c"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
                     "units": [{"id": "inventory:cold", "source": "cold.c"}]}
        capture = {"required_units": [{"id": "body", "source": "body.c", "captured_unit_ids": ["a"]},
                                      {"id": "inventory:cold", "source": "cold.c", "captured_unit_ids": ["b"]}]}
        self.assertEqual(set(acceptance.check_recipe_partition(original, capture, finalized)), {"body", "inventory:cold"})

    def test_finalized_inventory_addition_cannot_be_omitted_from_capture(self):
        original = {"coverage": {"required_units": [{"id": "body"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
                     "units": [{"id": "inventory:cold"}]}
        with self.assertRaisesRegex(acceptance.Unmet, "missing=.*inventory:cold"):
            acceptance.check_recipe_partition(original, {"required_units": [{"id": "body", "captured_unit_ids": ["a"]}]}, finalized)

    def test_capture_cannot_invent_rules_outside_finalized_inventory(self):
        original = {"coverage": {"required_units": [{"id": "body"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True, "units": [{"id": "inventory:cold"}]}
        capture = {"required_units": [{"id": name, "captured_unit_ids": [name]} for name in ["body", "inventory:cold", "invented"]]}
        with self.assertRaisesRegex(acceptance.Unmet, "added=.*invented"):
            acceptance.check_recipe_partition(original, capture, finalized)

    def _forged_cli(self, pinned_worker, partial_valid=False, catalog_mode=None, target_count=1, prerequisite_mode=None):
        # Exact retained adversarial producer: a real child process forges flags
        # while omitting a required original unit. This is not a runtime fixture.
        producer = """#!/usr/bin/python3
import pathlib,sys,json,hashlib
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);(out/'capture').mkdir(parents=True);(out/'lowered').mkdir()
sibling=pathlib.Path(__file__).parent/'ocorec'
compiler_sha=hashlib.sha256(sibling.read_bytes()).hexdigest()
capture={'capture_complete':True,'unit_roles_complete':True,'unclassified_unit_ids':[],'lowering_unit_ids':['body'],'units':[{'id':'body'}],'required_units':[{'id':'body','captured_unit_ids':['body']}]}
coverage={'compiler_sha256':compiler_sha,'units':[{'id':'body','verified':False,'lowered':False,'failure':'no import ever performed'}],'native_module_dependency_closure_complete':True,'symbol_closure_complete':True,'artifact_complete':True}
for name,value in [('capture/report.json',capture),('lowered/coverage.json',coverage),('source-recipe.json',{'success':True,'capture_complete':True,'artifact_complete':True})]: (out/name).write_text(json.dumps(value))
"""
        self.assertEqual(hashlib.sha256(producer.encode()).hexdigest(), "5e7909da81b98e9011415f9c25ea58fcd94e77d40c15d6ab03e8d6b06064a131")
        retained = os.environ.get("OCORE_ACCEPTANCE_CONTROL_OUTPUT")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            context = contextlib.nullcontext(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=retained))
        else:
            context = tempfile.TemporaryDirectory(prefix="ocore-forged-receipt-control-")
        with context as temporary:
            root = Path(temporary); source = root / "synthetic-original"; source.mkdir()
            (source / "body.c").write_text("int body(void) { return 1; }\n")
            (source / "cold.c").write_text("int original_cold_initializer = 42;\n")
            def git(*args):
                return subprocess.check_output(["git", "-C", str(source), *args], text=True, stderr=subprocess.PIPE).strip()
            git("init", "--quiet"); git("add", "body.c", "cold.c")
            git("-c", "user.name=Lee Daghlar Ostadi", "-c", "user.email=ostadi.lee@gmail.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Synthetic acceptance regression fixture only")
            git("remote", "add", "origin", "https://example.invalid/original.git")
            revision = git("rev-parse", "HEAD")
            recipe = {"schema": "ocore-runtime-recipe-v1", "name": "adversarial-original-fixture",
                      "source": {"url": "https://example.invalid/original.git", "revision": revision},
                      "commands": [{"name": "original-build", "argv": ["never-executed-build"]}],
                      "coverage": {"require_full_unit_inventory": True, "required_units": [{"id": n, "kind": "clang", "source": n + ".c"} for n in ["body", "cold"]]}}
            recipe_path = root / "recipe.json"; recipe_path.write_text(json.dumps(recipe))
            producer_path = root / "olangc"; producer_path.write_text(producer); producer_path.chmod(0o700)
            core = root / "ocorec"; core.write_text("#!/usr/bin/python3\nraise SystemExit('unexpected compiler invocation')\n"); core.chmod(0o700)
            library = root / "synthetic-parser"; library.write_bytes(b"unused synthetic parser pin")
            helper = root / "inventory_helper.py"; helper.write_text("# Synthetic negative control: no source inventory calls are permitted.\n")
            if partial_valid:
                # Explicit compiler/inventory test doubles make one candidate
                # GREEN. No real backend or whole-runtime proof is claimed.
                raw = root / "body.ll"; raw.write_text("define i32 @body() { ret i32 1 }\n")
                module = root / "body.native-ir.json"
                module.write_text(json.dumps({"target": diagnostic_target()["native_target"], "provenance": {"input_sha256": acceptance.digest(raw)}}))
                recipe["coverage"]["required_units"] = recipe["coverage"]["required_units"][:1]
                recipe_path.write_text(json.dumps(recipe))
                helper.write_text("class Reader:\n def __init__(self,*args): pass\n def read(self,path): return {}\ndef check_inventory(*args): return {'synthetic_control_only':True}\n")
                core.write_text(
                    "#!/usr/bin/python3\nimport sys,pathlib,json,hashlib\na=sys.argv\n"
                    "if a[1:]==['--help']: print('legacy synthetic compiler help')\n"
                    "elif '--verify-native' in a:\n"
                    " p=pathlib.Path(a[a.index('--receipt')+1]);p.write_text(json.dumps({'verified':True,'module_sha256':hashlib.sha256(pathlib.Path(a[1]).read_bytes()).hexdigest()}))\n"
                    "elif '--emit' in a:\n"
                    " p=pathlib.Path(a[a.index('-o')+1])\n"
                    " if a[a.index('--emit')+1]=='mir':\n"
                    f"  p.write_bytes(pathlib.Path({str(module)!r}).read_bytes())\n"
                    " else:\n"
                    f"  data=bytearray.fromhex({diagnostic_elf().hex()!r})\n"
                    f"  native=json.loads(pathlib.Path({str(module)!r}).read_text())['target']\n"
                    "  data[48:52]=(4 if native.get('abi')=='lp64d' else 0).to_bytes(4,'little');p.write_bytes(data)\n"
                    "else: raise SystemExit(1)\n"
                )
                patch = "capture['units'][0]['ir']=" + repr(acceptance.artifact(raw)) + "\n"
                patch += "capture['required_units'][0].update(kind='clang',source='body.c')\n"
                patch += "coverage['units'][0].update(verified=True,lowered=True,module=" + repr(acceptance.artifact(module)) + ")\n"
                patch += "(out/'build').mkdir();(out/'build/unit-inventory.json').write_text(" + repr(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,"units":[{"id":"inventory:cold","kind":"clang","source":"cold.c"}]})) + ")\n"
                producer_path.write_text(producer.replace("for name,value in", patch + "for name,value in"))
            value = profile(); value["implementation"].update(source_checkout=str(source), revision=revision, recipe=acceptance.artifact(recipe_path))
            value["targets"][0]["programs"][0]["required_units"] = ["body"] if partial_valid else ["body", "cold"]
            if partial_valid: value["targets"][0]["native_target"] = diagnostic_target()["native_target"]
            value["targets"] = [copy.deepcopy(value["targets"][0]) for _ in range(target_count)]
            for index, target in enumerate(value["targets"]):
                if index: target["id"] += "-" + str(index)
            if prerequisite_mode:
                self._declare_isa_prerequisites(root, value, prerequisite_mode)
            if catalog_mode:
                catalog = self._synthetic_catalog(catalog_mode)
                prefix = "#!/usr/bin/python3\nimport sys,json\nif sys.argv[1:]==['--list-targets']:\n"
                if catalog_mode == "unsupported":
                    prefix += " sys.stderr.write('synthetic compiler catalog unsupported\\n');raise SystemExit(2)\n"
                else:
                    if catalog_mode == "mutate_tool":
                        prefix += " import pathlib\n p=pathlib.Path(__file__);p.with_name('ocorec.before-catalog').write_bytes(p.read_bytes());p.write_bytes(p.read_bytes()+b'\\n# synthetic catalog tool mutation\\n')\n"
                    if catalog_mode == "mutate_input":
                        prefix += " import pathlib\n p=pathlib.Path(" + repr(str(root / "synthetic-isa-prerequisites.json")) + ");p.with_name('prerequisites.before-catalog.json').write_bytes(p.read_bytes());p.write_bytes(p.read_bytes()+b'\\n')\n"
                    prefix += " print(" + repr(json.dumps(catalog)) + ");raise SystemExit(0)\n"
                core.write_text(prefix + core.read_text().split("\n", 1)[1])
            profile_path = root / "profile.json"; profile_path.write_text(json.dumps(value))
            tools = {"olangc": acceptance.artifact(producer_path), "ocorec": acceptance.artifact(core), "llvm_library": acceptance.artifact(library), "inventory_helper": acceptance.artifact(helper)}
            if pinned_worker:
                tools["capture_verifier"] = acceptance.artifact(PATH.parents[3] / "scripts/ocore_runtime_capture.py")
            if prerequisite_mode: tools["cc"] = acceptance.artifact(root / "synthetic-frontend")
            toolchain = root / "tools.json"; toolchain.write_text(json.dumps({"schema": acceptance.TOOL_SCHEMA, "tools": tools, "environment": {}}))
            output = root / "result"
            argv = [sys.executable, "-I", str(PATH), str(profile_path), "--tools", str(toolchain), "--output", str(output)]
            process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            (root / "cli.stdout").write_text(process.stdout)
            (root / "cli.stderr").write_text(process.stderr)
            invocation = {"schema": "ocore-synthetic-acceptance-cli-control-v1", "method": self._testMethodName,
                          "argv": argv, "exit_code": process.returncode, "profile": acceptance.artifact(profile_path),
                          "toolchain": acceptance.artifact(toolchain), "stdout": acceptance.artifact(root / "cli.stdout"),
                          "stderr": acceptance.artifact(root / "cli.stderr"), "synthetic_control_only": True,
                          "runtime_accepted": False}
            if (output / "report.json").exists(): invocation["report"] = acceptance.artifact(output / "report.json")
            for original in ["ocorec.before-catalog", "prerequisites.before-catalog.json"]:
                if (root / original).exists(): invocation["mutation_original_" + original] = acceptance.artifact(root / original)
            (root / "cli-invocation.json").write_text(json.dumps(invocation, indent=2) + "\n")
            self.assertEqual(process.returncode, 1, process.stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "RED"); self.assertFalse(report["runtime_accepted"])
            if catalog_mode == "mutate_tool":
                self.assertFalse(report["tools_stable"])
                catalog_calls = [c for c in report["commands"] if c["argv"] == [str(core), "--list-targets"]]
                self.assertEqual(len(catalog_calls), 1)
                return report
            self.assertTrue(report["tools_stable"])
            target = report["targets"][0]; stages = {row["name"]: row for row in target["stages"]}
            self.assertEqual(stages["pinned_source_and_recipe_identity"]["status"], "GREEN")
            self.assertIn("no build execution", stages["pinned_source_and_recipe_identity"]["scope"])
            self.assertEqual(stages["original_source_and_build"]["status"], "UNVERIFIED")
            self.assertIn("does not prove original build execution", stages["original_source_and_build"]["diagnostic"])
            for name in ["olangc_owned_source_pipeline", "independent_capture_admission", "complete_original_unit_selection", "original_program_graph", "original_provider_and_native_symbol_closure"]:
                self.assertNotEqual(stages[name]["status"], "GREEN", name)
            if partial_valid:
                self.assertEqual(stages["complete_original_unit_selection"]["status"], "UNVERIFIED")
                expected_unit_status = "RED" if prerequisite_mode == "empty_native" else "GREEN"
                self.assertEqual([row["status"] for row in target["units"]], [expected_unit_status])
                if prerequisite_mode == "empty_native":
                    self.assertIn("native target and diagnostic ELF profile differ", target["units"][0]["diagnostic"])
                self.assertEqual(stages["all_original_units_independently_checked"]["status"], "UNVERIFIED")
            else:
                self.assertEqual(stages["complete_original_unit_selection"]["status"], "RED")
                self.assertTrue(any(row["id"] == "missing-original-rule:cold" for row in target["units"]))
            catalog_commands = [command for command in report["commands"] if command["argv"] == [str(core), "--list-targets"]]
            self.assertEqual(len(catalog_commands), 1, "selected compiler catalog must actually be invoked once")
            self.assertEqual(report["isa_inputs_stable"], catalog_mode != "mutate_input")
            self.assertFalse(report["all_isa_identity_qualified"])
            forbidden = [command for command in report["commands"] if command["argv"][0] == str(core) and command["argv"][1:] != ["--list-targets"]]
            if partial_valid:
                help_commands = [command for command in forbidden if command["argv"][1:] == ["--help"]]
                self.assertEqual(len(help_commands), 1, "actual selected helper capability is discovered once across units")
                forbidden = [command for command in forbidden if command["argv"][1:] != ["--help"]]
                self.assertEqual(len(forbidden), 5 * target_count, "only explicitly synthetic verify/canonicalize/import/verify/emit doubles were exercised")
                self.assertTrue(all(command["exit_code"] == 0 for command in forbidden))
                self.assertEqual(sum("--verify-native" in command["argv"] for command in forbidden), 2 * target_count)
                emits = [command["argv"] for command in forbidden if "--emit" in command["argv"]]
                self.assertEqual([(argv[argv.index("--input-kind") + 1], argv[argv.index("--emit") + 1]) for argv in emits],
                                 [("native-ir", "mir"), ("llvm-ir", "mir"), ("native-ir", "obj")] * target_count)
            else:
                self.assertEqual(forbidden, [], "no import/verify/emit command actually happened")
            replay = [command for command in report["commands"] if "verify-report" in command["argv"]]
            if pinned_worker:
                self.assertEqual(len(replay), 1); self.assertEqual(replay[0]["exit_code"], 1)
                self.assertEqual(stages["independent_capture_admission"]["status"], "RED")
                self.assertIn("capture verification requires ocore-runtime-capture-v1", Path(replay[0]["stderr"]["path"]).read_text())
            else:
                self.assertEqual(replay, [])
                self.assertEqual(stages["independent_capture_admission"]["status"], "UNVERIFIED")

            return report

    @staticmethod
    def _synthetic_catalog(mode):
        rows = []
        for id_, architecture in [("rv64gc", "riscv64"), ("x86_64", "x86_64"), ("aarch64", "aarch64")]:
            target = architecture + "-unknown-none"
            rows.append({"id": id_, "architecture": architecture, "target": target,
                         "assembler_triple": target + "-elf", "aliases": [target, target + "-elf"]})
        if mode == "added":
            rows.append({"id": "synthetic_added_isa", "architecture": "synthetic_added_arch",
                         "target": "synthetic-added-none", "assembler_triple": "synthetic-added-none-elf",
                         "aliases": ["synthetic-added-none", "synthetic-added-none-elf"]})
        if mode == "empty": rows = []
        if mode == "duplicate": rows.append(copy.deepcopy(rows[0]))
        if mode == "omitted_minimum": rows = [row for row in rows if row["id"] != "x86_64"]
        return {"schema": "wrong-schema" if mode == "malformed" else "ocore-target-catalog-v1",
                "scope": "canonical-target-declarations-only", "targets": rows}

    @staticmethod
    def _declare_isa_prerequisites(root, value, mode):
        # Explicit infrastructure inputs. These are never original references,
        # complete providers, guard admission or semantic execution evidence.
        control = root / "synthetic-execution-contract-only"
        control.write_text("synthetic contract/workload/state/provider/comparator only\n")
        pin = acceptance.artifact(control)
        execution = root / "synthetic-execution-profile.json"
        execution.write_text(json.dumps({"schema": "ocore-isa-execution-prerequisites-v1",
            "semantic_contract": pin, "workload": pin, "initial_state": pin, "provider_closure": pin,
            "comparator": pin, "observation_model": "normalize-after-observation" if mode == "bad_model" else "exact-defined-deterministic-v1"}))
        execution_pin = acceptance.artifact(execution)
        requirements = json.loads((PATH.parent.parent / "isa.requirements.json").read_text())
        mechanisms = [{"id": row["id"], "cases": ["synthetic-case-only"]} for row in requirements["mechanism_matrix"]]
        declarations = []
        for target in value["targets"]:
            native = {"triple": "riscv64-unknown-linux-gnu", "data_layout": "e-p:64:64", "pointer_bits": 64, "little_endian": True}
            # The compiler double is updated to preserve the same explicit fake
            # target in its synthetic claimed module; this remains a test double.
            module = root / "body.native-ir.json"
            before_module = acceptance.artifact(module)
            data = json.loads(module.read_text()); data["target"] = native; module.write_text(json.dumps(data))
            producer = root / "olangc"
            script = producer.read_text()
            require_old_pin = repr(before_module)
            assert require_old_pin in script
            producer.write_text(script.replace(require_old_pin, repr(acceptance.artifact(module))))
            if mode == "empty_native":
                old_pin = acceptance.artifact(module)
                native = {}
                data["target"] = native; module.write_text(json.dumps(data))
                producer.write_text(producer.read_text().replace(repr(old_pin), repr(acceptance.artifact(module))))
            target["native_target"] = native
            target["frontend_tools"] = {"--native-runtime-cc": "cc"}
            cases = copy.deepcopy(mechanisms)
            if mode == "missing_mechanism": cases.pop()
            if mode == "zero_cases": cases[0]["cases"] = []
            # The catalog prefix is added after this helper returns; use a
            # separate pinned synthetic frontend to avoid changing these bytes.
            frontend = root / "synthetic-frontend"
            frontend.write_text("synthetic frontend role only\n")
            frontend_tools = {"--native-runtime-cc": acceptance.artifact(frontend)}
            abi = root / ("synthetic-abi-" + target["id"] + ".json")
            abi.write_text(json.dumps({"schema": "ocore-target-abi-prerequisites-v1", "native_target": native,
                "import_profiles": target["import_profiles"], "frontend_tools": frontend_tools,
                "source_inputs": [pin if mode == "outside_source" else acceptance.artifact(root / "synthetic-original/body.c")],
                "recipe": value["implementation"]["recipe"], "revision": value["implementation"]["revision"]}))
            declarations.append({"target_id": target["id"], "isa": "rv64gc", "native_target": native,
                "import_profiles": {"--tls-profile": "linux-elf-static-nonpreemptive-v1"} if mode == "wrong_import_profile" else target["import_profiles"], "frontend_tools": frontend_tools, "abi_contract": acceptance.artifact(abi),
                "execution_profile": execution_pin,
                "guarded_runner": {"adapter": pin, "guard": "matching-native-or-explicit-emulation-v1",
                                   "isa": "wrong-guard-isa" if mode == "bad_guard" else "rv64gc", "native_target": native},
                "reference_oracle": {"adapter": pin, "revision": "0" * 40 if mode == "bad_reference" else value["implementation"]["revision"],
                                     "execution_profile_sha256": execution_pin["sha256"]}, "mechanisms": cases})
        pairs = [{"left": value["targets"][0]["id"], "right": value["targets"][1]["id"], "comparator": pin}] if mode == "same_isa_pair" else []
        manifest = root / "synthetic-isa-prerequisites.json"
        manifest.write_text(json.dumps({"schema": "ocore-isa-acceptance-prerequisites-v1", "profiles": declarations, "owned_pairs": pairs}))
        value["isa_coverage"] = acceptance.artifact(manifest)

    def test_actual_cli_added_catalog_backend_is_explicitly_unmet_and_units_continue(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="added")
        rows = {row["isa"]: row for row in report["isa_coverage"]["isa_rows"]}
        self.assertEqual(rows["synthetic_added_isa"]["status"], "RED")
        self.assertTrue(rows["synthetic_added_isa"]["implemented_in_catalog"])
        self.assertEqual(rows["synthetic_added_isa"]["configured_target_ids"], [])
        self.assertIn("no matching declared", " ".join(rows["synthetic_added_isa"]["gaps"]))
        for isa in ["i686", "armv7"]:
            self.assertEqual(rows[isa]["status"], "RED")
            self.assertFalse(rows[isa]["implemented_in_catalog"])
        self.assertEqual(report["targets"][0]["units"][0]["status"], "GREEN")

    def test_actual_cli_unsupported_catalog_keeps_all_declared_target_diagnostics(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="unsupported", target_count=2)
        self.assertFalse(report["isa_coverage"]["catalog_observed"])
        self.assertEqual(report["global_stages"][0]["status"], "UNVERIFIED")
        self.assertEqual(len(report["targets"]), 2)
        self.assertTrue(all(row["units"][0]["status"] == "GREEN" for row in report["targets"]))
        self.assertEqual(sum("--native-runtime-source" in row["argv"] for row in report["commands"]), 2)
        self.assertTrue(all(row["implemented_in_catalog"] is None for row in report["isa_coverage"]["isa_rows"]))

    def test_actual_cli_malformed_catalog_never_becomes_an_observed_backend(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="malformed")
        self.assertFalse(report["isa_coverage"]["catalog_observed"])
        self.assertEqual(report["isa_coverage"]["implemented_isa_ids"], [])
        self.assertIn("catalog schema/scope differs", " ".join(report["isa_coverage"]["global_gaps"]))

    def test_actual_cli_synthetic_ready_declarations_never_qualify_runtime_semantics(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="ready")
        summary = report["isa_coverage"]
        self.assertEqual(summary["profile_rows"][0]["status"], "DECLARED_PREREQUISITES_PRESENT")
        self.assertEqual(summary["status"], "RED")
        for field in ["source_build_catalog_admitted", "exact_case_inventory_admitted", "runtime_accepted",
                      "native_execution_qualified", "semantic_equivalence_qualified", "all_isa_identity_qualified"]:
            self.assertFalse(summary[field])

    def test_actual_cli_missing_mechanism_remains_unmet(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="missing_mechanism")
        self.assertIn("required mechanisms are omitted", report["isa_coverage"]["profile_rows"][0]["gaps"][0])

    def test_actual_cli_zero_required_cases_is_unmet(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="zero_cases")
        self.assertIn("cannot be empty", report["isa_coverage"]["profile_rows"][0]["gaps"][0])

    def test_actual_cli_wrong_guard_and_original_reference_are_unmet(self):
        for mode, diagnostic in [("bad_guard", "guarded runner target/profile differs"),
                                 ("bad_reference", "original reference source/profile differs")]:
            with self.subTest(mode=mode):
                report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode=mode)
                self.assertIn(diagnostic, report["isa_coverage"]["profile_rows"][0]["gaps"])

    def test_actual_cli_posthoc_comparison_model_is_rejected(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="bad_model")
        self.assertIn("post-hoc normalization is forbidden", report["isa_coverage"]["profile_rows"][0]["gaps"][0])

    def test_actual_cli_empty_native_profile_is_unmet(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="empty_native")
        self.assertIn("actual native target/DataLayout/ABI profile is incomplete", report["isa_coverage"]["profile_rows"][0]["gaps"])

    def test_actual_cli_import_profile_declaration_must_match_exactly(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="wrong_import_profile")
        self.assertIn("prerequisite import profiles differ from exact source declaration", report["isa_coverage"]["profile_rows"][0]["gaps"])

    def test_actual_cli_source_pin_cannot_name_a_file_outside_original_checkout(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", prerequisite_mode="outside_source")
        self.assertIn("ABI source pin is outside original checkout or duplicated", report["isa_coverage"]["profile_rows"][0]["gaps"])

    def test_actual_cli_same_isa_pair_cannot_replace_cross_isa_comparison(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="base", target_count=2, prerequisite_mode="same_isa_pair")
        self.assertIn("owned ISA pair cannot compare one ISA to itself", report["isa_coverage"]["owned_pair_gaps"])
        self.assertTrue(any("missing matched owned ISA pair" in gap for gap in report["isa_coverage"]["owned_pair_gaps"]))

    def test_actual_cli_empty_and_duplicate_catalogs_are_unverified(self):
        for mode, diagnostic in [("empty", "canonical catalog cannot be empty"),
                                 ("duplicate", "empty or duplicate canonical id")]:
            with self.subTest(mode=mode):
                report = self._forged_cli(False, partial_valid=True, catalog_mode=mode)
                self.assertFalse(report["isa_coverage"]["catalog_observed"])
                self.assertIn(diagnostic, " ".join(report["isa_coverage"]["global_gaps"]))
                self.assertEqual(report["targets"][0]["units"][0]["status"], "GREEN")

    def test_actual_cli_catalog_omission_cannot_remove_a_minimum_isa(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="omitted_minimum")
        rows = {row["isa"]: row for row in report["isa_coverage"]["isa_rows"]}
        self.assertEqual(rows["x86_64"]["status"], "RED")
        self.assertFalse(rows["x86_64"]["implemented_in_catalog"])
        self.assertIn("x86_64", report["isa_coverage"]["required_isa_ids"])

    def test_actual_cli_catalog_input_mutation_invalidates_pinned_prerequisites(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="mutate_input", prerequisite_mode="ready")
        self.assertFalse(report["isa_inputs_stable"])
        self.assertTrue(report["isa_input_failures"])
        self.assertIn("file bytes differ from pin", " ".join(report["isa_coverage"]["global_gaps"]))
        self.assertEqual(report["targets"][0]["units"][0]["status"], "GREEN")

    def test_actual_cli_catalog_tool_mutation_keeps_inventory_without_running_changed_tool(self):
        report = self._forged_cli(False, partial_valid=True, catalog_mode="mutate_tool")
        self.assertFalse(report["tools_stable"])
        self.assertFalse(report["isa_coverage"]["catalog_observed"])
        self.assertEqual(len(report["commands"]), 1, "changed compiler/sibling must not be invoked")
        self.assertEqual(len(report["targets"]), 1)
        self.assertTrue(any(row["id"] == "missing-original-rule:body" and row["status"] == "RED"
                            for row in report["targets"][0]["units"]))
        stages = {row["name"]: row for row in report["targets"][0]["stages"]}
        self.assertIn("file bytes differ from pin", stages["olangc_owned_source_pipeline"]["diagnostic"])

    def test_verified_buffer_rejects_transient_changed_bytes_even_after_restoration(self):
        with tempfile.TemporaryDirectory(prefix="isa-transient-byte-control-") as temporary:
            path = Path(temporary) / "manifest.json"
            original = b'{"value":"pinned"}'
            path.write_bytes(original); pin = acceptance.artifact(path)
            try:
                path.write_bytes(b'{"value":"transiently changed"}')
                with self.assertRaisesRegex(acceptance.Unmet, "file bytes differ from pin"):
                    acceptance.pinned_isa_buffer(pin)
            finally:
                path.write_bytes(original)
            self.assertEqual(acceptance.artifact(path), pin, "final equality alone would miss the transient contents")

    def test_dynamic_json_parser_consumes_verified_buffer_after_path_changes(self):
        dynamic_path = PATH.with_name("dynamic_isa.py")
        dynamic = types.ModuleType("dynamic_isa_buffer_control")
        exec(compile(dynamic_path.read_bytes(), str(dynamic_path), "exec"), dynamic.__dict__)
        with tempfile.TemporaryDirectory(prefix="isa-consumed-buffer-control-") as temporary:
            path = Path(temporary) / "manifest.json"
            original = b'{"value":"pinned"}'
            path.write_bytes(original); pin = acceptance.artifact(path)
            class Harness:
                read_isa_buffer = staticmethod(acceptance.pinned_isa_buffer)
                record = {}
                def save(self): pass
            harness = Harness()
            parser = dynamic.unique_json
            def swap_after_verified_read(source):
                self.assertIsInstance(source, bytes)
                path.write_bytes(b'{"value":"untrusted second pathname read"}')
                return parser(source)
            try:
                with mock.patch.object(dynamic, "unique_json", side_effect=swap_after_verified_read):
                    consumed, value = dynamic.document(harness, pin)
                self.assertEqual(consumed, pin)
                self.assertEqual(value, {"value": "pinned"})
            finally:
                path.write_bytes(original)
            self.assertEqual(acceptance.artifact(path), pin)

    def test_actual_runner_refuses_unpinned_dynamic_module_buffer_before_exec(self):
        with tempfile.TemporaryDirectory(prefix="isa-helper-buffer-control-") as temporary:
            marker = Path(temporary) / "untrusted-helper-executed"
            dynamic_path = PATH.with_name("dynamic_isa.py").resolve()
            original_read = Path.read_bytes
            def substituted_read(path):
                if path.resolve() == dynamic_path:
                    return ("from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('executed')").encode()
                return original_read(path)
            runner = acceptance.Runner.__new__(acceptance.Runner)
            runner.record = {}
            with mock.patch.object(Path, "read_bytes", substituted_read):
                with self.assertRaisesRegex(acceptance.Unmet, "file bytes differ from pin"):
                    runner.dynamic_isa_coverage()
            self.assertFalse(marker.exists(), "unpinned helper bytes reached compile/exec")

    def test_actual_cli_source_identity_alone_never_proves_original_build_execution(self):
        self._forged_cli(False)

    def test_actual_cli_available_valid_unit_cannot_establish_unadmitted_full_inventory(self):
        self._forged_cli(False, partial_valid=True)

    def test_actual_cli_retained_forged_producer_never_admits_missing_cold_unit(self):
        self._forged_cli(False)

    def test_actual_cli_pinned_worker_reconstructs_and_rejects_forged_capture(self):
        self._forged_cli(True)


if __name__ == "__main__":
    unittest.main()
