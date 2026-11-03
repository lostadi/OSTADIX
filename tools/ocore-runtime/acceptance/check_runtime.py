#!/usr/bin/env python3
"""Drive original sources; RED is an unmet runtime, never a skipped success.

Current public olangc produces verified module sets rather than whole runtime
artifacts. This runner executes that real path and independently checks every
available original unit. It deliberately cannot promote module sets, fresh
diagnostic objects, supplied executables or a test-harness link into a complete
olangc artifact. Unsupported later contracts remain RED after attempted stages.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback


SCHEMA = "ocore-original-runtime-acceptance-v1"
TOOL_SCHEMA = "ocore-original-runtime-toolchain-v1"
IMPORT_PROFILE_OPTIONS = frozenset({"--atomic-profile", "--tls-profile", "--wide-volatile-profile"})


class Unmet(AssertionError):
    pass


class Unverified(Unmet):
    """Evidence has not been independently reconstructed; never a GREEN gate."""



def require(condition, message):
    if not condition:
        raise Unmet(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def artifact(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def checked(record):
    require(isinstance(record, dict) and set(record) <= {"path", "bytes", "sha256"}
            and {"path", "sha256"} <= set(record), "file identity must contain path and SHA-256")
    require(isinstance(record["path"], str) and Path(record["path"]).is_absolute(),
            "pinned file path must be absolute")
    require(isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]),
            "pinned file requires lowercase SHA-256")
    actual = artifact(record["path"])
    require(all(actual[key] == value for key, value in record.items()),
            "file bytes differ from pin: " + record["path"])
    return actual


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " fields differ")


def validate_import_profiles(profiles, message):
    require(isinstance(profiles, dict)
            and set(profiles) <= IMPORT_PROFILE_OPTIONS
            and all(isinstance(value, str) for value in profiles.values()), message)


def validate_profile(profile):
    exact_keys(profile, ["schema", "name", "implementation", "requirements", "targets"], "profile")
    require(profile["schema"] == SCHEMA, "unsupported acceptance profile schema")
    require(isinstance(profile["name"], str) and profile["name"].strip(), "profile needs a name")
    impl = profile["implementation"]
    exact_keys(impl, ["kind", "upstream_url", "revision", "source_checkout", "recipe", "build_step"], "implementation")
    require(impl["kind"] in {"runtime", "compiler", "jit_engine", "library"}, "unsupported implementation role")
    require(isinstance(impl["revision"], str) and re.fullmatch(r"[0-9a-f]{40,64}", impl["revision"]), "pin original revision")
    require(all(isinstance(impl[key], str) and impl[key] for key in ["upstream_url", "source_checkout", "build_step"]), "original source/build identity is incomplete")
    req = profile["requirements"]
    exact_keys(req, ["delivery", "resource_profile", "compiler_output_routing", "jit_generation", "jit_publication", "jit_invalidation"], "requirements")
    require(req["delivery"] in {"native", "verified_ir", "oir"}, "unsupported delivery contract")
    require(isinstance(req["resource_profile"], str) and req["resource_profile"], "declare execution resources")
    require(all(type(req[key]) is bool for key in ["compiler_output_routing", "jit_generation", "jit_publication", "jit_invalidation"]), "requirement flags must be booleans")
    require(impl["kind"] != "compiler" or req["compiler_output_routing"], "compiler output routing cannot be disabled for a compiler")
    require(impl["kind"] != "jit_engine" or all(req[key] for key in ["jit_generation", "jit_publication", "jit_invalidation"]), "a JIT engine requires all generated-code gates")
    require(isinstance(profile["targets"], list) and profile["targets"], "required target matrix cannot be empty")
    ids = set()
    for target in profile["targets"]:
        exact_keys(target, ["id", "target", "native_target", "jobs", "unit_inventory", "frontend_tools", "import_profiles", "provider_profiles", "programs"], "target")
        require(isinstance(target["id"], str) and target["id"] and target["id"] not in ids, "empty or duplicate target ID")
        ids.add(target["id"])
        require(isinstance(target["target"], str) and target["target"], "declare actual target")
        require(target["native_target"] is None or isinstance(target["native_target"], dict), "declare exact native target profile")
        require(type(target["jobs"]) is int and target["jobs"] > 0, "jobs must be positive")
        require(isinstance(target["unit_inventory"], str) and target["unit_inventory"], "declare full build inventory")
        require(isinstance(target["frontend_tools"], dict) and isinstance(target["import_profiles"], dict), "declare frontend and import profiles")
        for flag, role in target["frontend_tools"].items():
            require(re.fullmatch(r"--native-runtime-(?:cc|cxx|rustc|cargo|llvm-nm|llvm-dis)", flag) and isinstance(role, str), "unsupported source-tool option")
        validate_import_profiles(target["import_profiles"], "unsupported import profile option")
        require(isinstance(target["provider_profiles"], list) and isinstance(target["programs"], list), "declare providers and original program graph")
        names = set()
        for program in target["programs"]:
            exact_keys(program, ["name", "kind", "required_units", "reference_output", "upstream_targets", "behavior_driver"], "program")
            require(isinstance(program["name"], str) and program["name"] and program["name"] not in names, "duplicate or empty program")
            names.add(program["name"])
            require(program["kind"] in {"program", "library"}, "invalid original link role")
            require(isinstance(program["required_units"], list) and program["required_units"] and len(set(program["required_units"])) == len(program["required_units"]), "program unit graph is empty or duplicated")
            require(all(isinstance(x, str) and x for x in program["required_units"]), "invalid original required-unit ID")
            require(isinstance(program["reference_output"], str) and program["reference_output"] and not Path(program["reference_output"]).is_absolute() and ".." not in Path(program["reference_output"]).parts, "reference output must belong to new source build")
            require(isinstance(program["upstream_targets"], list) and all(isinstance(x, str) and x for x in program["upstream_targets"]), "declare complete upstream behavior targets")
            if program["behavior_driver"] is not None:
                checked(program["behavior_driver"])
    return profile


def check_recipe_partition(recipe, capture, finalized_inventory=None):
    # Recipe rules are an immutable minimum. Make-derived finalized inventory
    # legitimately contributes additional rules; its exact set is checked only
    # against a separately reconstructed/pinned inventory, never capture labels.
    floor = recipe.get("coverage", {}).get("required_units", [])
    observed = capture.get("required_units", [])
    require(isinstance(floor, list) and floor, "original recipe has no nonempty required-unit inventory")
    expected = list(floor)
    if finalized_inventory is not None:
        require(finalized_inventory.get("schema") == "ocore-runtime-unit-inventory-v1" and finalized_inventory.get("complete") is True,
                "finalized inventory schema/completeness differs")
        additions = finalized_inventory.get("units")
        require(isinstance(additions, list) and additions, "finalized inventory has no required units")
        expected += additions
    require(isinstance(observed, list) and all(isinstance(row, dict) and isinstance(row.get("id"), str) for row in expected + observed), "required rules need original stable IDs")
    wanted = {row["id"]: row for row in expected}
    actual = {row["id"]: row for row in observed}
    require(len(wanted) == len(expected) and len(actual) == len(observed), "duplicate original required rule")
    missing, added = set(wanted) - set(actual), set(actual) - set(wanted)
    require(not missing and (finalized_inventory is None or not added),
            "capture required rules differ from ORIGINAL recipe/finalized inventory: missing=" + repr(sorted(missing)) + "; added=" + repr(sorted(added)))
    for name, rule in wanted.items():
        require(all(actual[name].get(key) == value for key, value in rule.items()), "captured required rule changed: " + name)
        require(isinstance(actual[name].get("captured_unit_ids"), list) and actual[name]["captured_unit_ids"], "original required rule has no captured implementation: " + name)
    return wanted


def check_capture_replay(receipt, report_pin, capture, recipe, recipe_pin,
                         source_checkout, expected_inventory, verifier_pin):
    require(receipt.get("schema") == "ocore-runtime-capture-verification-v1" and receipt.get("verified") is True,
            "trusted capture reconstruction did not verify")
    require(receipt.get("scope") == "source-capture-unit-role-partition-and-observed-native-output-membership",
            "capture verification scope differs")
    require(receipt.get("report") == report_pin, "capture verification is not bound to exact report bytes")
    canonical = hashlib.sha256(json.dumps(capture, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(receipt.get("report_content_sha256") == canonical, "reconstructed capture content differs")
    require(receipt.get("capture_worker_sha256") == verifier_pin["sha256"], "capture worker is not the independently selected verifier")
    directory = Path(receipt["capture_directory"]).resolve(strict=True)
    require(directory == Path(report_pin["path"]).parent, "capture journal directory differs")
    session = json.loads((directory / "session.json").read_text())
    manifest = checked(session["manifest"])
    require(manifest["sha256"] == recipe_pin["sha256"] and manifest["bytes"] == recipe_pin["bytes"] and session.get("recipe") == recipe,
            "reconstructed capture used a different original recipe")
    require(Path(session["source"]["path"]).resolve(strict=True) == Path(source_checkout).resolve(strict=True),
            "reconstructed capture used a different original source checkout")
    inventory = checked(receipt["inventory"])
    require(inventory == session.get("inventory_artifact") and inventory["path"] == str(Path(expected_inventory).resolve(strict=True)),
            "reconstructed finalized inventory path/identity differs")
    require(receipt.get("lowering_unit_ids") == capture.get("lowering_unit_ids") and
            receipt.get("provenance_unit_count") == len(capture.get("units", [])), "reconstructed original-unit partition differs")
    finalized = json.loads(Path(inventory["path"]).read_text())
    check_recipe_partition(recipe, capture, finalized)
    return finalized


def checked_complete_units(admission, units):
    if admission.get("status") != "GREEN":
        raise Unverified("available-unit checks do not establish the complete original inventory without trusted capture admission")
    require(units and all(unit["status"] == "GREEN" for unit in units),
            "some required original units lack source accounting/verification/owned diagnostic objects")
    return {"checked": len(units), "execution_attempted": False}


def check_selected_units(capture, coverage):
    selected = capture.get("lowering_unit_ids")
    require(isinstance(selected, list) and selected and len(set(selected)) == len(selected), "no complete nonempty required-unit selection")
    require(capture.get("capture_complete") is True and capture.get("unit_roles_complete") is True and not capture.get("unclassified_unit_ids"), "original capture/role inventory incomplete")
    units = capture.get("units", [])
    require(len({unit["id"] for unit in units}) == len(units), "duplicate original unit")
    require(set(selected) <= {unit["id"] for unit in units}, "selected unit is absent from original capture")
    rows = coverage.get("units", [])
    require(len({unit["id"] for unit in rows}) == len(rows), "duplicate native unit")
    require({unit["id"] for unit in rows} == set(selected), "native unit inventory silently omits or adds an original unit")
    return {unit["id"]: unit for unit in units}, {unit["id"]: unit for unit in rows}


def check_program_graph(capture, programs):
    require(programs, "complete original program/library link graph is missing")
    required = capture.get("required_units", [])
    logical = {unit["id"]: set(unit["captured_unit_ids"]) for unit in required}
    require(logical and len(logical) == len(required), "invalid original logical-unit inventory")
    selected = set(capture["lowering_unit_ids"])
    covered = set()
    for program in programs:
        for name in program["required_units"]:
            require(name in logical, "program refers to unknown original unit: " + name)
            covered.update(logical[name] & selected)
    require(covered == selected, "original program graph drops required implementation units")
    return {"programs": len(programs), "required_units_accounted": len(covered), "complete_olangc_artifact": False}


def check_target(module, expected):
    require(expected is not None, "actual frontend/DataLayout/ABI profile is not pinned")
    require(module.get("target") == expected, "native target/DataLayout/ABI/execution profile mismatch")


def complete_artifact_gate(source_receipt, coverage):
    # These are deliberately necessary but insufficient. No public whole-runtime
    # artifact re-admission interface exists in the inspected source-recipe API.
    require(source_receipt.get("artifact_complete") is True and coverage.get("artifact_complete") is True,
            "olangc source workflow did not construct a complete runtime artifact")
    raise Unmet("a public olangc whole-runtime artifact validator is required; supplied manifests and test-harness links cannot qualify it")


def records_in(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str):
                yield item
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def original_ir(unit, input_sha256):
    matches = {}
    for item in records_in(unit):
        if item["sha256"] == input_sha256 and Path(item["path"]).suffix in {".ll", ".bc"}:
            record = checked({key: item[key] for key in ["path", "sha256", "bytes"] if key in item})
            matches[record["path"]] = record
    require(matches, "native input is not an exact original captured LLVM unit")
    # Duplicate paths containing identical verified bytes are aliases, recorded
    # explicitly rather than counted as additional original units.
    return list(sorted(matches.values(), key=lambda row: row["path"]))


class Runner:
    def __init__(self, profile, toolchain, output):
        self.profile = validate_profile(profile)
        exact_keys(toolchain, ["schema", "tools", "environment"], "toolchain")
        require(toolchain["schema"] == TOOL_SCHEMA and isinstance(toolchain["tools"], dict), "unsupported pinned toolchain")
        self.tools = {name: checked(pin) for name, pin in toolchain["tools"].items()}
        require({"olangc", "ocorec", "llvm_library", "inventory_helper"} <= set(self.tools), "missing required actual compiler/parser/inventory tools")
        sibling = Path(self.tools["olangc"]["path"]).parent / "ocorec"
        require(artifact(sibling)["sha256"] == self.tools["ocorec"]["sha256"], "olangc uses its sibling ocorec; selected compiler bytes differ")
        self.sibling = artifact(sibling)
        self.python = artifact(sys.executable)
        require(isinstance(toolchain["environment"], dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in toolchain["environment"].items()), "invalid explicit tool environment")
        self.environment = dict(os.environ, **toolchain["environment"])
        self.output = Path(output).resolve()
        source = Path(profile["implementation"]["source_checkout"]).resolve()
        recipe = Path(profile["implementation"]["recipe"]["path"]).resolve()
        require(not self.output.exists() and self.output != source and source not in self.output.parents and self.output != recipe, "output must be a new directory outside original source/recipe")
        self.output.mkdir(parents=True)
        self.record = {"schema": "ocore-original-runtime-acceptance-result-v1", "name": profile["name"], "status": "RED", "complete": False,
                       "runtime_accepted": False, "runtime_complete": False, "native_execution_qualified": False,
                       "started_epoch": time.time(), "targets": [], "commands": [], "tools_before": self.tools,
                       "actual_olangc_sibling_ocorec": self.sibling, "capture_verifier_python_before": self.python, "environment_sha256": hashlib.sha256(json.dumps(toolchain["environment"], sort_keys=True).encode()).hexdigest(),
                       "scope": "actual original-source pipeline and independent unit diagnostics; no complete-artifact or engine qualification inferred from module/object checks"}
        self.save()
        pin = self.tools["inventory_helper"]
        spec = importlib.util.spec_from_file_location("ocore_acceptance_inventory_" + pin["sha256"], pin["path"])
        self.inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.inventory)
        self.reader = None

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def command(self, argv, directory, label):
        directory.mkdir(parents=True, exist_ok=True)
        stdout, stderr = directory / (label + ".stdout"), directory / (label + ".stderr")
        row = {"argv": list(map(str, argv)), "cwd": str(directory), "started_epoch": time.time()}
        self.record["commands"].append(row)
        self.save()
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen(list(map(str, argv)), cwd=directory, env=self.environment, stdout=out, stderr=err)
            row["pid_in_launcher_namespace"] = process.pid
            self.save()
            row["exit_code"] = process.wait()
        row.update(stdout=artifact(stdout), stderr=artifact(stderr), finished_epoch=time.time())
        self.save()
        return row

    def stage(self, target, name, operation):
        row = {"name": name, "status": "RED"}
        target["stages"].append(row)
        self.save()
        try:
            row["evidence"] = operation()
            row["status"] = "GREEN"
        except Unverified as error:
            row.update(status="UNVERIFIED", error_type=type(error).__name__, diagnostic=str(error))
        except Exception as error:
            row.update(error_type=type(error).__name__, diagnostic=str(error))
        self.save()
        return row

    def source_identity(self):
        impl = self.profile["implementation"]
        source = Path(impl["source_checkout"]).resolve(strict=True)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()
        require(git("rev-parse", "HEAD") == impl["revision"], "original source revision differs")
        require(not git("status", "--porcelain", "--untracked-files=all"), "original source checkout is not clean")
        recipe = checked(impl["recipe"])
        definition = json.loads(Path(recipe["path"]).read_text())
        require(definition.get("schema") == "ocore-runtime-recipe-v1", "not an original-source recipe")
        require(definition["source"]["revision"] == impl["revision"] and definition["source"]["url"] == impl["upstream_url"], "source/recipe upstream pin differs")
        require(any(step["name"] == impl["build_step"] for step in definition["commands"]), "original build step absent")
        require(definition.get("coverage", {}).get("require_full_unit_inventory") is True, "recipe does not require full original build inventory")
        return {"source": str(source), "revision": impl["revision"], "tree": git("rev-parse", "HEAD^{tree}"), "origin": git("remote", "get-url", "origin"), "recipe": recipe}

    def readmit_unit(self, original_unit, claimed_record, target, directory):
        """Re-import original bytes; neither hashes nor symbol lists prove a body."""
        claimed = checked({key: claimed_record[key] for key in ("path", "sha256", "bytes") if key in claimed_record})
        module = json.loads(Path(claimed["path"]).read_text())
        check_target(module, target["native_target"])
        inputs = original_ir(original_unit, module["provenance"]["input_sha256"])
        claimed_receipt = directory / "claimed-verification.json"
        verified = self.command([self.tools["ocorec"]["path"], claimed["path"], "--input-kind", "native-ir", "--verify-native", "--receipt", claimed_receipt], directory, "verify-claimed")
        require(verified["exit_code"] == 0, "claimed module failed actual native verification")
        result = json.loads(claimed_receipt.read_text())
        require(result.get("verified") is True and result.get("module_sha256") == claimed["sha256"], "claimed verification is not bound to exact bytes")
        canonical = directory / "claimed-canonical.native-ir.json"
        normalized = self.command([self.tools["ocorec"]["path"], claimed["path"], "--input-kind", "native-ir", "--emit", "mir", "--target", target["target"], "-o", canonical], directory, "canonicalize-claimed")
        require(normalized["exit_code"] == 0 and canonical.is_file(), "actual typed NativeModule canonicalization failed")
        canonical_module = json.loads(canonical.read_text())
        if self.reader is None:
            self.reader = self.inventory.Reader(self.tools["llvm_library"]["path"], self.tools["llvm_library"]["sha256"])
        original = self.reader.read(inputs[0]["path"])
        proof = self.inventory.check_inventory(original, canonical_module)
        for filename, value in (("original.json", original), ("preservation.json", proof)):
            (directory / filename).write_text(json.dumps(value, indent=2) + "\n")
        fresh = directory / "fresh-original.native-ir.json"
        argv = [self.tools["ocorec"]["path"], inputs[0]["path"], "--input-kind", "llvm-ir", "--emit", "mir", "--target", target["target"], "--llvm-library", self.tools["llvm_library"]["path"], "--llvm-sha256", self.tools["llvm_library"]["sha256"], "-o", fresh]
        for flag, value in target["import_profiles"].items():
            argv += [flag, value]
        imported = self.command(argv, directory, "import-original")
        require(imported["exit_code"] == 0 and fresh.is_file(), "fresh import of exact original LLVM unit failed")
        fresh_module = json.loads(fresh.read_text())
        check_target(fresh_module, target["native_target"])
        # The selected compiler parses/verifies/serializes the claimed NativeModule.
        # Compare every typed field, including provenance. No field is hand-erased.
        encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        same = encode(canonical_module) == encode(fresh_module)
        admission_path = directory / "readmission.json"
        admission = {"schema": "ocore-original-unit-body-readmission-v1", "method": "fresh selected O-core import and complete typed NativeModule identity; not a formal compiler-correctness proof", "original_inputs": inputs, "claimed_module": claimed, "claimed_verification": artifact(claimed_receipt), "claimed_typed_canonical": artifact(canonical), "fresh_module": artifact(fresh), "fresh_import_command": imported, "same_typed_module": same, "canonicalization": "actual selected NativeModule parse/verify/serialization; all resulting fields compared", "compiler": self.tools["ocorec"], "parser": self.tools["llvm_library"], "runtime_accepted": False}
        admission_path.write_text(json.dumps(admission, indent=2) + "\n")
        require(same, "fresh original LLVM import does not match claimed typed NativeModule")
        fresh_pin = artifact(fresh)
        verification = directory / "verification.json"
        verified = self.command([self.tools["ocorec"]["path"], fresh, "--input-kind", "native-ir", "--verify-native", "--receipt", verification], directory, "verify-fresh")
        require(verified["exit_code"] == 0 and verification.is_file(), "fresh regenerated NativeModule verification failed")
        result = json.loads(verification.read_text())
        require(result.get("verified") is True and result.get("module_sha256") == fresh_pin["sha256"], "regenerated verification is not bound to exact bytes")
        obj = directory / "diagnostic.o"
        emitted = self.command([self.tools["ocorec"]["path"], fresh, "--input-kind", "native-ir", "--emit", "obj", "--target", target["target"], "-o", obj], directory, "emit-fresh")
        require(emitted["exit_code"] == 0 and obj.is_file() and obj.read_bytes()[:4] == b"\x7fELF", "fresh owned diagnostic object emission failed")
        require(checked(claimed) == claimed and artifact(fresh) == fresh_pin and all(checked(item) == item for item in inputs), "unit inputs/regenerated bytes changed during readmission")
        return {"status": "GREEN", "original_inputs": inputs, "claimed_module": claimed, "module": fresh_pin, "original_ir_readmission": artifact(admission_path), "source_inventory": artifact(directory / "original.json"), "preservation": artifact(directory / "preservation.json"), "claimed_verification": artifact(claimed_receipt), "verification": artifact(verification), "fresh_owned_diagnostic_object": artifact(obj), "complete_olangc_artifact": False}

    def run_target(self, target):
        path = self.output / hashlib.sha256(target["id"].encode()).hexdigest()
        path.mkdir()
        result = {"id": target["id"], "requested_target": target["target"], "status": "RED", "stages": [], "units": []}
        self.record["targets"].append(result)
        identity = self.stage(result, "pinned_source_and_recipe_identity", self.source_identity)
        identity["scope"] = "Selected local source revision and recipe metadata only; no build execution."
        def original_build():
            require(identity["status"] == "GREEN", "original source identity failed")
            raise Unverified("Pinned source and recipe identity does not prove original build execution; genuinely admitted owned build/capture evidence is required")
        self.stage(result, "original_source_and_build", original_build)
        generated = path / "source-product"
        capture_path = generated / "capture/report.json"
        coverage_path = generated / "lowered/coverage.json"
        source_path = generated / "source-recipe.json"
        def source_pipeline():
            require(identity["status"] == "GREEN", "original source identity failed")
            argv = [self.tools["olangc"]["path"], self.profile["implementation"]["recipe"]["path"], "--native-runtime", "--native-runtime-source", self.profile["implementation"]["source_checkout"], "--native-runtime-output", "ir", "--native-isa", target["target"], "--native-runtime-unit-inventory", target["unit_inventory"], "--native-runtime-jobs", str(target["jobs"]), "--llvm-library", self.tools["llvm_library"]["path"], "--llvm-sha256", self.tools["llvm_library"]["sha256"], "-o", str(generated)]
            for flag, role in target["frontend_tools"].items():
                require(role in self.tools, "selected frontend tool is unpinned: " + role)
                argv += [flag, self.tools[role]["path"]]
            for flag, value in target["import_profiles"].items():
                argv += [flag, value]
            row = self.command(argv, path, "source-pipeline")
            require(source_path.is_file(), "actual olangc produced no source-recipe receipt")
            source_receipt = json.loads(source_path.read_text())
            result["source_receipt"] = artifact(source_path)
            for key, item in [("capture", capture_path), ("lowering", coverage_path)]:
                if item.is_file():
                    result[key] = artifact(item)
            require(row["exit_code"] == 0 and source_receipt.get("success") is True, "actual original-source pipeline is incomplete: " + str(source_receipt.get("error", "see retained compiler diagnostics")))
            raise Unverified("source command exited successfully; receipt flags do not prove frontend/import/verification activity")
        self.stage(result, "olangc_owned_source_pipeline", source_pipeline)
        capture = json.loads(capture_path.read_text()) if capture_path.is_file() else {}
        coverage = json.loads(coverage_path.read_text()) if coverage_path.is_file() else {}
        source_receipt = json.loads(source_path.read_text()) if source_path.is_file() else {}
        recipe_pin = checked(self.profile["implementation"]["recipe"])
        recipe = json.loads(Path(recipe_pin["path"]).read_text())
        finalized_inventory = None
        def source_admission():
            nonlocal finalized_inventory
            if "capture_verifier" not in self.tools:
                raise Unverified("independently pinned trusted capture_verifier is required; receipt booleans are not admission")
            require(capture_path.is_file(), "no captured original-source report to reconstruct")
            verifier = checked(self.tools["capture_verifier"])
            report_pin = artifact(capture_path)
            receipt_path = path / "independent-capture" / "verification.json"
            command = self.command([self.python["path"], "-I", verifier["path"], "verify-report", report_pin["path"], "--receipt", receipt_path], receipt_path.parent, "verify-capture")
            require(command["exit_code"] == 0 and receipt_path.is_file(), "trusted capture-worker reconstruction failed; see retained verify-capture diagnostics")
            require(artifact(capture_path) == report_pin and checked(verifier) == verifier, "capture report/verifier changed during replay")
            expected_inventory = (generated / "build" / target["unit_inventory"]).resolve()
            require((generated / "build").resolve() in expected_inventory.parents, "finalized inventory escapes source build")
            receipt = json.loads(receipt_path.read_text())
            finalized_inventory = check_capture_replay(receipt, report_pin, capture, recipe, recipe_pin,
                                                       self.profile["implementation"]["source_checkout"], expected_inventory, verifier)
            return {"verification": artifact(receipt_path), "command": command, "capture_verifier": verifier,
                    "inventory": checked(receipt["inventory"]), "scope": receipt["scope"],
                    "dependency_closure_complete": False, "runtime_complete": False, "native_execution_qualified": False}
        admission = self.stage(result, "independent_capture_admission", source_admission)
        result["original_recipe_required_rules"] = recipe.get("coverage", {}).get("required_units", [])
        unit_maps = None
        if isinstance(capture.get("lowering_unit_ids"), list) and capture["lowering_unit_ids"]:
            unit_maps = ({row["id"]: row for row in capture.get("units", []) if isinstance(row, dict) and isinstance(row.get("id"), str)},
                         {row["id"]: row for row in coverage.get("units", []) if isinstance(row, dict) and isinstance(row.get("id"), str)})
        def selected_inventory():
            nonlocal unit_maps
            check_recipe_partition(recipe, capture, finalized_inventory)
            unit_maps = check_selected_units(capture, coverage)
            if admission["status"] != "GREEN":
                raise Unverified("selected-list equality is not independently reconstructed original-recipe/journal admission")
            return {"required_units": len(capture["lowering_unit_ids"]), "capture": artifact(capture_path)}
        self.stage(result, "complete_original_unit_selection", selected_inventory)
        if unit_maps is not None:
            originals, native = unit_maps
            for unit_id in capture["lowering_unit_ids"]:
                unit = {"id": unit_id, "status": "RED"}
                result["units"].append(unit)
                directory = path / "independent" / hashlib.sha256(unit_id.encode()).hexdigest()
                directory.mkdir(parents=True)
                try:
                    require(unit_id in native and unit_id in originals, "required unit is absent from original or native records")
                    row = native[unit_id]
                    require(row.get("verified") is True and row.get("lowered") is True, "required original unit was not independently verified/lowered: " + str(row.get("failure")))
                    unit.update(self.readmit_unit(originals[unit_id], row["module"], target, directory))
                except Exception as error:
                    unit.update(error_type=type(error).__name__, diagnostic=str(error))
                self.save()
        observed_rules = {row.get("id") for row in capture.get("required_units", []) if isinstance(row, dict)}
        for rule in recipe.get("coverage", {}).get("required_units", []):
            if rule.get("id") not in observed_rules:
                result["units"].append({"id": "missing-original-rule:" + str(rule.get("id")), "status": "RED", "diagnostic": "original recipe requires this implementation even though capture omitted it"})
        def original_program_graph():
            check_recipe_partition(recipe, capture, finalized_inventory)
            declared = check_program_graph(capture, target["programs"])
            result["declared_program_graph_coverage"] = declared
            raise Unverified("declared graph coverage is not independent reconstruction of actual original native build/link journal")
        self.stage(result, "original_program_graph", original_program_graph)
        def all_units():
            return checked_complete_units(admission, result["units"])
        self.stage(result, "all_original_units_independently_checked", all_units)
        def providers():
            for pin in target["provider_profiles"]:
                checked(pin)
            require(not target["provider_profiles"], "required provider source profiles must be run and composed by olangc; supplied packages are not accepted")
            require(result["units"] and all(unit["status"] == "GREEN" for unit in result["units"]), "provider closure cannot ignore failed or missing original implementation units")
            require(coverage.get("native_module_dependency_closure_complete") is True and coverage.get("symbol_closure_complete") is True, "original implementation/provider native symbol closure is incomplete")
            raise Unverified("provider/native symbol closure must be reconstructed from verified modules and actual artifact references; asserted closure booleans are not proof")
        self.stage(result, "original_provider_and_native_symbol_closure", providers)
        self.stage(result, "complete_olangc_artifact", lambda: complete_artifact_gate(source_receipt, coverage))
        def unmet(message):
            raise Unmet(message)
        self.stage(result, "resources_and_reference_vs_owned_behavior", lambda: unmet("requires an admitted complete olangc artifact, explicit resource bindings, and complete unchanged upstream behavior; original reference build executables are not owned products"))
        for gate in ["compiler_output_routing", "jit_generation", "jit_publication", "jit_invalidation"]:
            if self.profile["requirements"][gate]:
                self.stage(result, gate, lambda gate=gate: unmet("required " + gate + " needs its distinct actual olangc generated-code/artifact path"))
        self.stage(result, "original_sources_unchanged", lambda: self.same_source(identity))
        result["status"] = "GREEN" if result["stages"] and all(row["status"] == "GREEN" for row in result["stages"]) else "RED"
        self.save()

    def same_source(self, before):
        require(before["status"] == "GREEN", "original source identity was not admitted")
        after = self.source_identity()
        require(after == before["evidence"], "original source/recipe identity changed")
        return after

    def run(self):
        for target in self.profile["targets"]:
            try:
                self.run_target(target)
            except Exception as error:
                self.record.setdefault("failures", []).append({"target": target["id"], "error_type": type(error).__name__, "diagnostic": str(error)})
                self.save()
        self.record["tools_after"] = {name: artifact(pin["path"]) for name, pin in self.tools.items()}
        self.record["capture_verifier_python_after"] = artifact(self.python["path"])
        self.record["tools_stable"] = self.record["capture_verifier_python_after"] == self.python and self.record["tools_before"] == self.record["tools_after"] and artifact(self.sibling["path"]) == self.sibling
        self.record.update(stage="complete", finished_epoch=time.time())
        good = self.record["tools_stable"] and not self.record.get("failures") and len(self.record["targets"]) == len(self.profile["targets"]) and all(row["status"] == "GREEN" for row in self.record["targets"])
        self.record.update(status="GREEN" if good else "RED", complete=good, runtime_accepted=good)
        self.save()
        return 0 if good else 1


def unit_readmission_cli(arguments):
    """Diagnostic entry: successful unit identity never accepts a runtime."""
    parser = argparse.ArgumentParser(description="Re-import one pinned LLVM unit and compare its complete typed body; diagnostic only")
    parser.add_argument("request", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    request_pin, tools_pin = artifact(args.request), artifact(args.tools)
    request = json.loads(args.request.read_text())
    exact_keys(request, ["schema", "unit_id", "original_unit", "claimed_module", "target"], "unit readmission request")
    require(request["schema"] == "ocore-original-unit-readmission-request-v1" and isinstance(request["unit_id"], str), "unsupported unit diagnostic request")
    target = request["target"]
    exact_keys(target, ["target", "native_target", "import_profiles"], "unit target")
    require(isinstance(target["target"], str) and isinstance(target["native_target"], dict), "explicit target profile required")
    validate_import_profiles(target["import_profiles"], "unknown or malformed import profile")
    toolchain = json.loads(args.tools.read_text())
    exact_keys(toolchain, ["schema", "tools", "environment"], "unit toolchain")
    require(toolchain["schema"] == TOOL_SCHEMA and isinstance(toolchain["tools"], dict), "unsupported pinned tools")
    runner = Runner.__new__(Runner)
    runner.tools = {name: checked(pin) for name, pin in toolchain["tools"].items()}
    require({"ocorec", "llvm_library", "inventory_helper"} <= set(runner.tools), "unit diagnosis requires compiler/parser/inventory pins")
    require(isinstance(toolchain["environment"], dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in toolchain["environment"].items()), "invalid tool environment")
    runner.environment = dict(os.environ, **toolchain["environment"])
    runner.output = args.output.resolve()
    require(not runner.output.exists(), "unit diagnostic output must be a new directory")
    runner.output.mkdir(parents=True)
    runner.record = {"schema": "ocore-original-unit-readmission-result-v1", "status": "UNQUALIFIED_RUNTIME", "complete": False, "runtime_accepted": False, "runtime_complete": False, "native_execution_qualified": False, "original_capture_admitted": False, "complete_original_inventory_admitted": False, "complete_olangc_artifact": False, "scope": "diagnostic identity of the supplied original LLVM unit only; no upstream origin/capture, runtime artifact, behavior or execution acceptance", "request": request_pin, "toolchain": tools_pin, "checker_before": artifact(__file__), "tools_before": runner.tools, "commands": [], "started_epoch": time.time()}
    spec = importlib.util.spec_from_file_location("ocore_unit_inventory_" + runner.tools["inventory_helper"]["sha256"], runner.tools["inventory_helper"]["path"])
    runner.inventory = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runner.inventory
    spec.loader.exec_module(runner.inventory)
    runner.reader = None
    unit = {"id": request["unit_id"], "status": "RED"}
    runner.record["unit"] = unit
    runner.save()
    try:
        unit.update(runner.readmit_unit(request["original_unit"], request["claimed_module"], target, runner.output / "unit"))
    except Exception as error:
        unit.update(error_type=type(error).__name__, diagnostic=str(error))
    runner.record["tools_after"] = {name: artifact(pin["path"]) for name, pin in runner.tools.items()}
    runner.record["checker_after"] = artifact(__file__)
    stable = runner.record["tools_before"] == runner.record["tools_after"] and runner.record["checker_before"] == runner.record["checker_after"] and artifact(args.request) == request_pin and artifact(args.tools) == tools_pin
    runner.record.update(tools_and_request_stable=stable, unit_readmission_complete=stable and unit["status"] == "GREEN", finished_epoch=time.time(), stage="diagnostic-complete")
    runner.record["diagnostic_status"] = "PASS" if runner.record["unit_readmission_complete"] else "FAIL"
    runner.save()
    return 0 if runner.record["unit_readmission_complete"] else 1


def main():
    if sys.argv[1:2] == ["readmit-unit"]:
        return unit_readmission_cli(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        profile_pin, tool_pin = artifact(args.profile), artifact(args.tools)
        runner = Runner(json.loads(args.profile.read_text()), json.loads(args.tools.read_text()), args.output)
        runner.record.update(profile=profile_pin, toolchain=tool_pin, runner=artifact(__file__))
        runner.save()
        code = runner.run()
        print(json.dumps({"status": runner.record["status"], "runtime_accepted": runner.record["runtime_accepted"], "report": artifact(runner.output / "report.json")}))
        return code
    except Exception as error:
        # Configuration/tool failures are also unmet acceptance, never a skip.
        print(json.dumps({"status": "RED", "runtime_accepted": False, "error_type": type(error).__name__, "diagnostic": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
