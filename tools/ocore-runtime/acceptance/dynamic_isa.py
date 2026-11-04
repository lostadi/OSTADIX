"""Actual compiler catalog and fail-closed ISA prerequisites, never semantics.

Only Runner's selected, digest-pinned compiler supplies catalog bytes. Profile
manifests may declare prerequisites but cannot supply a substitute catalog or
admit source/build correctness, actual execution or functional identity.
"""

import itertools
import json
from pathlib import Path
import types


def unique_json(source):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result
    require(isinstance(source, bytes), "JSON parser requires the already verified byte buffer")
    return json.loads(source, object_pairs_hook=pairs)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " fields differ")


def names(values, label):
    require(isinstance(values, list) and values and all(isinstance(v, str) and v for v in values),
            label + " cannot be empty or malformed")
    require(len(values) == len(set(values)), label + " contains duplicates")
    return set(values)


def remember_buffer(runner, pin):
    try:
        actual, source = runner.read_isa_buffer(pin)
    except Exception as error:
        runner.record.setdefault("isa_input_failures", []).append({"expected": pin, "error_type": type(error).__name__, "diagnostic": str(error)})
        runner.save()
        raise
    inputs = runner.record.setdefault("isa_inputs_before", {})
    require(actual["path"] not in inputs or inputs[actual["path"]] == actual,
            "ISA input changed during prerequisite checking: " + actual["path"])
    inputs[actual["path"]] = actual
    return actual, source


def remember(runner, pin):
    return remember_buffer(runner, pin)[0]


def document(runner, pin):
    actual, source = remember_buffer(runner, pin)
    return actual, unique_json(source)


def evaluate(runner):
    summary = {
        "schema": "ocore-dynamic-isa-acceptance-v1", "status": "RED",
        "scope": "actual selected-compiler catalog and declared prerequisites; no source/build or execution admission",
        "catalog_status": "UNVERIFIED", "catalog_observed": False,
        "minimum_isa_ids": [], "implemented_isa_ids": [], "required_isa_ids": [],
        "isa_rows": [], "profile_rows": [], "global_gaps": [], "owned_pair_gaps": [],
        "source_build_catalog_admitted": False, "exact_case_inventory_admitted": False,
        "runtime_accepted": False, "native_execution_qualified": False,
        "semantic_equivalence_qualified": False, "all_isa_identity_qualified": False,
    }
    runner.record["isa_coverage"] = summary
    runner.save()
    minimum = set()
    mechanisms = set()
    try:
        path = Path(__file__).resolve().parent.parent / "isa.requirements.json"
        pin, requirements = document(runner, runner.isa_artifact(path))
        require(requirements.get("kind") == "ostadix-all-mechanism-isa-expansion-requirements",
                "not the ISA expansion requirements contract")
        inventory = requirements["all_implemented_isa_semantic_equivalence"]["required_isa_set"]
        gate = inventory["ci_and_acceptance_coverage_gate"]
        require(gate.get("required") is True, "required dynamic coverage gate is not enabled in the contract")
        minimum = names(inventory["minimum_mandatory_primary_profiles"] + inventory["minimum_additional_required_expansion_profiles"], "minimum ISA profiles")
        minimum |= names([row["id"] for row in requirements["target_profiles"]], "profile matrix IDs")
        summary["coverage_gate_contract"] = gate
        mechanisms = names([row["id"] for row in requirements["mechanism_matrix"]], "required mechanisms")
        summary["requirements"] = pin
        summary["minimum_isa_ids"] = sorted(minimum)
    except Exception as error:
        summary["global_gaps"].append("ISA requirements unavailable/invalid: " + str(error))
    catalog = None
    try:
        helper_path = Path(__file__).with_name("isa_coverage.py")
        helper_pin, helper_source = remember_buffer(runner, runner.isa_artifact(helper_path))
        helper = types.ModuleType("pinned_canonical_catalog_shape_checker")
        exec(compile(helper_source, helper_pin["path"], "exec"), helper.__dict__)
        before = runner.checked_isa_pin(runner.tools["ocorec"])
        command = runner.command([before["path"], "--list-targets"], runner.output / "isa-coverage", "selected-compiler-catalog", timeout=15)
        summary["catalog_command"] = command
        command["environment_sha256"] = runner.isa_environment_sha256()
        catalog_pin, catalog_source = remember_buffer(runner, command["stdout"])
        remember(runner, command["stderr"])
        after = runner.checked_isa_pin(runner.tools["ocorec"])
        require(before == after, "selected compiler changed during catalog invocation")
        require(command["exit_code"] == 0 and not command.get("timed_out"),
                "selected compiler --list-targets is unsupported or failed; see retained output")
        catalog = unique_json(catalog_source)
        implemented = helper.validate_catalog(catalog)
        summary.update(catalog_status="OBSERVED_PINNED_COMPILER_DECLARATIONS", catalog_observed=True,
                       catalog=command["stdout"], compiler=before, implemented_isa_ids=sorted(implemented))
    except Exception as error:
        catalog = None
        implemented = set()
        summary["global_gaps"].append("compiler catalog unavailable/unverified: " + str(error))
    required = minimum | implemented
    summary["required_isa_ids"] = sorted(required)
    summary["required_mechanism_ids"] = sorted(mechanisms)
    alias_to_isa = {alias: row["id"] for row in catalog["targets"] for alias in row["aliases"]} if catalog else {}
    targets = {row["id"]: row for row in runner.profile["targets"]}
    target_isas = {name: alias_to_isa.get(row["target"]) for name, row in targets.items()}
    for isa in sorted(required):
        summary["isa_rows"].append({
            "isa": isa, "status": "RED", "implemented_in_catalog": isa in implemented if catalog else None,
            "configured_target_ids": sorted(name for name, value in target_isas.items() if value == isa),
            "mechanism_statuses": {mechanism: "RED" for mechanism in sorted(mechanisms)},
            "gaps": [], "runtime_accepted": False, "semantic_equivalence_qualified": False,
        })
    for row in summary["isa_rows"]:
        if not catalog:
            row["gaps"].append("selected compiler catalog unavailable; foundation status is unverified")
        elif not row["implemented_in_catalog"]:
            row["gaps"].append("required canonical target foundation is absent from selected compiler catalog")
        if not row["configured_target_ids"]:
            row["gaps"].append("no matching declared target/frontend/ABI profile")
    coverage = {}
    try:
        require("isa_coverage" in runner.profile, "pinned ISA prerequisite manifest is missing")
        pin, coverage = document(runner, runner.profile["isa_coverage"])
        exact(coverage, ["schema", "profiles", "owned_pairs"], "ISA prerequisite manifest")
        require(coverage["schema"] == "ocore-isa-acceptance-prerequisites-v1", "ISA prerequisite schema differs")
        require(isinstance(coverage["profiles"], list) and isinstance(coverage["owned_pairs"], list),
                "ISA prerequisite lists are malformed")
        summary["prerequisite_manifest"] = pin
    except Exception as error:
        summary["global_gaps"].append("ISA prerequisites unavailable/invalid: " + str(error))
        coverage = {"profiles": [], "owned_pairs": []}
    declarations = {}
    for declaration in coverage["profiles"]:
        if not isinstance(declaration, dict) or not isinstance(declaration.get("target_id"), str):
            summary["global_gaps"].append("malformed target prerequisite declaration")
            continue
        name = declaration["target_id"]
        if name in declarations or name not in targets:
            summary["global_gaps"].append("duplicate/unknown target prerequisite: " + name)
            continue
        declarations[name] = declaration
    admitted_declarations = {}
    for name, target in targets.items():
        row = {"target_id": name, "isa": target_isas[name], "status": "RED", "gaps": [],
               "execution_attempted": False, "semantic_equivalence_qualified": False}
        summary["profile_rows"].append(row)
        try:
            require(row["isa"] is not None, "target name is not recognized by the actual selected compiler catalog")
            require(name in declarations, "target lacks its pinned prerequisite declaration")
            declaration = declarations[name]
            exact(declaration, ["target_id", "isa", "native_target", "execution_profile", "guarded_runner",
                                "reference_oracle", "mechanisms", "import_profiles", "frontend_tools", "abi_contract"], "target prerequisite")
            require(declaration["isa"] == row["isa"], "declared ISA does not match canonical target")
            native = target["native_target"]
            require(isinstance(native, dict) and {"triple", "data_layout", "pointer_bits", "little_endian"} <= set(native)
                    and isinstance(native["triple"], str) and native["triple"]
                    and isinstance(native["data_layout"], str) and native["data_layout"]
                    and type(native["pointer_bits"]) is int and native["pointer_bits"] > 0
                    and type(native["little_endian"]) is bool, "actual native target/DataLayout/ABI profile is incomplete")
            require(declaration["native_target"] == native, "prerequisite native target differs from source profile")
            descriptor = next(item for item in catalog["targets"] if item["id"] == row["isa"])
            require(native["triple"].split("-")[0] == descriptor["architecture"], "actual frontend architecture differs from canonical target")
            require(target["frontend_tools"] and all(role in runner.tools for role in target["frontend_tools"].values()),
                    "actual frontend tool roles are missing or unpinned")
            require(declaration["import_profiles"] == target["import_profiles"], "prerequisite import profiles differ from exact source declaration")
            require(isinstance(declaration["frontend_tools"], dict) and set(declaration["frontend_tools"]) == set(target["frontend_tools"]), "frontend role declarations differ")
            for flag, role in target["frontend_tools"].items():
                require(remember(runner, declaration["frontend_tools"][flag]) == runner.checked_isa_pin(runner.tools[role]), "frontend tool pin differs from selected source tool")
            abi_pin, abi = document(runner, declaration["abi_contract"])
            exact(abi, ["schema", "native_target", "import_profiles", "frontend_tools", "source_inputs", "recipe", "revision"], "ABI prerequisite")
            require(abi["schema"] == "ocore-target-abi-prerequisites-v1" and abi["native_target"] == native
                    and abi["import_profiles"] == declaration["import_profiles"] and abi["frontend_tools"] == declaration["frontend_tools"], "ABI/frontend/import prerequisite correspondence differs")
            require(abi["revision"] == runner.profile["implementation"]["revision"] and remember(runner, abi["recipe"]) == runner.checked_isa_pin(runner.profile["implementation"]["recipe"]), "ABI source/build recipe differs")
            require(isinstance(abi["source_inputs"], list) and abi["source_inputs"], "ABI source input inventory is empty")
            source_paths = set()
            for source_pin in abi["source_inputs"]:
                source = remember(runner, source_pin)
                source_path = Path(source["path"])
                require(Path(runner.profile["implementation"]["source_checkout"]).resolve() in source_path.parents and source["path"] not in source_paths, "ABI source pin is outside original checkout or duplicated")
                source_paths.add(source["path"])
            profile_pin, profile = document(runner, declaration["execution_profile"])
            exact(profile, ["schema", "semantic_contract", "workload", "initial_state", "provider_closure",
                            "observation_model", "comparator"], "execution prerequisite profile")
            require(profile["schema"] == "ocore-isa-execution-prerequisites-v1", "execution prerequisite schema differs")
            require(profile["observation_model"] in {"exact-defined-deterministic-v1", "predeclared-allowed-traces-v1"},
                    "unsupported observation/comparison model; post-hoc normalization is forbidden")
            require(profile["observation_model"] == "exact-defined-deterministic-v1", "concurrency/nondeterministic allowed-trace model admission is not implemented; samples cannot qualify it")
            for key in ["semantic_contract", "workload", "initial_state", "provider_closure", "comparator"]:
                remember(runner, profile[key])
            guard = declaration["guarded_runner"]
            exact(guard, ["adapter", "guard", "isa", "native_target"], "guarded runner prerequisite")
            require(guard["guard"] == "matching-native-or-explicit-emulation-v1" and guard["isa"] == row["isa"]
                    and guard["native_target"] == native, "guarded runner target/profile differs")
            remember(runner, guard["adapter"])
            oracle = declaration["reference_oracle"]
            exact(oracle, ["adapter", "revision", "execution_profile_sha256"], "original reference prerequisite")
            require(oracle["revision"] == runner.profile["implementation"]["revision"] and
                    oracle["execution_profile_sha256"] == profile_pin["sha256"], "original reference source/profile differs")
            remember(runner, oracle["adapter"])
            require(isinstance(declaration["mechanisms"], list), "mechanism declarations must be explicit")
            cases = {}
            for mechanism in declaration["mechanisms"]:
                exact(mechanism, ["id", "cases"], "mechanism prerequisite")
                identifier = mechanism["id"]
                require(isinstance(identifier, str) and identifier in mechanisms and identifier not in cases,
                        "unknown or duplicate required mechanism")
                cases[identifier] = sorted(names(mechanism["cases"], "mechanism cases"))
            require(set(cases) == mechanisms, "required mechanisms are omitted: " + repr(sorted(mechanisms - set(cases))))
            admitted_declarations[name] = {"isa": row["isa"], "execution_profile": profile_pin,
                                           "comparator": profile["comparator"], "cases": cases}
            row.update(status="DECLARED_PREREQUISITES_PRESENT", scope="declarations and file pins only; no execution admission", mechanism_case_ids=cases)
        except Exception as error:
            row["gaps"].append(str(error))
    expected_isa_pairs = set(itertools.combinations(sorted(implemented), 2))
    observed_isa_pairs = set()
    observed_profile_pairs = set()
    for pair in coverage["owned_pairs"]:
        try:
            exact(pair, ["left", "right", "comparator"], "owned comparison prerequisite")
            left, right = pair["left"], pair["right"]
            require(isinstance(left, str) and isinstance(right, str) and left != right,
                    "owned comparison needs two distinct declared target profiles")
            key = tuple(sorted([left, right]))
            require(key not in observed_profile_pairs, "duplicate owned profile pair")
            require(left in admitted_declarations and right in admitted_declarations,
                    "owned pair lacks ready target/profile/runner/reference prerequisites")
            a, b = admitted_declarations[left], admitted_declarations[right]
            require(a["isa"] != b["isa"], "owned ISA pair cannot compare one ISA to itself")
            require(a["execution_profile"]["sha256"] == b["execution_profile"]["sha256"] and a["cases"] == b["cases"],
                    "owned pair has conflicting execution profiles or mechanism case inventories")
            comparator = remember(runner, pair["comparator"])
            require(comparator["sha256"] == a["comparator"]["sha256"] == b["comparator"]["sha256"],
                    "owned pair comparator differs from predeclared execution profile")
            observed_profile_pairs.add(key)
            observed_isa_pairs.add(tuple(sorted([a["isa"], b["isa"]])))
        except Exception as error:
            summary["owned_pair_gaps"].append(str(error))
    for left, right in sorted(expected_isa_pairs - observed_isa_pairs):
        summary["owned_pair_gaps"].append("missing matched owned ISA pair: " + left + " / " + right)
    for left, a in sorted(admitted_declarations.items()):
        for other_isa in sorted(implemented - {a["isa"]}):
            if not any(left in pair and admitted_declarations[pair[0] if pair[1] == left else pair[1]]["isa"] == other_isa
                       for pair in observed_profile_pairs):
                summary["owned_pair_gaps"].append("target profile lacks matched owned comparison: " + left + " / " + other_isa)
    for row in summary["isa_rows"]:
        for profile_row in summary["profile_rows"]:
            if profile_row["target_id"] in row["configured_target_ids"] and profile_row["gaps"]:
                row["gaps"].append("incomplete target prerequisites: " + profile_row["target_id"])
        if not row["gaps"]:
            row["status"] = "DECLARED_PREREQUISITES_PRESENT"
            row["mechanism_statuses"] = {mechanism: "DECLARED_CASES_PRESENT_UNVERIFIED" for mechanism in sorted(mechanisms)}
    if (required and catalog and not summary["global_gaps"] and not summary["owned_pair_gaps"]
            and all(not row["gaps"] for row in summary["isa_rows"])
            and all(not row["gaps"] for row in summary["profile_rows"])):
        summary["status"] = "PREREQUISITES_PRESENT"
    runner.save()
    return summary
