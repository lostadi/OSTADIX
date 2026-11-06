#!/usr/bin/env python3
"""Fail closed on missing ISA declarations; this does not admit executions.

The catalog must eventually come from the pinned compiler's --list-targets and
be bound independently to its source/build identity. This module checks coverage
structure only. Exact ABI/profile/case inventory, artifact admission, guarded
execution and semantic comparison evidence require separate acceptance stages.
"""

import itertools


class CoverageError(ValueError):
    pass


def require(value, message):
    if not value:
        raise CoverageError(message)


def identifiers(values, label):
    require(isinstance(values, list) and all(isinstance(v, str) and v for v in values),
            label + " must be an explicit string list")
    require(len(values) == len(set(values)), label + " contains duplicates")
    return set(values)


def validate_catalog(catalog):
    require(isinstance(catalog, dict) and set(catalog) == {"schema", "scope", "targets"},
            "catalog fields differ")
    require(catalog["schema"] == "ocore-target-catalog-v1" and
            catalog["scope"] == "canonical-target-declarations-only", "catalog schema/scope differs")
    require(isinstance(catalog["targets"], list) and catalog["targets"], "canonical catalog cannot be empty")
    seen = {field: set() for field in ["id", "architecture", "target", "assembler_triple", "aliases"]}
    for row in catalog["targets"]:
        require(isinstance(row, dict) and set(row) == set(seen), "canonical target fields differ")
        for field in ["id", "architecture", "target", "assembler_triple"]:
            value = row[field]
            require(isinstance(value, str) and value and value not in seen[field],
                    "empty or duplicate canonical " + field)
            seen[field].add(value)
        aliases = identifiers(row["aliases"], "target aliases")
        require({row["target"], row["assembler_triple"]} <= aliases, "canonical aliases omit name/triple")
        require(not aliases & seen["aliases"], "ambiguous target aliases")
        seen["aliases"].update(aliases)
    return seen["id"]


def assess_declared_coverage(catalog, requirements, declared):
    """Return bounded omissions, retaining every unsupported required foundation.

    Declared runner/oracle/case presence is not proof that those records execute
    or are independently admitted. Even a complete declaration result cannot
    accept a runtime or qualify all-ISA functional identity.
    """
    implemented = validate_catalog(catalog)
    minimum = identifiers([row["id"] for row in requirements["target_profiles"]], "minimum profiles")
    mechanisms = identifiers([row["id"] for row in requirements["mechanism_matrix"]], "mechanisms")
    require(minimum and mechanisms, "required profile/mechanism matrices cannot be empty")
    required = implemented | minimum
    require(isinstance(declared, dict) and set(declared) == {
        "target_profiles", "guarded_runners", "original_reference_oracles", "mechanism_cases", "owned_pairs"
    }, "coverage declaration fields differ")
    missing = {}
    for field in ["target_profiles", "guarded_runners", "original_reference_oracles"]:
        observed = identifiers(declared[field], field)
        require(not observed - required, "unknown ISA in " + field)
        missing[field] = sorted(required - observed)
    require(isinstance(declared["mechanism_cases"], list), "mechanism cases must be explicit")
    observed = set()
    for row in declared["mechanism_cases"]:
        require(isinstance(row, dict) and set(row) == {"isa", "mechanism", "cases"},
                "mechanism case fields differ")
        pair = (row["isa"], row["mechanism"])
        require(pair[0] in required and pair[1] in mechanisms and pair not in observed,
                "unknown or duplicate mechanism/ISA declaration")
        cases = identifiers(row["cases"], "mechanism case IDs")
        require(cases, "required mechanism cannot declare zero cases")
        observed.add(pair)
    missing["mechanism_declarations"] = [list(pair) for pair in sorted(
        set(itertools.product(required, mechanisms)) - observed)]
    require(isinstance(declared["owned_pairs"], list), "owned pairs must be explicit")
    pairs = set()
    for row in declared["owned_pairs"]:
        values = identifiers(row, "owned pair")
        require(len(values) == 2 and values <= implemented, "owned pair requires two implemented ISAs")
        pair = tuple(sorted(values))
        require(pair not in pairs, "duplicate owned pair")
        pairs.add(pair)
    expected_pairs = set(itertools.combinations(sorted(implemented), 2))
    missing["owned_pairs"] = [list(pair) for pair in sorted(expected_pairs - pairs)]
    missing_foundations = sorted(minimum - implemented)
    complete = not missing_foundations and not any(missing.values())
    return {
        "schema": "ocore-isa-declared-coverage-v1",
        "scope": "ISA and nonempty mechanism-case declarations only; no exact ABI/case completeness or execution admission",
        "status": "DECLARED_COVERAGE_COMPLETE" if complete else "RED",
        "implemented_isa_ids": sorted(implemented), "required_isa_ids": sorted(required),
        "required_foundations_missing": missing_foundations, "missing": missing,
        "catalog_input_admitted": False, "exact_case_inventory_admitted": False,
        "runtime_accepted": False, "native_execution_qualified": False,
        "all_isa_identity_qualified": False,
    }
