"""Pure source/declaration controls; no compiler or runtime execution claims."""

import copy
import itertools
import json
from pathlib import Path
import re
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "crates/ostadix-api/src/ocore/common.rs"
COVERAGE = ROOT / "tools/ocore-runtime/acceptance/isa_coverage.py"
coverage = types.ModuleType("isa_declaration_coverage_from_exact_source")
exec(compile(COVERAGE.read_bytes(), str(COVERAGE), "exec"), coverage.__dict__)


def registry_catalog(source):
    """Inspect our restricted registry literals; this is not a Rust compiler."""
    start = source.index("define_targets! {") + len("define_targets! {")
    end = source.index("\n}\n", start)
    declaration = source[start:end].strip()
    pattern = re.compile(r'''([A-Za-z_][A-Za-z_0-9]*)\s*\{\s*
        id:\s*("[^"\\]*"),\s*architecture:\s*("[^"\\]*"),\s*
        name:\s*("[^"\\]*"),\s*triple:\s*("[^"\\]*"),\s*
        aliases:\s*(\[[^\]]*\])\s*\}''', re.X)
    rows = []
    pos = 0
    while pos < len(declaration):
        match = pattern.match(declaration, pos)
        if not match:
            raise coverage.CoverageError("unrecognized registry declaration")
        variant, id_, architecture, name, triple, aliases = match.groups()
        id_, architecture, name, triple, aliases = map(json.loads, [id_, architecture, name, triple, aliases])
        rows.append({"id": id_, "architecture": architecture, "target": name,
                     "assembler_triple": triple, "aliases": [name, triple] + aliases})
        pos = match.end()
        if pos < len(declaration):
            if declaration[pos] != ",":
                raise coverage.CoverageError("unrecognized registry separator")
            pos += 1
            while pos < len(declaration) and declaration[pos].isspace():
                pos += 1
    catalog = {"schema": "ocore-target-catalog-v1", "scope": "canonical-target-declarations-only", "targets": rows}
    coverage.validate_catalog(catalog)
    return catalog


def fixture_requirements(catalog):
    return {"target_profiles": [{"id": row["id"]} for row in catalog["targets"]],
            "mechanism_matrix": [{"id": "fixture-mechanism-only"}]}


def fixture_coverage(catalog, requirements):
    implemented = sorted(coverage.validate_catalog(catalog))
    required = sorted(set(implemented) | {row["id"] for row in requirements["target_profiles"]})
    return {"target_profiles": list(required), "guarded_runners": list(required),
            "original_reference_oracles": list(required),
            "mechanism_cases": [{"isa": isa, "mechanism": mechanism["id"], "cases": ["synthetic-case-only"]}
                                for isa in required for mechanism in requirements["mechanism_matrix"]],
            "owned_pairs": [list(pair) for pair in itertools.combinations(implemented, 2)]}


class CanonicalIsaSourceControls(unittest.TestCase):
    def setUp(self):
        self.source = COMMON.read_text()
        self.catalog = registry_catalog(self.source)
        self.requirements = fixture_requirements(self.catalog)
        self.declared = fixture_coverage(self.catalog, self.requirements)

    def test_enum_all_and_metadata_are_generated_by_one_registry(self):
        macro = self.source[:self.source.index("define_targets! {")]
        compact = re.sub(r"\s+", "", macro)
        for generated in ["pub enum Target { $($variant),+ }", "&[$(Self::$variant),+]",
                          "Self::$variant => $id", "Self::$variant => $architecture",
                          "Self::$variant => $name", "Self::$variant => $triple",
                          "Self::$variant => &[$name, $triple, $($alias),*]"]:
            self.assertIn(re.sub(r"\s+", "", generated), compact)
        self.assertEqual(self.source.count("define_targets! {"), 1)
        self.assertEqual(len(self.catalog["targets"]), len({r["id"] for r in self.catalog["targets"]}))

    def test_existing_parse_names_and_extra_alias_are_preserved(self):
        baseline = {"x86_64": ["x86_64-unknown-none", "x86_64-unknown-none-elf"],
                    "aarch64": ["aarch64-unknown-none", "aarch64-unknown-none-elf"],
                    "rv64gc": ["riscv64-unknown-none", "riscv64-unknown-none-elf", "riscv64gc-unknown-none-elf"]}
        for row in self.catalog["targets"]:
            if row["id"] in baseline:
                self.assertEqual(row["aliases"], baseline[row["id"]])
            self.assertNotIn(row["architecture"], row["aliases"])

    def test_compiler_catalog_iterates_registry_without_requiring_fake_input(self):
        source = (ROOT / "src/bin/ocorec.rs").read_text()
        compact = re.sub(r"\s+", "", source)
        self.assertIn('required_unless_present_any=["verify_native_map","list_targets"]', compact)
        self.assertIn("Target::ALL.iter().map", compact)
        for method in ["id", "architecture", "name", "triple", "aliases"]:
            self.assertIn("target." + method + "()", source)
        self.assertLess(source.index("if cli.list_targets {"), source.index("if cli.native_map.is_some()"))
        self.assertIn('"canonical-target-declarations-only"', source)

    def test_artifact_driver_and_runtime_use_canonical_architecture_metadata(self):
        driver = (ROOT / "crates/ostadix-api/src/ocore/driver.rs").read_text()
        self.assertNotIn("fn architecture(self)", driver)
        runtime = (ROOT / "src/bin/olangc/native_runtime.rs").read_text()
        method = runtime[runtime.index("fn architecture(target:"):]
        method = method[:method.index("\n}\n")]
        self.assertIn("Target::parse(target)", method)
        self.assertIn("Target::from_architecture(target)", method)
        self.assertNotIn('"x86_64"', method)

    def test_common_source_stays_in_generated_runtime_inventory(self):
        embedded = (ROOT / "crates/ostadix-api/src/api/aot_source.rs").read_text()
        self.assertIn('("common.rs", include_str!("../ocore/common.rs"))', embedded)
        core = (ROOT / "crates/ostadix-api/src/ocore/native_core.rs").read_text()
        self.assertIn('#[path = "common.rs"]', core)

    def test_matching_host_execution_guard_is_retained(self):
        source = (ROOT / "crates/ostadix-api/src/native_leaf.rs").read_text()
        guard = source.index("if host != audited.target {")
        self.assertIn("native scalar leaf target must match the Linux host ISA", source[guard:guard + 180])
        self.assertLess(guard, source.index("let tool_working_directory =", guard))

    def test_complete_synthetic_declarations_never_qualify_execution(self):
        result = coverage.assess_declared_coverage(self.catalog, self.requirements, self.declared)
        self.assertEqual(result["status"], "DECLARED_COVERAGE_COMPLETE")
        for flag in ["catalog_input_admitted", "exact_case_inventory_admitted", "runtime_accepted",
                     "native_execution_qualified", "all_isa_identity_qualified"]:
            self.assertFalse(result[flag])

    def test_added_canonical_backend_cannot_disappear_from_coverage(self):
        extended = copy.deepcopy(self.catalog)
        extended["targets"].append({"id": "synthetic_extra_isa", "architecture": "synthetic_extra_arch",
                                    "target": "synthetic-extra-none", "assembler_triple": "synthetic-extra-none-elf",
                                    "aliases": ["synthetic-extra-none", "synthetic-extra-none-elf"]})
        result = coverage.assess_declared_coverage(extended, self.requirements, self.declared)
        self.assertEqual(result["status"], "RED")
        for category in ["target_profiles", "guarded_runners", "original_reference_oracles"]:
            self.assertIn("synthetic_extra_isa", result["missing"][category])
        self.assertEqual(len(result["missing"]["owned_pairs"]), len(self.catalog["targets"]))
        self.assertTrue(any(row[0] == "synthetic_extra_isa" for row in result["missing"]["mechanism_declarations"]))

    def test_required_32bit_foundations_remain_red_even_if_listed(self):
        requirements = json.loads((ROOT / "tools/ocore-runtime/isa.requirements.json").read_text())
        declared = fixture_coverage(self.catalog, requirements)
        result = coverage.assess_declared_coverage(self.catalog, requirements, declared)
        self.assertEqual(result["status"], "RED")
        self.assertIn("i686", result["required_foundations_missing"])
        self.assertIn("armv7", result["required_foundations_missing"])
        self.assertTrue(all(not values for values in result["missing"].values()))

    def test_omitted_mechanism_and_owned_pair_are_retained(self):
        omitted = self.declared["mechanism_cases"].pop()
        pair = self.declared["owned_pairs"].pop()
        result = coverage.assess_declared_coverage(self.catalog, self.requirements, self.declared)
        self.assertIn([omitted["isa"], omitted["mechanism"]], result["missing"]["mechanism_declarations"])
        self.assertIn(pair, result["missing"]["owned_pairs"])

    def test_zero_cases_and_ambiguous_aliases_are_rejected(self):
        self.declared["mechanism_cases"][0]["cases"] = []
        with self.assertRaisesRegex(coverage.CoverageError, "zero cases"):
            coverage.assess_declared_coverage(self.catalog, self.requirements, self.declared)
        bad = copy.deepcopy(self.catalog)
        bad["targets"][1]["aliases"].append(bad["targets"][0]["target"])
        with self.assertRaisesRegex(coverage.CoverageError, "ambiguous"):
            coverage.validate_catalog(bad)

    def test_unknown_registry_syntax_is_not_silently_ignored(self):
        with self.assertRaisesRegex(coverage.CoverageError, "unrecognized"):
            registry_catalog(self.source.replace('id: "x86_64",', 'unparsed_field: "x86_64",'))


if __name__ == "__main__":
    unittest.main()
