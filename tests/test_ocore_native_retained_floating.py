"""Replay the eight retained FP import failures without regenerating their IR.

The old complete C/LLVM units remain immutable.  Reference objects are rebuilt
from those exact LLVM bytes.  Compiler-runtime archives are explicitly foreign
reference providers; passing these fixtures does not qualify provider closure.
"""

import json
import os
from pathlib import Path

from tests import test_ocore_native_floating_abi as floating


PROFILES = ("x86_64", "aarch64", "riscv64-lp64", "riscv64-lp64d")
SCOPES = ("floating_variadic", "floating_variadic_quad_first")
REQUIRED = {(profile, scope) for profile in PROFILES for scope in SCOPES}


class RetainedFloatingAbiTests(floating.NativeFloatingAbiTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.retained_manifest = Path(os.environ["OCORE_FP_RETAINED_INPUTS"])
        cls.retained_manifest_pin = floating.support.artifact(cls.retained_manifest)
        manifest = json.loads(cls.retained_manifest.read_text())
        if manifest["schema"] != "ocore-retained-fp-eight-original-units-v1":
            raise AssertionError("unexpected retained-input manifest")
        cls.retained_cases = {}
        for row in manifest["cases"]:
            key = (row["profile"], row["scope"])
            if key in cls.retained_cases:
                raise AssertionError("duplicate retained original case")
            cls.retained_cases[key] = row
        if set(cls.retained_cases) != REQUIRED:
            raise AssertionError("retained inventory is not the exact eight original failed cases")

    @classmethod
    def tearDownClass(cls):
        if floating.support.artifact(cls.retained_manifest) != cls.retained_manifest_pin:
            raise AssertionError("retained-input manifest changed")
        super().tearDownClass()

    def original(self, name, source, profile):
        inputs = self.retained_case["original_inputs"]
        selected = []
        for extension in (".c", ".ll"):
            matches = [pin for pin in inputs if Path(pin["path"]).name == name + extension]
            self.assertEqual(len(matches), 1, "missing or ambiguous complete original input")
            pin = matches[0]
            self.assertEqual(floating.support.artifact(pin["path"]), pin)
            selected.append(Path(pin["path"]))
        original_c, original_llvm = selected
        # A changed fixture must not silently become a replay of a different
        # test.  No frontend rerun, IR editing, unit filtering or retargeting.
        self.assertEqual(original_c.read_bytes(), source.encode())
        reference_object = self.directory / (name + ".reference.o")
        self.command([self.clang, *self.frontend_flags(profile), "-x", "ir", "-c",
                      original_llvm, "-o", reference_object])
        self.record.setdefault("retained_original_reference_compilations", []).append({
            "source": floating.support.artifact(original_c),
            "llvm": floating.support.artifact(original_llvm),
            "reference_object": floating.support.artifact(reference_object),
            "frontend_regenerated": False,
        })
        self.save()
        return original_c, original_llvm, reference_object

    def matrix(self, profile, scope, fixture):
        self.retained_case = self.retained_cases[(profile, scope)]
        report_pin = self.retained_case["report"]
        self.assertEqual(floating.support.artifact(report_pin["path"]), report_pin)
        historical = json.loads(Path(report_pin["path"]).read_text())
        self.assertIs(historical["complete"], False)
        self.assertEqual(historical["pairings"], [])
        self.assertEqual((historical["profile"], historical["scope"]), (profile, scope))
        self.assertEqual(historical["original_inputs"], self.retained_case["original_inputs"])
        self.assertEqual(len(historical["original_inputs"]), 6)
        self.record["retained_failure"] = report_pin
        self.record["replay_boundary"] = (
            "Exact six retained C/LLVM inputs; new references from original LLVM; "
            "all four caller/provider pairings; original-source-built foreign helper archives")
        self.save()
        super().matrix(profile, scope, fixture)
        self.assertEqual(len(self.record["pairings"]), 4)
        self.assertEqual(len(self.record["owned_modules"]), 2)
        self.assertEqual(len(self.record["original_source_inventory_checks"]), 2)
        self.assertEqual(floating.support.artifact(report_pin["path"]), report_pin)


# The inherited broad suite is not silently counted as run.  This replay has
# an explicit eight-case inventory; the retained 29-case suite stays separate.
for _name in dir(floating.NativeFloatingAbiTests):
    if _name.startswith("test_"):
        setattr(RetainedFloatingAbiTests, _name, None)

for _profile, _scope in sorted(REQUIRED):
    def _test(self, profile=_profile, scope=_scope):
        self.matrix(profile, scope, floating.variadic_sources(
            profile, reverse=scope == "floating_variadic_quad_first"))
    setattr(RetainedFloatingAbiTests,
            "test_" + _profile.replace("-", "_") + "_" + _scope, _test)
