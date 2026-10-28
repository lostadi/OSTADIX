"""Fixture qualification of direct original-source capture plus native varargs.

This is a pinned two-unit C test fixture, not an external runtime or compiler.
The complete unit containing a fixed entry and a variadic implementation is
captured and lowered without function filtering. Its owned object is compared
with the original Clang object. The separate bounded HGraph leaf profile must
still refuse this complete module.
"""
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_ocore_native_source_recipe as source_recipe

run = source_recipe.run

LEE = {
    "GIT_AUTHOR_NAME": "Lee Daghlar Ostadi",
    "GIT_AUTHOR_EMAIL": "ostadi.lee@gmail.com",
    "GIT_COMMITTER_NAME": "Lee Daghlar Ostadi",
    "GIT_COMMITTER_EMAIL": "ostadi.lee@gmail.com",
}

RUNTIME_SOURCE = r'''#include <stdarg.h>
typedef unsigned long long U;
__attribute__((noinline)) U source_fold(unsigned count, ...) {
    va_list original, copied;
    va_start(original, count);
    U first = va_arg(original, U);
    va_copy(copied, original);
    U left = 0, right = 0;
    for (unsigned i = 1; i < count; ++i) left += va_arg(original, U);
    for (unsigned i = 1; i < count; ++i) right += va_arg(copied, U);
    va_end(copied);
    va_end(original);
    return first + left + (left != right ? 0xbadf00dULL : 0);
}
U engine_add(U a, U b) {
    return source_fold(13, a, b, 1ULL, 2ULL, 3ULL, 4ULL, 5ULL,
                       6ULL, 7ULL, 8ULL, 9ULL, 10ULL, 11ULL);
}
'''


def info(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


class NativeVariadicSourceRecipeTests(unittest.TestCase):
    setUpClass = classmethod(source_recipe.NativeSourceRecipeTests.setUpClass.__func__)
    source_snapshot = source_recipe.NativeSourceRecipeTests.source_snapshot
    write_recipe = source_recipe.NativeSourceRecipeTests.write_recipe
    invoke = source_recipe.NativeSourceRecipeTests.invoke
    assert_original_source = source_recipe.NativeSourceRecipeTests.assert_original_source
    assert_bound_receipt_files = source_recipe.NativeSourceRecipeTests.assert_bound_receipt_files

    def setUp(self):
        # Environment identity overrides the older fixture's local Git config.
        with patch.dict(os.environ, LEE):
            source_recipe.NativeSourceRecipeTests.setUp(self)
        (self.source / "runtime.c").write_text(RUNTIME_SOURCE)
        environment = os.environ.copy()
        environment.update(LEE)
        for argv in (["git", "add", "runtime.c"],
                     ["git", "commit", "-qm", "original complete variadic C fixture"]):
            result = run(argv, cwd=self.source, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        revision = run(["git", "rev-parse", "HEAD"], cwd=self.source).stdout.strip()
        self.recipe["name"] = "original-c-variadic-source-cli-fixture"
        self.recipe["source"]["revision"] = revision
        self.original_source = self.source_snapshot()
        self.write_recipe()

    def test_complete_source_recipe_varargs_executes_but_keeps_native_leaf_boundary(self):
        result, output = self.invoke(kind="obj", jobs=1)
        (self.case / "driver.stdout").write_text(result.stdout)
        (self.case / "driver.stderr").write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads((output / "source-recipe.json").read_text())
        self.assertEqual((receipt["stage"], receipt["success"]), ("complete", True))
        for key in ("capture_complete", "worker_capture_complete", "lowering_complete"):
            self.assertTrue(receipt[key], key)
        self.assertFalse(receipt["runtime_complete"])
        self.assertFalse(receipt["native_execution_qualified"])
        self.assert_bound_receipt_files(receipt)
        capture = json.loads((output / "capture/report.json").read_text())
        self.assertTrue(capture["capture_complete"])
        self.assertEqual(len(capture["units"]), 2)
        self.assertEqual(len(capture["lowering_unit_ids"]), 2)
        self.assertEqual(capture["non_lowering_units"], [])
        self.assertEqual({Path(unit["source"]["path"]).name for unit in capture["units"]},
                         {"runtime.c", "cold.c"})
        coverage = json.loads((output / "lowered/coverage.json").read_text())
        for key in ("module_set_complete", "native_module_dependency_closure_complete"):
            self.assertTrue(coverage[key], key)
        self.assertEqual((coverage["required_lowering_unit_count"],
                          coverage["lowered_unit_count"]), (2, 2))
        self.assertFalse(coverage["runtime_complete"])
        self.assertFalse(coverage["native_execution_qualified"])
        package_path = output / "lowered/runtime.native-ir.json"
        package = json.loads(package_path.read_text())
        self.assertEqual(len(package["modules"]), 2)
        modules = [json.loads(record["native_ir"]) for record in package["modules"]]
        functions = [function for module in modules for function in module["functions"]]
        self.assertEqual({function["name"] for function in functions if function["entry"] is not None},
                         {"engine_add", "source_fold", "cold_path"})
        runtime_module = next(module for module in modules
                              if any(function["name"] == "source_fold"
                                     for function in module["functions"]))
        fold = next(function for function in runtime_module["functions"]
                    if function["name"] == "source_fold")
        self.assertTrue(fold["signature"]["variadic"])
        self.assertEqual(len(runtime_module["functions"]),
                         runtime_module["provenance"]["source_function_count"])
        owned = sorted((output / "lowered").glob("unit-*/module.o"))
        original = [output / "build/runtime.o", output / "build/cold.o"]
        self.assertEqual(len(owned), 2)
        self.assertTrue(all(path.is_file() for path in original))
        harness = self.case / "carrier.c"
        harness.write_text(r'''#include <stdio.h>
typedef unsigned long long U;
extern U engine_add(U, U);
extern int cold_path(int);
int main(void) {
    const U pairs[][2] = {{0,0},{20,22},{~0ULL,1},
                         {0xf123456789abcdefULL,0x1234567890abcdefULL}};
    for (unsigned i=0; i<sizeof(pairs)/sizeof(pairs[0]); ++i)
        if (engine_add(pairs[i][0],pairs[i][1]) != pairs[i][0]+pairs[i][1]+66ULL)
            return 10+i;
    if (cold_path(12) != 5) return 30;
    puts("source-recipe-varargs:4");
    return 0;
}
''')
        executions = []
        for label, objects in (("original-clang", original), ("owned-ocore", owned)):
            executable = self.case / label
            argv = [self.sdk / "clang", harness, *objects, "-no-pie", "-o", executable]
            linked = run(argv)
            (self.case / (label + ".link.stdout")).write_text(linked.stdout)
            (self.case / (label + ".link.stderr")).write_text(linked.stderr)
            self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            observed = run([executable])
            (self.case / (label + ".stdout")).write_text(observed.stdout)
            (self.case / (label + ".stderr")).write_text(observed.stderr)
            self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
            self.assertEqual(observed.stdout, "source-recipe-varargs:4\n")
            executions.append({"kind": label, "link_command": list(map(str, argv)),
                               "executable": info(executable), "exit_code": observed.returncode,
                               "stdout": observed.stdout,
                               "objects": [info(path) for path in objects]})
        evaluator = Path(os.environ.get("OCORE_TEST_NATIVE_HGRAPH_EVALUATOR",
                                       str(self.olangc.parent / "O")))
        descriptor = {"schema": "ocore-native-i64-leaf-v1",
                      "entry": "engine_add", "module": runtime_module}
        program = self.case / "unsupported-whole-variadic-leaf.O"
        program.write_text("let x = text^(20)_text;\nlet x = ocore_i64(text^(" +
                           json.dumps(descriptor, separators=(",", ":")) +
                           ")_text,$x,text^(22)_text);\ntext^($x)_text")
        refused = run([evaluator, "--json", "--executor", "graph", "--workers", "2",
                       program, self.olangc.parents[2] / "backends"])
        (self.case / "leaf-refusal.stdout.json").write_text(refused.stdout)
        (self.case / "leaf-refusal.stderr").write_text(refused.stderr)
        self.assertNotEqual(refused.returncode, 0)
        envelope = json.loads(refused.stdout)
        self.assertFalse(envelope["ok"])
        evidence = envelope["execution_evidence"]
        self.assertIsNone(evidence["admission"])
        self.assertEqual(evidence["native_leaves"], [])
        if evidence["trace"] is not None:
            self.assertEqual(evidence["trace"]["events"], [])
            self.assertEqual(evidence["trace"]["publications"], [])
        self.assert_original_source()
        proof = {"schema": "ocore-native-variadic-source-fixture-proof-v1",
                 "fixture_only": True, "runtime_complete": False,
                 "source_revision": self.recipe["source"]["revision"],
                 "source_files": [info(self.source / name) for name in ("runtime.c", "cold.c", "Makefile")],
                 "recipe": info(self.recipe_path), "source_recipe": info(output / "source-recipe.json"),
                 "capture": info(output / "capture/report.json"),
                 "coverage": info(output / "lowered/coverage.json"),
                 "module_set": info(package_path), "executions": executions,
                 "bounded_native_leaf_refused_whole_module": True,
                 "leaf_refusal": info(self.case / "leaf-refusal.stdout.json")}
        (self.case / "qualification.json").write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
