import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lua_inventory", Path(__file__).with_name("build_inventory.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@unittest.skipUnless(shutil.which("cc") and shutil.which("make") and shutil.which("ar"), "native reference tools required")
class OriginalLuaInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.build, self.capture = [self.root / name for name in ("source", "build", "capture")]
        for path in (self.source, self.build, self.capture / "wrappers", self.capture / "events"):
            path.mkdir(parents=True, exist_ok=True)
        for name, program in (("cc", "cc"), ("llvm-ar", "ar"), ("llvm-ranlib", "ranlib")):
            (self.capture / "wrappers" / name).symlink_to(shutil.which(program))
        self.names = ["core", "cold", "aux", "math", "dyn", "lua"]
        for name in self.names:
            code = "int main(void) { return 0; }\n" if name == "lua" else "int " + name + "(void) { return 1; }\n"
            (self.source / (name + ".c")).write_text(code)
        (self.source / "makefile").write_text(
            "CORE_O=core.o cold.o\nAUX_O=aux.o\nLIB_O=math.o dyn.o\nLUA_O=lua.o\n"
            "CORE_T=liblua.a\nLUA_T=lua\nALL_T=$(CORE_T) $(LUA_T)\n"
            "ALL_O=$(CORE_O) $(LUA_O) $(AUX_O) $(LIB_O)\n"
            "CC=cc\nAR=ar rc\nRANLIB=ranlib\nCFLAGS=-O2\n"
            "all: $(ALL_T)\n"
            "$(CORE_T): $(CORE_O) $(AUX_O) $(LIB_O)\n\t$(AR) $@ $?\n\t$(RANLIB) $@\n"
            "$(LUA_T): $(LUA_O) $(CORE_T)\n\t$(CC) -o $@ $(LUA_O) $(CORE_T)\n")
        self.identity_patch = patch.object(m, "source_identity", side_effect=self.identity)
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def identity(self, source):
        return {"revision": m.LUA_COMMIT, "path": str(source), "clean": True,
                "files": [m.artifact(path) for path in sorted(source.iterdir())]}

    def planned(self):
        graph = m.plan(self.source, self.build, self.capture)
        m.write(self.build / "native-build-plan.json", graph)
        return graph

    def built(self):
        graph = self.planned()
        subprocess.run([*graph["make_argv"], "all"], cwd=self.build, env=m.environment(),
                       check=True, capture_output=True)
        events = []
        for index, row in enumerate(graph["entries"]):
            event = {"kind": "clang", "cwd": str(self.build), "build_step": {"name": m.BUILD_STEP},
                     "sources": [row["source"]], "expanded_argv": row["argv"][1:],
                     "state": "finished", "exit_code": 0, "capture_errors": [],
                     "outputs": [m.artifact(Path(row["output"]))]}
            events.append(event)
            m.write(self.capture / "events" / (str(index) + ".json"), event)
        return graph, events

    def test_complete_evaluated_graph_retains_cold_and_library_sources(self):
        graph, events = self.built()
        inventory = m.inventory(self.source, self.build, self.capture)
        self.assertEqual({row["source"] for row in inventory["units"]}, {name + ".c" for name in self.names})
        self.assertEqual(len(events), len(self.names))
        self.assertEqual([row["name"] for row in inventory["original_archive_members"]],
                         ["core.o", "cold.o", "aux.o", "math.o", "dyn.o"])
        self.assertTrue(inventory["complete"])
        for key in ("dependency_closure_complete", "ocore_lowering_complete", "native_execution_qualified", "runtime_complete"):
            self.assertFalse(inventory[key])
        self.assertEqual(inventory["non_lowering_units"], [])

    def test_missing_cold_producer_or_duplicate_native_output_rejects(self):
        graph = self.planned()
        text = (self.build / "native-build-plan.stdout").read_text()
        lines = text.splitlines()
        cold = next(line for line in lines if "cold.c" in line)
        for bad in ("\n".join(line for line in lines if line != cold), text + "\n" + cold):
            with self.assertRaisesRegex(ValueError, "missing, duplicate"):
                m.compile_entries(bad, self.source, self.build, str(self.capture / "wrappers/cc"), graph["groups"])

    def test_actual_frontend_flags_missing_units_and_duplicate_attempts_reject(self):
        graph, events = self.built()
        for mutate in (lambda rows: rows.pop(),
                       lambda rows: rows.append(copy.deepcopy(rows[0])),
                       lambda rows: rows[0]["expanded_argv"].append("-ffast-math"),
                       lambda rows: rows[0].update(exit_code=1),
                       lambda rows: rows[0].update(capture_errors=["replay failed"])):
            changed = copy.deepcopy(events)
            mutate(changed)
            with self.assertRaises(ValueError):
                m.check_events(graph["entries"], changed, self.build)

    def test_substituted_native_object_or_archive_member_rejects(self):
        graph, events = self.built()
        original = self.build / "cold.o"
        original.write_bytes((self.build / "core.o").read_bytes())
        with self.assertRaisesRegex(ValueError, "production evidence"):
            m.check_events(graph["entries"], events, self.build)
        with self.assertRaisesRegex(ValueError, "archive member differs"):
            m.check_archive(self.build / "liblua.a", [self.build / name for name in
                ["core.o", "cold.o", "aux.o", "math.o", "dyn.o"]])

    def test_extra_archive_member_or_changed_archive_order_rejects(self):
        self.built()
        objects = [self.build / name for name in ["core.o", "cold.o", "aux.o", "math.o", "dyn.o"]]
        with self.assertRaisesRegex(ValueError, "order/content"):
            m.check_archive(self.build / "liblua.a", objects[::-1])
        subprocess.run(["ar", "r", str(self.build / "liblua.a"), str(self.build / "lua.o")], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "order/content"):
            m.check_archive(self.build / "liblua.a", objects)

    def test_thin_and_truncated_archive_bytes_cannot_establish_membership(self):
        self.built()
        path = self.build / "liblua.a"
        data = path.read_bytes()
        for damaged in (b"!<thin>\n" + data[8:], data[:-1], data[:40]):
            path.write_bytes(damaged)
            with self.assertRaises(ValueError):
                m.archive_members(path)

    def test_changed_source_or_plan_and_reused_outputs_reject(self):
        self.planned()
        (self.source / "cold.c").write_text("changed source")
        with self.assertRaisesRegex(ValueError, "source changed"):
            m.checked_plan(self.source, self.build, self.capture)
        with self.assertRaisesRegex(ValueError, "reuse existing"):
            (self.build / "cold.o").write_bytes(b"supplied native object")
            m.plan(self.source, self.build, self.capture)

    def test_parent_make_overrides_and_ambiguous_paths_cannot_change_graph(self):
        with patch.dict(os.environ, {"MAKEFLAGS": "-e", "MAKEFILES": "/supplied.mk", "CFLAGS": "-ffast-math",
                                     "CPPFLAGS": "-DLUA_32BITS", "TARGET_ARCH": "-ffast-math"}):
            graph = self.planned()
        self.assertTrue(all("-O2" in row["argv"] and "-ffast-math" not in row["argv"]
                            and "-DLUA_32BITS" not in row["argv"] for row in graph["entries"]))
        with self.assertRaises(ValueError):
            m.make_argv(self.source, self.source / "build", "cc", "ar", "ranlib")
        with self.assertRaises(ValueError):
            m.make_argv(self.root / "source path", self.build, "cc", "ar", "ranlib")


class RecipeTests(unittest.TestCase):
    def test_recipe_pins_helper_original_source_and_no_unsupported_success_claim(self):
        path = Path(__file__).with_name("full.recipe.json")
        recipe = json.loads(path.read_text())
        self.assertEqual(recipe["source"]["revision"], m.LUA_COMMIT)
        self.assertEqual(recipe["source_inventory_helper"]["sha256"], m.artifact(Path(m.__file__))["sha256"])
        self.assertEqual(recipe["toolchain"]["llvm_version"], "22.1.6")
        for step in recipe["commands"]:
            self.assertIn(recipe["source_inventory_helper"]["sha256"], step["argv"])
        self.assertTrue(recipe["coverage"]["require_full_unit_inventory"])
        self.assertEqual(recipe["coverage"]["required_outputs"], ["lua", "liblua.a", "native-build-plan.json", "unit-inventory.json"])


if __name__ == "__main__":
    unittest.main()
