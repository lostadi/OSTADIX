"""Guard the inventory helper; synthetic Make fixtures are not compiler evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("chibicc_inventory", Path(__file__).with_name("build_inventory.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
ORIGINAL_IDENTITY = m.source_identity


@unittest.skipUnless(shutil.which("make"), "GNU Make is required")
class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="chibicc-inventory-guard-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.build, self.capture = [self.root / name for name in ("source", "build", "capture")]
        for path in (self.source, self.build, self.capture):
            path.mkdir()
        (self.source / "Makefile").write_text(
            "CFLAGS=-std=c11 -g\nSRCS=$(wildcard *.c)\nOBJS=$(SRCS:.c=.o)\n"
            "TEST_SRCS=$(wildcard test/*.c)\nTESTS=$(TEST_SRCS:.c=.exe)\n"
            "chibicc: $(OBJS)\n\t$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)\n"
            "$(OBJS): engine.h\n")
        (self.source / "engine.h").write_text("/* inventory fixture only */\n")
        for name in ("alpha", "beta"):
            (self.source / (name + ".c")).write_text("int " + name + "(void) { return 1; }\n")
        self.identity_patch = mock.patch.object(m, "source_identity", side_effect=self.synthetic_identity)
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def synthetic_identity(self, source):
        return {"revision": "synthetic-inventory-guard", "path": str(source), "clean": True,
                "files": [m.artifact(path) for path in sorted(source.iterdir()) if path.is_file()]}

    def plan(self):
        graph = m.plan(self.source, self.build, self.capture)
        (self.build / "native-build-plan.json").write_text(json.dumps(graph))
        return graph

    def events(self, graph):
        result = []
        for row in graph["entries"]:
            path = Path(row["output"])
            path.write_bytes(b"fixture native object: " + path.name.encode())
            result.append({"build_step": {"name": m.BUILD_STEP}, "cwd": str(self.build),
                           "expanded_argv": row["argv"][1:], "sources": [row["source"]],
                           "state": "finished", "exit_code": 0, "capture_errors": [],
                           "outputs": [m.artifact(path)]})
        output = self.build / "chibicc"
        output.write_bytes(b"fixture reference output; never executed")
        result.append({"build_step": {"name": m.BUILD_STEP}, "cwd": str(self.build),
                       "expanded_argv": graph["link_argv"][1:], "sources": [],
                       "state": "finished", "exit_code": 0, "capture_errors": [],
                       "outputs": [m.artifact(output)]})
        return result

    def test_original_make_wildcards_are_preserved_out_of_tree(self):
        before = self.synthetic_identity(self.source)
        graph = self.plan()
        self.assertEqual(graph["groups"]["SRCS"], ["alpha.c", "beta.c"])
        self.assertEqual({Path(row["source"]["path"]).name for row in graph["entries"]},
                         {"alpha.c", "beta.c"})
        self.assertEqual(m.checked_plan(self.source, self.build, self.capture), graph)
        self.assertEqual(self.synthetic_identity(self.source), before)
        self.assertFalse(graph["runtime_complete"])
        self.assertFalse(graph["compiler_output_routed_through_ocore"])

    def test_missing_duplicate_or_unplanned_make_producers_reject(self):
        graph = self.plan()
        text = (self.build / "native-build-plan.stdout").read_text()
        lines = text.splitlines()
        for changed in ("\n".join(lines[1:]), text + lines[0] + "\n", text + "echo bypass\n"):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    m.compile_entries(changed, self.source, self.build,
                                      str(self.capture / "wrappers/cc"), graph["groups"])

    def test_every_source_object_and_final_link_need_matching_evidence(self):
        graph = self.plan()
        events = self.events(graph)
        m.check_events(graph, events, self.build)
        for changed in (events[1:], events + [events[0]], events[:-1], events + [events[-1]]):
            with self.assertRaises(ValueError):
                m.check_events(graph, changed, self.build)
        changed = copy.deepcopy(events)
        changed[0]["expanded_argv"].append("-DCHANGED=1")
        with self.assertRaises(ValueError):
            m.check_events(graph, changed, self.build)
        Path(graph["entries"][0]["output"]).write_bytes(b"replaced object")
        with self.assertRaises(ValueError):
            m.check_events(graph, events, self.build)

    def test_actual_linker_child_is_bound_to_the_exact_driver_link(self):
        graph = self.plan()
        events = self.events(graph)
        link = events[-1]
        link.update(id="driver-link", native_tool_invocation_ids=["actual-linker"])
        child = {"build_step": {"name": m.BUILD_STEP},
                 "id": "actual-linker", "parent_invocation_id": "driver-link",
                 "kind": "linker", "classification": "native-tool", "sources": [],
                 "cwd": str(self.build), "expanded_argv": ["--driver-selected-linker"],
                 "state": "finished", "exit_code": 0, "capture_errors": [],
                 "outputs": [m.artifact(self.build / "chibicc")]}
        m.check_events(graph, [child, *events], self.build)
        for field, value in (("parent_invocation_id", "orphan"), ("id", "unrecorded"),
                             ("kind", "assembler"), ("exit_code", 1),
                             ("outputs", []), ("capture_errors", ["unverified link"])):
            changed = copy.deepcopy(child)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    m.check_events(graph, [*events, changed], self.build)
        with self.assertRaises(ValueError):
            m.check_events(graph, [*events, child, child], self.build)
        with self.assertRaises(ValueError):
            m.check_events(graph, events, self.build)

    def test_changed_source_and_plan_evidence_reject(self):
        self.plan()
        (self.source / "alpha.c").write_text("int replaced;\n")
        with self.assertRaises(ValueError):
            m.checked_plan(self.source, self.build, self.capture)

    def test_cached_outputs_and_path_aliases_reject(self):
        (self.source / "alpha.o").write_bytes(b"cached object")
        with self.assertRaises(ValueError):
            self.plan()
        groups = m.make_groups(self.source)
        with self.assertRaises(ValueError):
            m.make_argv(self.source, self.source, self.capture, groups)
        with self.assertRaises(ValueError):
            m.make_argv(self.source, self.root / "build space", self.capture, groups)

    def test_parent_make_overrides_do_not_change_the_graph(self):
        with mock.patch.dict(os.environ, {"MAKEFLAGS": "-e", "MAKEFILES": "/missing/override.mk",
                                         "CPPFLAGS": "-DUNPLANNED=1"}):
            graph = self.plan()
        self.assertEqual(graph["groups"]["CFLAGS"], ["-std=c11", "-g"])
        self.assertNotIn("UNPLANNED", (self.build / "native-build-plan.stdout").read_text())

    def test_original_git_revision_and_cleanliness_are_required(self):
        with mock.patch.object(m, "command", return_value="different revision\n"):
            with self.assertRaises(ValueError):
                ORIGINAL_IDENTITY(self.source)
        with mock.patch.object(m, "command", side_effect=[m.CHIBICC_COMMIT + "\n", "?? changed.c\n"]):
            with self.assertRaises(ValueError):
                ORIGINAL_IDENTITY(self.source)

    def test_recipe_pins_current_helper_and_complete_original_profile(self):
        directory = Path(__file__).parent
        recipe = json.loads((directory / "chibicc.recipe.json").read_text())
        digest = hashlib.sha256((directory / "build_inventory.py").read_bytes()).hexdigest()
        self.assertEqual(recipe["source"]["revision"], m.CHIBICC_COMMIT)
        self.assertEqual(recipe["source_inventory_helper"]["sha256"], digest)
        for step in recipe["commands"]:
            self.assertIn(digest, step["argv"])
        self.assertTrue(recipe["coverage"]["require_full_unit_inventory"])


if __name__ == "__main__":
    unittest.main()
