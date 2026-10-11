import copy
import importlib.util
from pathlib import Path
import shlex
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("musl_inventory", Path(__file__).with_name("build_inventory.py"))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.build = self.root / "source", self.root / "build"
        self.source.mkdir()
        self.build.mkdir()

    def graph(self, isa="riscv64"):
        value = {key: "" for key in inventory.GRAPH_KEYS}
        value.update(ARCH=isa, ADD_CFI="no", MALLOC_DIR="mallocng", STATIC_LIBS="lib/libc.a",
                     CC=f"capture-cc --target={inventory.PROFILES[isa]['triple']} " + " ".join(inventory.PROFILES[isa]["flags"]),
                     CFLAGS_ALL="-std=c99 -ffreestanding -nostdinc -frounding-math")
        return value

    def entries(self):
        names = ["src/thread/pthread_create.c", "src/env/__init_tls.c", "src/malloc/mallocng/malloc.c",
                 "src/stdio/vfprintf.c", "src/math/sin.c", "src/thread/riscv64/clone.s",
                 "src/unrelated/cold-function.c", "crt/crt1.c"]
        commands = []
        for name in names:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"original {name}\n")
            output = "obj/" + str(Path(name).with_suffix(".o"))
            commands.append(shlex.join(["capture-cc", "--target=riscv64-unknown-linux-musl", "-march=rv64gc",
                                        "-mabi=lp64d", "-std=c99", "-ffreestanding", "-c", "-o", output, str(path)]))
        return inventory.compiler_entries("\n".join(commands), self.source, self.build, "capture-cc")

    def test_entire_original_graph_keeps_cold_libc_tls_math_arch_and_startup_units(self):
        entries = self.entries()
        graph = self.graph()
        graph["AOBJS"] = " ".join(str(Path(item["output"]).relative_to(self.build)) for item in entries[:-1])
        graph["CRT_OBJS"] = str(Path(entries[-1]["output"]).relative_to(self.build))
        inventory.require_graph_producers(graph, entries, self.build)
        self.assertEqual(len(entries), 8)
        self.assertTrue(any("cold-function" in entry["source"]["path"] for entry in entries))
        self.assertEqual(sum(entry["source_kind"] == "assembly" for entry in entries), 1)
        self.assertTrue(all(entry["source"] == inventory.info(Path(entry["source"]["path"])) for entry in entries))

    def test_missing_and_unplanned_producers_fail_exact_full_graph(self):
        entries = self.entries()
        graph = self.graph()
        graph["AOBJS"] = " ".join(str(Path(item["output"]).relative_to(self.build)) for item in entries)
        for bad in [entries[:-1], [*entries, {**entries[-1], "output": str(self.build / "unplanned.o")}]]:
            with self.assertRaisesRegex(inventory.InventoryError, "producer graph mismatch"):
                inventory.require_graph_producers(graph, bad, self.build)

    def test_thread_tls_malloc_math_and_assembly_must_not_disappear(self):
        entries = self.entries()
        for remove in ["pthread_create", "__init_tls", "malloc.c", "sin.c", "clone.s"]:
            altered = [item for item in entries if remove not in item["source"]["path"]]
            graph = self.graph()
            graph["AOBJS"] = " ".join(str(Path(item["output"]).relative_to(self.build)) for item in altered)
            with self.assertRaises(inventory.InventoryError):
                inventory.require_graph_producers(graph, altered, self.build)

    def test_original_profile_guards_all_three_targets(self):
        for isa in inventory.PROFILES:
            graph = self.graph(isa)
            inventory.check_profile(graph, isa)
            for key, wrong in [("ARCH", "wrong"), ("STATIC_LIBS", ""), ("SHARED_LIBS", "lib/libc.so"),
                               ("MALLOC_DIR", "reimplementation"), ("ADD_CFI", "yes"), ("SUBARCH", "-sf")]:
                with self.assertRaises(inventory.InventoryError):
                    inventory.check_profile({**graph, key: wrong}, isa)

    def test_rv_soft_float_or_overridden_target_cannot_relabel_lp64d(self):
        graph = self.graph()
        for extra in [" -mabi=lp64", " -march=rv64imac", " --target=x86_64-unknown-linux-musl"]:
            with self.assertRaises(inventory.InventoryError):
                inventory.check_profile({**graph, "CC": graph["CC"] + extra}, "riscv64")

    def test_fast_math_rejects_semantic_profile_change(self):
        graph = self.graph()
        with self.assertRaises(inventory.InventoryError):
            inventory.check_profile({**graph, "CFLAGS_ALL": graph["CFLAGS_ALL"] + " -ffast-math"}, "riscv64")

    def test_expanded_graph_missing_or_duplicate_fields_is_rejected(self):
        graph = self.graph()
        text = "\n".join(f"OCORE_MUSL_{key}={value}" for key, value in graph.items())
        self.assertEqual(inventory.parse_graph(text), graph)
        for bad in [text + "\nOCORE_MUSL_ARCH=riscv64", text.replace("OCORE_MUSL_ARCH=", "missing_ARCH=")]:
            with self.assertRaises(inventory.InventoryError):
                inventory.parse_graph(bad)

    def test_duplicate_output_and_external_source_are_rejected(self):
        entries = self.entries()
        line = entries[0]["command"]
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate"):
            inventory.compiler_entries(line + "\n" + line, self.source, self.build, "capture-cc")
        external = self.root / "external.c"
        external.write_text("not the pinned source\n")
        with self.assertRaisesRegex(inventory.InventoryError, "outside pinned"):
            inventory.compiler_entries(shlex.join(["capture-cc", "-c", "-o", "one.o", str(external)]), self.source, self.build, "capture-cc")

    def test_include_and_output_filenames_are_not_mistaken_for_source_units(self):
        path = self.source / "unit.c"
        path.write_text("original unit\n")
        line = shlex.join(["capture-cc", "-I", "misleading.c", "-include", "another.c", "-c", "-o", "output.c", str(path)])
        entries = inventory.compiler_entries(line, self.source, self.build, "capture-cc")
        self.assertEqual(entries[0]["source"], inventory.info(path))

    def test_configure_preserves_default_math_and_full_static_graph(self):
        for isa in inventory.PROFILES:
            args = inventory.configure_argv(self.source, self.build, self.root / "capture", isa)
            self.assertIn("--enable-static", args)
            self.assertIn("--disable-shared", args)
            self.assertFalse(any("LIBCC=" in arg or "CFLAGS=" in arg or "--disable-wrapper" == arg for arg in args))
            self.assertIn(f"--target={inventory.PROFILES[isa]['triple']}", args)


if __name__ == "__main__":
    unittest.main()
