import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("unwind_inventory", Path(__file__).with_name("build_inventory.py"))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class BuildInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.build = self.root / "source", self.root / "build"
        self.source.mkdir()
        self.build.mkdir()

    def rows(self, isa="riscv64", threads=True):
        rows, objects = [], []
        for index, name in enumerate(inventory.SOURCE_FLOOR):
            source = self.source / "libunwind/src" / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(f"original source {name}\n")
            output = self.build / f"unit-{index}.o"
            args = ["original-cc", f"--target={inventory.ISAS[isa]['triple']}",
                    *inventory.ISAS[isa]["flags"], "-D_LIBUNWIND_IS_NATIVE_ONLY"]
            if not threads:
                args.append("-D_LIBUNWIND_HAS_NO_THREADS")
            if name.endswith(".c"):
                args += ["-std=c99", "-fexceptions"]
            args += ["-o", str(output), "-c", str(source)]
            rows.append({"directory": str(self.build), "file": str(source), "arguments": args})
            objects.append(output)
        return rows, objects

    def test_configured_whole_archive_retains_all_original_sources_and_order(self):
        rows, objects = self.rows()
        # An unused shared target is retained in the raw graph but does not own a static member.
        extra = copy.deepcopy(rows[0])
        extra["arguments"][extra["arguments"].index("-o") + 1] = str(self.build / "shared-only.o")
        units = inventory.select_units([*rows, extra], objects, self.source, "riscv64", True)
        self.assertEqual([Path(unit["source"]).name for unit in units], inventory.SOURCE_FLOOR)
        self.assertEqual([unit["source_kind"] for unit in units].count("assembly"), 2)
        self.assertEqual([unit["native_output"] for unit in units], [str(path) for path in objects])
        self.assertTrue(all(unit["original_source"]["sha256"] == inventory.info(self.source / unit["source"])["sha256"] for unit in units))

    def test_missing_or_ambiguous_archive_producer_is_rejected(self):
        rows, objects = self.rows()
        for candidate in [rows[:-1], [*rows, rows[0]]]:
            with self.assertRaisesRegex(inventory.InventoryError, "ambiguous/missing"):
                inventory.select_units(candidate, objects, self.source, "riscv64", True)

    def test_assembly_cannot_be_dropped_from_configured_graph(self):
        rows, objects = self.rows()
        with self.assertRaisesRegex(inventory.InventoryError, "omits required original"):
            inventory.select_units(rows, objects[:-2], self.source, "riscv64", True)

    def test_c_raise_exception_source_contract_is_retained(self):
        rows, objects = self.rows()
        for flag in ["-std=c99", "-fexceptions"]:
            altered = copy.deepcopy(rows)
            altered[3]["arguments"].remove(flag)
            with self.assertRaisesRegex(inventory.InventoryError, "exception contract"):
                inventory.select_units(altered, objects, self.source, "riscv64", True)

    def test_no_silent_thread_or_float_abi_profile_change(self):
        rows, objects = self.rows()
        changes = [(["-D_LIBUNWIND_HAS_NO_THREADS"], None), ([], "-mabi=lp64d"), ([], "-march=rv64gc")]
        for added, removed in changes:
            altered = copy.deepcopy(rows)
            altered[0]["arguments"] += added
            if removed:
                altered[0]["arguments"].remove(removed)
            with self.assertRaises(inventory.InventoryError):
                inventory.select_units(altered, objects, self.source, "riscv64", True)
        single, outputs = self.rows(threads=False)
        self.assertEqual(len(inventory.select_units(single, outputs, self.source, "riscv64", False)), 9)

    def test_original_context_and_fpu_macros_guard_all_three_isas(self):
        for isa, profile in inventory.ISAS.items():
            macros = f"#define _LIBUNWIND_CONTEXT_SIZE {profile['context']}\n#define _LIBUNWIND_CURSOR_SIZE {profile['cursor']}\n"
            if isa == "riscv64":
                macros += "#define __riscv_xlen 64\n#define __riscv_flen 64\n#define __riscv_float_abi_double 1\n"
            inventory.check_macros(macros, isa)
            with self.assertRaises(inventory.InventoryError):
                inventory.check_macros(macros.replace("_LIBUNWIND_CONTEXT_SIZE", "wrong_context"), isa)
            if isa == "riscv64":
                with self.assertRaisesRegex(inventory.InventoryError, "LP64D/FLEN64"):
                    inventory.check_macros(macros.replace("__riscv_flen 64", "__riscv_flen 32"), isa)

    def test_original_riscv_context_expressions_are_evaluated_without_code_execution(self):
        macros = "#define RISCV_FLEN __riscv_flen\n#define _LIBUNWIND_CONTEXT_SIZE (32 * (__riscv_xlen + RISCV_FLEN) / 64)\n#define _LIBUNWIND_CURSOR_SIZE (_LIBUNWIND_CONTEXT_SIZE + 12)\n#define __riscv_xlen 64\n#define __riscv_flen 64\n#define __riscv_float_abi_double 1\n"
        inventory.check_macros(macros, "riscv64")
        with self.assertRaises(inventory.InventoryError):
            inventory.macro_integer({"a": "b", "b": "a"}, "a")
        with self.assertRaises(inventory.InventoryError):
            inventory.macro_integer({"a": "arbitrary_call()"}, "a")

    def test_original_cmake_assembly_target_argv_is_supported_exactly(self):
        rows, objects = self.rows()
        for row in rows[-2:]:
            row["arguments"][1:2] = ["-target", inventory.ISAS["riscv64"]["triple"]]
        self.assertEqual(len(inventory.select_units(rows, objects, self.source, "riscv64", True)), 9)

    def test_original_assembly_preprocessor_preserves_semantic_argv(self):
        original = ["capture-cc", "--target=riscv64-unknown-none-elf", "-march=rv64gc", "-mabi=lp64d",
                    "-D_LIBUNWIND_IS_NATIVE_ONLY", "-I", "original headers", "-fPIC", "-MD", "-MT", "unit.o",
                    "-MF", "unit.d", "-o", "unit.o", "-c", "original.S"]
        expected = ["pinned-clang", "--target=riscv64-unknown-none-elf", "-march=rv64gc", "-mabi=lp64d",
                    "-D_LIBUNWIND_IS_NATIVE_ONLY", "-I", "original headers", "-fPIC", "original.S",
                    "-E", "-P", "-x", "assembler-with-cpp"]
        self.assertEqual(inventory.preprocess_argv(original, "pinned-clang"), expected)

    def test_ninja_archive_query_preserves_order_and_rejects_duplicates(self):
        text = "lib/libunwind.a:\n  input: CXX_STATIC_LIBRARY_LINKER\n    second.o\n    first.o\n    || phony\n  outputs:\n    install\n"
        self.assertEqual(inventory.query_objects(text, self.build), [self.build / "second.o", self.build / "first.o"])
        with self.assertRaises(inventory.InventoryError):
            inventory.query_objects(text.replace("first.o", "second.o"), self.build)

    def test_actual_archive_member_content_name_and_order_are_required(self):
        units = [{"native_output": f"unit-{i}.obj", "native_output_artifact": {"sha256": f"sha-{i}"}} for i in range(9)]
        members = [{"member": f"unit-{i}.obj", "sha256": f"sha-{i}"} for i in range(9)]
        self.assertTrue(inventory.archive_matches(units, members))
        for altered in [members[:-1], list(reversed(members)), [{**members[0], "sha256": "corrupt"}, *members[1:]],
                        [{**members[0], "member": "different-source.obj"}, *members[1:]]]:
            self.assertFalse(inventory.archive_matches(units, altered))

    def test_configuration_keeps_original_threads_frame_and_native_source_profiles(self):
        for isa, profile in inventory.ISAS.items():
            args = inventory.cmake_argv(self.source, self.build, isa, True, self.root / "original headers", "cc", "cxx", "ar", "ranlib")
            self.assertIn("-DLIBUNWIND_ENABLE_THREADS=ON", args)
            self.assertIn("-DLIBUNWIND_ENABLE_FRAME_APIS=ON", args)
            self.assertIn("-DLIBUNWIND_IS_BAREMETAL=ON", args)
            self.assertIn("-DLIBUNWIND_ENABLE_CROSS_UNWINDING=OFF", args)
            self.assertIn(f"-DCMAKE_ASM_COMPILER_TARGET={profile['triple']}", args)
            self.assertFalse(any("_POSIX" in item for item in args))

    def test_cache_tamper_cannot_relabel_reduced_provider_profile(self):
        for isa in inventory.ISAS:
            args = inventory.cmake_argv(self.source, self.build, isa, True, self.root, "cc", "cxx", "ar", "ranlib")
            cache = "\n".join(arg.removeprefix("-D").replace("=", ":STRING=", 1) for arg in args if arg.startswith("-D"))
            inventory.check_cache(cache, isa, True)
            for key in ["LIBUNWIND_ENABLE_THREADS", "LIBUNWIND_ENABLE_FRAME_APIS", "LIBUNWIND_ENABLE_ASSERTIONS"]:
                with self.assertRaisesRegex(inventory.InventoryError, key):
                    inventory.check_cache(cache.replace(f"{key}:STRING=ON", f"{key}:STRING=OFF"), isa, True)


if __name__ == "__main__":
    unittest.main()
