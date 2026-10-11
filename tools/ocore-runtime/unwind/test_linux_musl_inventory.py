import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name("linux_musl_inventory.py")
spec = importlib.util.spec_from_file_location("linux_musl_inventory", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class LinuxMuslProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.musl = {"headers": "/source-built-musl/include", "sysroot": "/source-built-musl",
                     "library_dir": "/source-built-musl/lib"}

    def rows(self, isa):
        rows, objects = [], []
        for n, name in enumerate(m.base.SOURCE_FLOOR):
            path = self.root / "libunwind/src" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("unchanged fixture source " + name)
            output = self.root / "build" / (str(n) + ".o")
            args = ["clang", "--target=" + m.PROFILES[isa]["triple"],
                    "--sysroot=" + self.musl["sysroot"], "-nostdlibinc", "-isystem", self.musl["headers"],
                    *m.PROFILES[isa]["flags"], "-fPIC", "-c", str(path), "-o", str(output)]
            if name.endswith(".c"): args.extend(["-std=c99", "-fexceptions"])
            rows.append({"directory": str(self.root), "file": str(path), "arguments": args})
            objects.append(output)
        return rows, objects

    def cache(self, isa):
        values = {"LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
                  "LIBUNWIND_ENABLE_THREADS": "ON", "LIBUNWIND_ENABLE_ASSERTIONS": "ON",
                  "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "LIBUNWIND_IS_BAREMETAL": "OFF",
                  "LIBUNWIND_ENABLE_CROSS_UNWINDING": "OFF", "LIBUNWIND_WEAK_PTHREAD_LIB": "OFF",
                  "CMAKE_SYSTEM_NAME": "Linux", "CMAKE_SYSROOT": self.musl["sysroot"],
                  **{key: m.PROFILES[isa]["triple"] for key in
                     ["CMAKE_C_COMPILER_TARGET", "CMAKE_CXX_COMPILER_TARGET", "CMAKE_ASM_COMPILER_TARGET"]}}
        return "\n".join(key + ":STRING=" + value for key, value in values.items())

    def test_all_three_genuine_linux_profiles_keep_threads_and_entire_archive(self):
        for isa in m.PROFILES:
            rows, objects = self.rows(isa)
            units = m.select_units(rows, objects, self.root, isa, self.musl)
            self.assertEqual([Path(u["source"]).name for u in units], m.base.SOURCE_FLOOR)
            self.assertEqual(sum(u["source_kind"] == "assembly" for u in units), 2)
            m.check_cache(self.cache(isa), isa, self.musl)

    def test_threads_baremetal_target_and_header_profile_changes_are_rejected(self):
        for change in ["_LIBUNWIND_HAS_NO_THREADS", "_LIBUNWIND_IS_BAREMETAL", "-ffast-math", "-ffreestanding"]:
            rows, objects = self.rows("x86_64")
            rows[0]["arguments"].append("-D" + change if change.startswith("_") else change)
            with self.assertRaises(m.InventoryError):
                m.select_units(rows, objects, self.root, "x86_64", self.musl)
        rows, objects = self.rows("aarch64")
        rows[0]["arguments"].append("--target=x86_64-unknown-linux-musl")
        with self.assertRaises(m.InventoryError): m.select_units(rows, objects, self.root, "aarch64", self.musl)
        rows[0]["arguments"].pop()
        rows[0]["arguments"].remove("--sysroot=" + self.musl["sysroot"])
        with self.assertRaises(m.InventoryError): m.select_units(rows, objects, self.root, "aarch64", self.musl)

    def test_rv_full_floating_context_and_no_conflicting_abi_flags(self):
        for flag in ["-mabi=lp64", "-march=rv64imac"]:
            rows, objects = self.rows("riscv64")
            rows[0]["arguments"].append(flag)
            with self.assertRaises(m.InventoryError): m.select_units(rows, objects, self.root, "riscv64", self.musl)

    def test_missing_original_assembly_or_exception_flag_rejects_inventory(self):
        rows, objects = self.rows("x86_64")
        with self.assertRaises(m.InventoryError): m.select_units(rows[:-1], objects[:-1], self.root, "x86_64", self.musl)
        rows[3]["arguments"].remove("-fexceptions")
        with self.assertRaises(m.InventoryError): m.select_units(rows, objects, self.root, "x86_64", self.musl)

    def test_runtime_cache_cannot_silently_disable_linux_threading_or_weak_locks(self):
        for old, new in [("LIBUNWIND_ENABLE_THREADS:STRING=ON", "LIBUNWIND_ENABLE_THREADS:STRING=OFF"),
                         ("LIBUNWIND_IS_BAREMETAL:STRING=OFF", "LIBUNWIND_IS_BAREMETAL:STRING=ON"),
                         ("LIBUNWIND_WEAK_PTHREAD_LIB:STRING=OFF", "LIBUNWIND_WEAK_PTHREAD_LIB:STRING=ON"),
                         ("CMAKE_SYSTEM_NAME:STRING=Linux", "CMAKE_SYSTEM_NAME:STRING=Generic")]:
            with self.assertRaises(m.InventoryError): m.check_cache(self.cache("x86_64").replace(old,new), "x86_64", self.musl)

    def test_configure_declares_authentic_sysroot_and_keeps_original_source_flags(self):
        args = m.cmake_argv(self.root, self.root / "build", "riscv64", self.musl, "cc", "cxx", "ar", "ranlib")
        text = "\n".join(args)
        for item in ["CMAKE_SYSTEM_NAME=Linux", "LIBUNWIND_IS_BAREMETAL=OFF", "LIBUNWIND_ENABLE_THREADS=ON",
                     "LIBUNWIND_ENABLE_STATIC=ON", "LIBUNWIND_ENABLE_SHARED=OFF", "-march=rv64gc", "-mabi=lp64d"]:
            self.assertIn(item,text)
        for item in ["_LIBUNWIND_HAS_NO_THREADS", "_LIBUNWIND_IS_BAREMETAL", "ffast-math", "CFLAGS=-fno"]:
            self.assertNotIn(item,text)

    def test_byte_changed_dependency_artifact_is_rejected(self):
        path = self.root / "generated-header.h"
        path.write_text("original bytes")
        record = m.info(path)
        m.check_artifact(record)
        path.write_text("rewritten bytes")
        with self.assertRaises(m.InventoryError): m.check_artifact(record)

    def test_header_provenance_wrong_isa_and_forged_source_revision_are_rejected(self):
        for change in [{"isa":"riscv64"}, {"source":{"revision":"0"*40}}]:
            row = {"isa":"x86_64", "triple":"x86_64-unknown-linux-musl", "source":{"revision":m.MUSL_COMMIT}} | change
            path = self.root / "header-receipt.json";path.write_text(json.dumps(row))
            with patch.dict(m.MUSL_PROVENANCE_SHA,{"x86_64":m.info(path)["sha256"]}):
                with self.assertRaises(m.InventoryError): m.verify_musl(path,"x86_64")

    def test_untrusted_mutually_consistent_header_receipt_is_rejected(self):
        path = self.root / "header-receipt.json"
        path.write_text(json.dumps({"isa":"x86_64", "triple":"x86_64-unknown-linux-musl"}))
        with self.assertRaises(m.InventoryError): m.verify_musl(path,"x86_64")

    def test_empty_original_feature_macros_do_not_consume_following_layout_definitions(self):
        for isa, profile in m.PROFILES.items():
            text = ("#define _EMPTY_FEATURE\n#define _LIBUNWIND_CONTEXT_SIZE " + str(profile["context"])
                    + "\n#define _OTHER_EMPTY\n#define _LIBUNWIND_CURSOR_SIZE " + str(profile["cursor"])
                    + "\n#define _LIBUNWIND_TARGET_LINUX 1\n"
                    + "#define __riscv_xlen 64\n#define __riscv_flen 64\n#define __riscv_float_abi_double 1\n")
            m.check_context_macros(text, isa)
            with self.assertRaises(m.InventoryError):
                m.check_context_macros(text.replace("_LIBUNWIND_TARGET_LINUX 1", "_LIBUNWIND_TARGET_LINUX 0"), isa)

    def test_full_ninja_dependency_metadata_is_preserved_in_exact_observed_argv(self):
        rows, objects = self.rows("x86_64")
        units = m.select_units(rows, objects, self.root, "x86_64", self.musl)
        import shlex
        commands = []
        for unit in units:
            args = unit["argv"][:1] + ["-MD", "-MT", unit["native_output"], "-MF", unit["native_output"]+".d"] + unit["argv"][1:]
            commands.append(shlex.join(args))
        text = "\n".join(commands)
        m.bind_expanded_commands(units,text,self.root)
        self.assertIn("-MF",units[0]["argv"])
        self.assertNotIn("-MF",units[0]["compile_database_argv"])
        self.assertEqual(m.without_dependency_outputs(units[0]["argv"]),units[0]["compile_database_argv"])
        for bad in [text.replace("-fPIC", "-ffast-math",1), text+"\n"+commands[0], "\n".join(commands[:-1])]:
            with self.assertRaises(m.InventoryError):
                m.bind_expanded_commands(m.select_units(rows,objects,self.root,"x86_64",self.musl),bad,self.root)


if __name__ == "__main__": unittest.main()
