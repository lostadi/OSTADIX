import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("original_cxxabi_capture", Path(__file__).with_name("provider_capture.py"))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class WholeLibcxxabiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.source = self.root / "source";self.build = self.root / "build"
        self.musl = {"headers": "/source-built-musl/include"}
        self.staged = {"sysroot": "/new/source-owned-sysroot", "resource": "/new/source-owned-resource"}

    def rows(self, isa="x86_64"):
        rows, objects = [], []
        for number, name in enumerate(sorted(m.SOURCES)):
            path = self.source / "libcxxabi/src" / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_text(name)
            output = self.build / (str(number) + ".o");objects.append(output)
            argv = ["clang++", "--target=" + m.PROFILES[isa]["triple"], "--sysroot=" + self.staged["sysroot"],
                    "-isystem", self.musl["headers"], "-resource-dir=" + self.staged["resource"],
                    *m.PROFILES[isa]["flags"], "-c", str(path), "-o", str(output)]
            rows.append({"file": str(path), "directory": str(self.build), "arguments": argv})
        return rows, objects

    def test_whole18_original_bodies_preserved_and_every_missing_member_rejected(self):
        rows, objects = self.rows()
        units = m.select_units(rows, objects, self.source, self.build, "x86_64", self.musl, self.staged)
        self.assertEqual({Path(u["source"]).name for u in units}, m.SOURCES)
        for index in range(len(objects)):
            with self.assertRaises(m.InventoryError):
                m.select_units(rows, objects[:index] + objects[index + 1:], self.source, self.build, "x86_64", self.musl, self.staged)

    def test_original_threads_tls_exceptions_fp_and_rv_context_cannot_be_disabled(self):
        for flag in ["-D_LIBCXXABI_HAS_NO_THREADS", "-DHAVE___CXA_THREAD_ATEXIT_IMPL", "-fno-threadsafe-statics",
                     "-fno-exceptions", "-ffast-math", "-mabi=lp64", "-march=rv64imac"]:
            rows, objects = self.rows("riscv64");rows[0]["arguments"].append(flag)
            with self.assertRaises(m.InventoryError):
                m.select_units(rows, objects, self.source, self.build, "riscv64", self.musl, self.staged)

    def test_authentic_executable_probes_and_full_threaded_profile(self):
        argv = m.cmake_argv(self.source, self.build, self.root / "capture", "riscv64", self.musl, self.staged, "cc", "cxx", "ar", "ranlib")
        text = "\n".join(argv)
        for value in ["CMAKE_TRY_COMPILE_TARGET_TYPE=EXECUTABLE", "LIBCXXABI_ENABLE_THREADS=ON", "LIBCXXABI_ENABLE_EXCEPTIONS=ON",
                      "LIBCXXABI_ENABLE_NEW_DELETE_DEFINITIONS=ON", "LIBCXXABI_USE_LLVM_UNWINDER=ON", "LIBCXX_HAS_MUSL_LIBC=ON",
                      "LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY=OFF", "--rtlib=compiler-rt", "--unwindlib=none", "-march=rv64gc", "-mabi=lp64d"]:
            self.assertIn(value, text)
        self.assertNotIn("LIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=", text)
        self.assertNotIn("HAVE___CXA_THREAD_ATEXIT_IMPL", text)
        self.assertIn("-fuse-ld=lld", text)
        self.assertNotIn("-fuse-ld=" + str(self.root / "capture/wrappers"), text)
        cache = "\n".join(item[2:].replace("=", ":STRING=", 1) for item in argv if item.startswith("-D"))
        m.check_cache(cache, "riscv64", self.staged)
        for change in ["CMAKE_TRY_COMPILE_TARGET_TYPE:STRING=STATIC_LIBRARY", "LIBCXXABI_ENABLE_THREADS:STRING=OFF",
                       "LIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL:INTERNAL=1"]:
            with self.assertRaises(m.InventoryError):m.check_cache(cache + "\n" + change, "riscv64", self.staged)

    def test_archive_original_command_order_and_members_preserved(self):
        _, objects = self.rows()
        original = ': && cmake -E rm -f lib/libc++abi.a && llvm-ar qc lib/libc++abi.a ' + shlex.join([str(p.relative_to(self.build)) for p in objects]) + ' && llvm-ranlib lib/libc++abi.a && :'
        self.assertEqual(m.archive_command(original, self.build, objects), ["/bin/sh", "-c", original])
        deterministic=original.replace(" qc "," Dqc ")
        self.assertEqual(m.archive_command(deterministic,self.build,objects),["/bin/sh","-c",deterministic])
        for text in [original.replace(str(objects[0].relative_to(self.build)), "unowned.o"), original + "\n" + original, original.replace(" qc ", " q ")]:
            with self.assertRaises(m.InventoryError):m.archive_command(text, self.build, objects)
        with self.assertRaises(m.InventoryError):m.archive_command(original, self.build, list(reversed(objects)))

    def test_prerequisite_object_must_match_recorded_original_producer_digest(self):
        build = self.build;build.mkdir()
        capture = build.parent / "capture";(capture / "events").mkdir(parents=True)
        source = self.source / "original.c";source.parent.mkdir();source.write_text("source")
        native = build / "object.o";native.write_bytes(b"original object")
        config = build / "provider-configuration.json"
        config.write_text(json.dumps({"isa": "x86_64", "configure": {"argv": ["cmake", "-B", str(build)]}}))
        event = {"id": "original", "exit_code": 0, "outputs": [m.info(native)], "units": []}
        (capture / "events/original.json").write_text(json.dumps(event))
        archive = build / "libclang_rt.builtins-x86_64.a";archive.write_bytes(b"original archive")
        begin = build / "clang_rt.crtbegin-x86_64.o";begin.write_bytes(b"begin")
        end = build / "clang_rt.crtend-x86_64.o";end.write_bytes(b"end")
        value = {"complete": True, "issues": [], "source": {"revision": m.LLVM_COMMIT, "files": [m.info(source)]},
                 "runtime_outputs": [m.info(p) for p in [archive, begin, end]], "generated_headers": [], "build_graph_artifacts": [],
                 "configuration": m.info(config), "original_units": [{"native_output_artifact": m.info(native),
                     "invocation_ids": ["original"], "original_source": m.info(source)}]}
        inventory = build / "inventory.json";inventory.write_text(json.dumps(value))
        m.verify_provider(inventory, "x86_64", "compiler_rt")
        native.write_bytes(b"rewritten object")
        value["original_units"][0]["native_output_artifact"] = m.info(native)
        inventory.write_text(json.dumps(value))
        with self.assertRaises(m.InventoryError):m.verify_provider(inventory, "x86_64", "compiler_rt")


if __name__ == "__main__":unittest.main()
