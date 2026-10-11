import importlib.util
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).with_name("compiler_rt_capture.py")
spec = importlib.util.spec_from_file_location("compiler_rt_capture", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OriginalCompilerRTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.source = self.root / "source";self.build = self.root / "build"
        self.musl = {"headers":"/original-musl/include","sysroot":"/original-musl","library_dir":"/original-musl/lib"}

    def rows(self,isa):
        names = ["muldc3.c","mulsc3.c","crtbegin.c","crtend.c","atomic.c","cold-unrelated.c"]
        names += ["mulxc3.c"] if isa == "x86_64" else ["addtf3.c","multf3.c","divtf3.c"]
        rows=[]
        for n,name in enumerate(names):
            p=self.source/"compiler-rt/lib/builtins"/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(name)
            argv=["clang","--target="+m.PROFILES[isa]["triple"],"--sysroot="+self.musl["sysroot"],"-isystem",self.musl["headers"],*m.PROFILES[isa]["flags"],"-c",str(p),"-o",str(self.build/(str(n)+".o"))]
            rows.append({"file":str(p),"directory":str(self.build),"arguments":argv})
        return rows

    def test_all_original_configured_sources_include_cold_math_atomic_and_crt(self):
        for isa in m.PROFILES:
            rows=self.rows(isa);units=m.select_units(rows,self.source,self.build,isa,self.musl)
            self.assertEqual(len(units),len(rows));self.assertIn("cold-unrelated.c",{Path(u["source"]).name for u in units})

    def test_original_complex_quad_or_crt_sources_cannot_disappear(self):
        for isa in m.PROFILES:
            rows=self.rows(isa)
            for n in [0,2,4,len(rows)-1]:
                with self.assertRaises(m.InventoryError):m.select_units(rows[:n]+rows[n+1:],self.source,self.build,isa,self.musl)

    def test_duplicate_output_or_outside_native_object_is_rejected(self):
        rows=self.rows("x86_64")
        rows[1]["arguments"][-1]=rows[0]["arguments"][-1]
        with self.assertRaises(m.InventoryError):m.select_units(rows,self.source,self.build,"x86_64",self.musl)
        rows=self.rows("x86_64");rows[0]["arguments"][-1]="/supplied-native-object.o"
        with self.assertRaises(m.InventoryError):m.select_units(rows,self.source,self.build,"x86_64",self.musl)

    def test_wrong_isa_soft_rv_or_changed_fp_flags_reject_profile(self):
        for flag in ["--target=x86_64-unknown-linux-musl","-mabi=lp64","-march=rv64imac","-ffast-math"]:
            rows=self.rows("riscv64");rows[0]["arguments"].append(flag)
            with self.assertRaises(m.InventoryError):m.select_units(rows,self.source,self.build,"riscv64",self.musl)

    def test_original_asm_split_target_spelling_is_preserved(self):
        for isa in m.PROFILES:
            rows=self.rows(isa)
            rows[0]["arguments"][1:2]=["-target",m.PROFILES[isa]["triple"]]
            units=m.select_units(rows,self.source,self.build,isa,self.musl)
            self.assertEqual(units[0]["argv"],rows[0]["arguments"])
            rows[0]["arguments"].extend(["--target","aarch64-unknown-linux-gnu"])
            with self.assertRaises(m.InventoryError):m.select_units(rows,self.source,self.build,isa,self.musl)

    def test_custom_crt_source_commands_are_required_whole_producers(self):
        import shlex
        rows=self.rows("x86_64")
        original="\n".join(shlex.join(row["arguments"]) for row in rows)
        db=[row for row in rows if Path(row['file']).name not in {'crtbegin.c','crtend.c'}]
        commands=[]
        for row in rows:
            line=shlex.join(row['arguments'])
            commands.append('cd '+str(self.build)+' && '+line if 'crt' in row['file'] else line)
        combined=m.complete_source_rows(db,"\n".join(commands),self.build)
        units=m.select_units(combined,self.source,self.build,"x86_64",self.musl)
        self.assertEqual(len(units),len(rows))
        self.assertEqual(sum(r.get('custom_producer',False) for r in combined),2)
        for bad in [original+'\n'+commands[0],"\n".join(commands[:-1]),original.replace(' -c ',' && bad -c ',1)]:
            with self.assertRaises(m.InventoryError):m.complete_source_rows(rows,bad,self.build)

    def test_upstream_generated_asm_binds_original_source_and_rejects_changed_bytes(self):
        import shlex
        rows=self.rows("aarch64")
        original=self.source/'compiler-rt/lib/builtins/aarch64/lse.S'
        original.parent.mkdir(parents=True);original.write_text('original full assembly')
        generated=self.build/'outline_atomic_helpers.dir/outline_atomic_cas1_1.S'
        argv=rows[0]['arguments'][:-4]+['-DL_cas','-DSIZE=1','-DMODEL=1','-c',str(generated),'-o',str(self.build/'generated.o')]
        rows.append({'file':str(generated),'directory':str(self.build),'arguments':argv})
        commands='cmake -E create_symlink '+str(original)+' '+str(generated)+'\n'+'\n'.join(shlex.join(r['arguments']) for r in rows)
        combined=m.complete_source_rows(rows,commands,self.build)
        units=m.select_units(combined,self.source,self.build,'aarch64',self.musl)
        self.assertEqual(units[-1]['original_source']['path'],str(original))
        self.assertEqual(units[-1]['source_kind'],'assembly')
        generated.parent.mkdir(parents=True);generated.write_text('changed')
        with self.assertRaises(m.InventoryError):m.select_units(combined,self.source,self.build,'aarch64',self.musl)

    def test_upstream_configure_preserves_whole_target_atomic_crt_and_real_package(self):
        text="\n".join(m.cmake_argv(self.source,self.build,"riscv64",self.musl,Path("/sdk"),"cc","cxx","ar","ranlib"))
        for value in ["COMPILER_RT_DEFAULT_TARGET_ONLY=ON","COMPILER_RT_BUILD_CRT=ON","COMPILER_RT_EXCLUDE_ATOMIC_BUILTIN=OFF","COMPILER_RT_BUILTINS_ENABLE_PIC=ON","LLVM_CMAKE_DIR=/sdk/lib/cmake/llvm","CMAKE_SYSTEM_NAME=Linux","-march=rv64gc","-mabi=lp64d"]:self.assertIn(value,text)
        self.assertNotIn("COMPILER_RT_DEFAULT_TARGET_TRIPLE=",text)
        self.assertNotIn("CMAKE_TRY_COMPILE_TARGET_TYPE=",text)
        self.assertNotIn("ffast-math",text)

    def test_complete_archive_and_two_crt_outputs_are_mandatory(self):
        text="lib/linux/libclang_rt.builtins-x86_64.a: C_STATIC_LIBRARY_LINKER\nlib/linux/clang_rt.crtbegin-x86_64.o: CUSTOM_COMMAND\nlib/linux/clang_rt.crtend-x86_64.o: CUSTOM_COMMAND\n"
        self.assertEqual(len(m.target_outputs(text,self.build)),3)
        self.assertEqual(len(m.target_outputs(text+"libclang_rt.builtins-x86_64.a: phony\n",self.build)),3)
        for bad in [text.splitlines()[0]+"\n",text.replace("lib/linux/clang_rt.crtend-x86_64.o","../../SDK/clang_rt.crtend-x86_64.o")]:
            with self.assertRaises(m.InventoryError):m.target_outputs(bad,self.build)


if __name__ == "__main__":unittest.main()
