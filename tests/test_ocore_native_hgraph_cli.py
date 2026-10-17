"""Actual owned scalar executables beneath ordinary admitted O HGraphs.

Descriptors contain complete modules imported from original Clang22 C fixture
units. Public execution evidence must show actual successful resource producers,
and must withhold a successor Store after native failure. This bounded integer
leaf profile does not qualify general graph-to-native or foreign runtime support.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline


ROOT = Path(__file__).resolve().parents[1]
SDK_DEFAULT = Path.home()/".local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin"
FLAGS = ["-O1", "-S", "-emit-llvm", "-ffreestanding", "-fno-builtin",
         "-fno-pic", "-fno-pie", "-fno-stack-protector", "-fno-vectorize",
         "-fno-slp-vectorize", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]


def run(argv, **kwargs):
    return subprocess.run([str(value) for value in argv], capture_output=True,
                          text=True, timeout=120, **kwargs)


class NativeHgraphCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = Path(os.environ.get("OCORE_TEST_NATIVE_HGRAPH_EVALUATOR", str(ROOT/"target/debug/O")))
        cls.olangc = ROOT/"target/debug/olangc"
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK_DEFAULT)))
        for executable in (cls.evaluator, cls.olangc, cls.sdk/"clang"):
            if not executable.is_file() or not os.access(executable,os.X_OK):
                raise unittest.SkipTest(f"actual fresh evaluator, compiler and LLVM22 frontend required: {executable}")
        version = run([cls.sdk/"clang", "--version"])
        if version.returncode or not re.search(r"clang version 22\.1\.6(?:\s|$)",version.stdout):
            raise RuntimeError("actual Clang22.1.6 frontend required")
        cls.library = baseline.llvm_library()
        cls.library_sha256 = os.environ.get("OCORE_TEST_LLVM_SHA256",importer.PINNED_SHA256)
        if hashlib.sha256(cls.library.read_bytes()).hexdigest() != cls.library_sha256:
            raise RuntimeError("actual LLVM parser differs from the selected test pin")
        retained = os.environ.get("OCORE_TEST_NATIVE_HGRAPH_OUTPUT_DIR")
        if retained:
            parent = Path(retained).expanduser().resolve()
            parent.mkdir(parents=True,exist_ok=True)
            cls.directory = Path(tempfile.mkdtemp(prefix="run-",dir=parent))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-hgraph-cli-")
            cls.addClassCleanup(temporary.cleanup)
            cls.directory = Path(temporary.name)
        fixtures = {
            "add":("native_add", "long long native_add(long long x) { return x + 1; }\n"),
            "zero":("native_zero", "long long native_zero(void) { return 42; }\n"),
            "ten":("native_ten", "long long native_ten(long long a,long long b,long long c,long long d,long long e,long long f,long long g,long long h,long long i,long long j) { return a+b+c+d+e+f+g+h+i+j; }\n"),
            "trap":("native_trap", "long long native_trap(long long x) { __builtin_trap(); }\n"),
            "impure":("native_add", "long long native_add(long long x) { return x+1; }\nlong long counter; long long unused_original_memory(long long x) { counter=x; return counter; }\n"),
            "external":("native_add", "extern long long foreign_provider(long long); long long native_add(long long x) { return foreign_provider(x); }\n"),
        }
        cls.descriptors = {}
        records = []
        for name,(entry,body) in fixtures.items():
            source = cls.directory/(name+".c")
            llvm = cls.directory/(name+".ll")
            source.write_text(body)
            result = run([cls.sdk/"clang",*FLAGS,source,"-o",llvm])
            if result.returncode:
                raise RuntimeError(f"original complete C fixture failed frontend: {result.stderr}")
            module = importer.import_module(llvm,library_path=cls.library,
                                            expected_sha256=cls.library_sha256)
            if len(module["functions"]) != module["provenance"]["source_function_count"]:
                raise RuntimeError("the complete source function inventory must be retained")
            descriptor = {"schema":"ocore-native-i64-leaf-v1","entry":entry,"module":module}
            cls.descriptors[name] = descriptor
            records.append({"name":name,"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
                            "llvm_sha256":hashlib.sha256(llvm.read_bytes()).hexdigest(),
                            "function_count":len(module["functions"]),"global_count":len(module["globals"])})
        (cls.directory/"original-fixtures.json").write_text(json.dumps({
            "fixtures":records,"frontend_sha256":hashlib.sha256((cls.sdk/"clang").read_bytes()).hexdigest(),
            "llvm_parser_sha256":cls.library_sha256,"runtime_complete":False},indent=2)+"\n")

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-",dir=self.directory))

    @staticmethod
    def descriptor_text(descriptor):
        return json.dumps(descriptor,separators=(",",":"))

    def source(self,name="add",arguments=None,descriptor=None):
        descriptor = descriptor if descriptor is not None else self.descriptors[name]
        self.current_descriptor = self.descriptor_text(descriptor)
        arguments = ["$x"] if arguments is None else arguments
        args = ", ".join(["text^("+self.current_descriptor+")_text",*arguments])
        # Root-level O syntax is sequenced. End at the typed result rather than
        # introducing a final raw text node that would become the document value.
        source = "let x = text^(41)_text;\nlet x = ocore_i64("+args+");\ntext^($x)_text"
        path = self.case/"program.O"
        path.write_text(source)
        return path

    def inspect(self,source,env=None):
        result = run([self.olangc,source,"--target","ir"],env=env)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        (self.case/"inspection.txt").write_text(result.stdout)
        stores = [int(value) for value in re.findall(r"^node (\d+) store \$x$",result.stdout,re.M)]
        self.assertEqual(len(stores),2,result.stdout)
        for version,store in enumerate(stores,1):
            self.assertRegex(result.stdout,rf"ResourceState\(scope:x@{version}\) plan={store}\b")
        return stores,result.stdout

    def execute(self,source,success=True):
        env = os.environ.copy()
        env["O_LIFECYCLE_TRACE"] = str(self.case/"lifecycle.log")
        result = run([self.evaluator,"--json","--executor","graph","--workers","2",
                      source,ROOT/"backends"],env=env)
        (self.case/"stdout.json").write_text(result.stdout)
        (self.case/"stderr.txt").write_text(result.stderr)
        self.assertEqual(result.returncode==0,success,result.stdout+result.stderr)
        envelope = json.loads(result.stdout)
        self.assertEqual(envelope["ok"],success,envelope)
        return envelope

    def evidence(self,envelope):
        evidence = envelope["execution_evidence"]
        if envelope["ok"]:
            self.assertEqual(evidence["execution_mode"],"graph")
        self.assertIsNotNone(evidence["admission"])
        self.assertRegex(evidence["admission"]["admission_sha256"],r"^[0-9a-f]{64}$")
        trace = evidence["trace"]
        self.assertIsInstance(trace["events"],list)
        self.assertIsInstance(trace["publications"],list)
        return evidence,trace

    def versions(self,trace):
        return [(publication["plan_node"],output["version"])
                for publication in trace["publications"] for output in publication["outputs"]
                if output.get("kind")=="resource_state" and output.get("resource")=="scope:x"]

    def leaf(self,evidence,parameter_count):
        self.assertEqual(len(evidence["native_leaves"]),1)
        leaf = evidence["native_leaves"][0]
        self.assertEqual(leaf["profile"],"linux-elf-i64-acyclic-v1")
        self.assertEqual(leaf["descriptor_sha256"],hashlib.sha256(self.current_descriptor.encode()).hexdigest())
        self.assertEqual(leaf["parameter_count"],parameter_count)
        for key in ("module_sha256","assembly_sha256","executable_sha256","adapter_executable_sha256"):
            self.assertRegex(leaf[key],r"^[0-9a-f]{64}$",key)
        return leaf

    def assert_value(self,envelope,expected):
        self.assertEqual(envelope["value"]["t"],"text")
        self.assertEqual(envelope["value"]["v"]["utf8"],str(expected))

    def test_actual_owned_leaf_between_two_store_resource_versions(self):
        source = self.source()
        stores,_ = self.inspect(source)
        envelope = self.execute(source)
        self.assert_value(envelope,42)
        evidence,trace = self.evidence(envelope)
        leaf = self.leaf(evidence,1)
        self.assertEqual(self.versions(trace),[(stores[0],1),(stores[1],2)])
        finished = [event["plan_node"] for event in trace["events"] if event["event"]=="finished"]
        self.assertLess(finished.index(stores[0]),finished.index(leaf["plan_node"]))
        self.assertLess(finished.index(leaf["plan_node"]),finished.index(stores[1]))
        lifecycle = (self.case/"lifecycle.log").read_text()
        self.assertIn("event=native_leaf.executed",lifecycle)
        self.assertIn("executable="+leaf["executable_sha256"],lifecycle)
        self.assertIn("descriptor="+leaf["descriptor_sha256"],lifecycle)

    def test_zero_argument_and_stack_arguments_execute_original_entry(self):
        for name,values,expected in (("zero",[],42),("ten",list(range(1,11)),55)):
            with self.subTest(name=name):
                source = self.source(name,[f"text^({value})_text" for value in values])
                envelope = self.execute(source)
                self.assert_value(envelope,expected)
                evidence,trace = self.evidence(envelope)
                leaf = self.leaf(evidence,len(values))
                self.assertIn(leaf["plan_node"],[p["plan_node"] for p in trace["publications"]])
                self.assertEqual([v for _,v in self.versions(trace)],[1,2])

    def test_actual_native_trap_withholds_second_store_resource_successor(self):
        source = self.source("trap")
        stores,_ = self.inspect(source)
        envelope = self.execute(source,success=False)
        evidence,trace = self.evidence(envelope)
        leaf = self.leaf(evidence,1)
        self.assertEqual(self.versions(trace),[(stores[0],1)])
        self.assertIn(leaf["plan_node"],[e["plan_node"] for e in trace["events"] if e["event"]=="failed"])
        self.assertNotIn(stores[1],[p["plan_node"] for p in trace["publications"]])
        signal = r"(?:SIGTRAP|signal: 5\b)" if platform.machine() in {"aarch64","arm64"} else r"(?:SIGILL|signal: 4\b)"
        self.assertRegex(envelope["error"],signal,
                         "an actual owned Trap must terminate the child by signal, not a wrapper protocol failure")

    def test_noncanonical_or_out_of_range_arguments_do_not_publish_native_result(self):
        for value in ("041","+41","9223372036854775808"):
            with self.subTest(value=value):
                source = self.source(arguments=[f"text^({value})_text"])
                envelope = self.execute(source,success=False)
                evidence,trace = self.evidence(envelope)
                leaf = self.leaf(evidence,1)
                self.assertEqual([v for _,v in self.versions(trace)],[1])
                self.assertNotIn(leaf["plan_node"],[p["plan_node"] for p in trace["publications"]])

    def test_whole_original_impure_and_external_units_cannot_be_filtered_to_pure_entry(self):
        for name in ("impure","external"):
            with self.subTest(name=name):
                source = self.source(name)
                envelope = self.execute(source,success=False)
                evidence = envelope["execution_evidence"]
                self.assertFalse(evidence["native_leaves"])
                self.assertIsNone(evidence["trace"])
                self.assertIsNone(evidence["admission"])

    def test_descriptor_is_static_and_cannot_name_a_supplied_executable(self):
        descriptor = copy.deepcopy(self.descriptors["add"])
        descriptor["executable"] = str(self.evaluator)
        envelope = self.execute(self.source(descriptor=descriptor),success=False)
        self.assertFalse(envelope["execution_evidence"]["native_leaves"])
        dynamic = self.case/"dynamic.O"
        dynamic.write_text("let descriptor = text^("+self.descriptor_text(self.descriptors["add"])+")_text;\n"
                           "ocore_i64($descriptor,text^(41)_text)")
        envelope = self.execute(dynamic,success=False)
        self.assertFalse(envelope["execution_evidence"]["native_leaves"])

    def test_nonexecuting_ir_inspection_preserves_resources_without_spawning_native_tools(self):
        source = self.source()
        tools = self.case/"tools"
        tools.mkdir()
        marker = self.case/"unexpected-native-tool"
        for name in ("clang","cc","as","ld","ld.lld"):
            executable = tools/name
            executable.write_text("#!/bin/sh\nprintf called > '"+str(marker)+"'\nexit 91\n")
            executable.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(tools)+os.pathsep+env.get("PATH","")
        _,text = self.inspect(source,env=env)
        self.assertRegex(text,r"(?i)native[_ -]?i64")
        self.assertFalse(marker.exists(),"logical inspection must not assemble or link a native adapter")

    def test_genuine_cross_frontend_modules_cannot_execute_on_a_different_host_isa(self):
        host = {"AMD64":"x86_64","arm64":"aarch64"}.get(platform.machine(),platform.machine())
        for triple in baseline.TRIPLES:
            if triple.split("-")[0]==host:
                continue
            with self.subTest(triple=triple):
                llvm = self.case/(triple+".ll")
                result = run([self.sdk/"clang","--target="+triple,*FLAGS,
                              self.directory/"add.c","-o",llvm])
                self.assertEqual(result.returncode,0,result.stderr)
                module = importer.import_module(llvm,library_path=self.library,
                                                expected_sha256=self.library_sha256)
                self.assertEqual(module["target"]["triple"].split("-")[0],triple.split("-")[0])
                descriptor = {"schema":"ocore-native-i64-leaf-v1","entry":"native_add","module":module}
                envelope = self.execute(self.source(descriptor=descriptor),success=False)
                self.assertIn("host ISA",json.dumps(envelope))
                self.assertFalse(envelope["execution_evidence"]["native_leaves"])
                self.assertIsNone(envelope["execution_evidence"]["trace"])


if __name__=="__main__":
    unittest.main()
