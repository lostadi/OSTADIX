"""Real ordinary-.O AOT binaries using the shared owned native computation core.

One product compile retains its exact runtime project. Plain/trap product mains
come from genuine materialize-only invocations and become metadata-only extra
binary targets in that same project/cache. A separate observer projects public
Evaluator records; its evidence is never attributed to a product executable.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
import tomllib
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline


ROOT = Path(__file__).resolve().parents[1]
SDK_DEFAULT = Path.home() / ".local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin"
FLAGS = ["-O1", "-S", "-emit-llvm", "-ffreestanding", "-fno-builtin",
         "-fno-pic", "-fno-pie", "-fno-stack-protector", "-fno-vectorize",
         "-fno-slp-vectorize", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def engine_sources(directory):
    return {str(path.relative_to(directory)): sha(path)
            for path in sorted(directory.rglob("*.rs")) if path.name != "main.rs"}


OBSERVER = r'''
use __RUNTIME__::eval::{Evaluator, TraceEvent};
use __RUNTIME__::ir::{OIrProgram, PlanNodeKind};
use __RUNTIME__::parser::Parser;
use anyhow::Context;
use sha2::{Digest, Sha256};
fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn main() -> anyhow::Result<()> {
    let case = std::env::args().nth(1).context("observer requires a case")?;
    let source = match case.as_str() {
        "native" => include_str!(__NATIVE_SOURCE__),
        "trap" => include_str!(__TRAP_SOURCE__),
        _ => anyhow::bail!("unknown observer case"),
    };
    let registered = __RUNTIME__::ir::BackendRegistry::global().registered_backend_tags();
    let nodes = Parser::new(source, &registered).parse()?;
    let program = OIrProgram::lower(&nodes);
    let plan = program.plan();
    let mut evaluator = Evaluator::new(std::env::temp_dir()).with_registered_backends(registered);
    let mut scope = std::collections::HashMap::new();
    let outcome = evaluator.eval_ir_program_graph_with_scope(&program, &mut scope);
    let trace = evaluator.last_execution_trace().context("observer lacks actual trace")?;
    let admission = evaluator.last_execution_admission().context("observer lacks actual admission")?;
    let native: Vec<_> = plan.nodes.iter().filter_map(|node| match &node.kind {
        PlanNodeKind::NativeI64 { descriptor: Some(descriptor), .. } => Some(serde_json::json!({
            "plan_node":node.id.0,"descriptor_sha256":digest(descriptor.as_bytes())
        })),
        _ => None,
    }).collect();
    let stores: Vec<_> = plan.nodes.iter().filter_map(|node| match &node.kind {
        PlanNodeKind::Store { name } if name == "x" => Some(node.id.0),
        _ => None,
    }).collect();
    // This is an explicit projection of actual public events, not synthesized
    // events or the product main's private CLI observation implementation.
    let events: Vec<_> = trace.events.iter().filter_map(|event| match event {
        TraceEvent::NodeStarted(id) => Some(serde_json::json!({"event":"started","plan_node":id.0})),
        TraceEvent::NodeFinished { id, .. } => Some(serde_json::json!({"event":"finished","plan_node":id.0})),
        TraceEvent::NodeFailed { id, .. } => Some(serde_json::json!({"event":"failed","plan_node":id.0})),
        _ => None,
    }).collect();
    let bindings = admission.bindings();
    println!("{}", serde_json::json!({
        "schema":"ostadix.native-aot-test-companion/v1",
        "observation_scope":"separate companion against the exact generated runtime",
        "observer_executable_sha256":digest(&std::fs::read(std::env::current_exe()?)?),
        "source_sha256":digest(source.as_bytes()),
        "observed_program_success":outcome.is_ok(),
        "value":outcome.as_ref().ok().map(ToString::to_string),
        "error":outcome.as_ref().err().map(|error|format!("{error:#}")),
        "native_nodes":native,"stores":stores,"events":events,
        "publications":trace.publications,
        "admission_sha256":admission.admission_sha256(),
        "executable_manifest_sha256":bindings.executable_manifest_sha256,
        "native_leaves":admission.executable_manifest().native_leaves
    }));
    Ok(())
}
'''


class NativeHgraphAotTests(unittest.TestCase):
    @classmethod
    def command(cls, name, argv, *, cwd=None, env=None, success=True, timeout=7200):
        started = time.monotonic()
        result = subprocess.run([str(value) for value in argv], cwd=cwd,
                                env=cls.env if env is None else env,
                                capture_output=True, text=True, timeout=timeout)
        stdout = cls.directory / (name + ".stdout")
        stderr = cls.directory / (name + ".stderr")
        stdout.write_text(result.stdout)
        stderr.write_text(result.stderr)
        cls.proof["commands"].append({
            "name":name,"argv":[str(value) for value in argv],"cwd":str(cwd or Path.cwd()),
            "exit_code":result.returncode,"elapsed_seconds":round(time.monotonic()-started,3),
            "stdout":str(stdout),"stdout_sha256":sha(stdout),
            "stderr":str(stderr),"stderr_sha256":sha(stderr)})
        cls.save()
        if success and result.returncode:
            raise RuntimeError(f"{name} failed ({result.returncode}); {stderr}\n{result.stderr[-2500:]}")
        return result

    @classmethod
    def save(cls):
        (cls.directory / "proof.json").write_text(json.dumps(cls.proof,indent=2)+"\n")

    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64","aarch64","arm64","riscv64"}:
            raise unittest.SkipTest("actual native leaf AOT execution requires a supported Linux host")
        cls.olangc = Path(os.environ.get("OCORE_TEST_AOT_OLANGC", str(ROOT/"target/debug/olangc"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN",str(SDK_DEFAULT))).resolve()
        cls.cargo = Path(os.environ.get("OCORE_TEST_AOT_CARGO",str(Path.home()/".cargo/bin/cargo")))
        for executable in (cls.olangc,cls.sdk/"clang",cls.cargo):
            if not executable.is_file() or not os.access(executable,os.X_OK):
                raise unittest.SkipTest(f"actual compiler/frontend/Cargo required: {executable}")
        expected = os.environ.get("OCORE_TEST_AOT_OLANGC_SHA256")
        if expected and sha(cls.olangc) != expected:
            raise RuntimeError("AOT compiler is not the selected fresh binary")
        parent = os.environ.get("OCORE_TEST_AOT_OUTPUT_DIR")
        if parent:
            Path(parent).mkdir(parents=True,exist_ok=True)
        cls.directory = Path(tempfile.mkdtemp(prefix="native-hgraph-aot-",dir=parent)).resolve()
        cls.env = os.environ.copy()
        cls.env["PATH"] = str(cls.sdk)+os.pathsep+cls.env.get("PATH","")
        libraries = [cls.sdk.parent.parent/(platform.machine()+"-linux-gnu"),cls.sdk.parent/"lib"]
        search = [str(path) for path in libraries if path.is_dir()]
        if cls.env.get("LD_LIBRARY_PATH"):
            search.append(cls.env["LD_LIBRARY_PATH"])
        if search:
            cls.env["LD_LIBRARY_PATH"] = os.pathsep.join(search)
        profiles = {key:"0" for key in (
            "CARGO_PROFILE_DEV_OPT_LEVEL","CARGO_PROFILE_DEV_DEBUG",
            "CARGO_PROFILE_TEST_OPT_LEVEL","CARGO_PROFILE_TEST_DEBUG",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL","CARGO_PROFILE_RELEASE_DEBUG")}
        profiles.update({"CARGO_PROFILE_RELEASE_LTO":"false",
                         "CARGO_PROFILE_RELEASE_CODEGEN_UNITS":"16"})
        cls.env.update(profiles)
        cls.env.update({"CARGO":str(cls.cargo),"RUSTUP_TOOLCHAIN":"1.97.1",
                        "CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true","CARGO_BUILD_JOBS":"1"})
        cls.proof = {"schema":"ostadix.native-hgraph-aot-gate/v1","commands":[],"gates":{},
                     "compiler":str(cls.olangc),"compiler_sha256":sha(cls.olangc),
                     "profile_environment":profiles,"cargo_jobs":1,"runtime_complete":False}
        cls.save()
        rustc = os.environ.get("OCORE_TEST_AOT_RUSTC")
        if not rustc:
            rustup = os.environ.get("OCORE_TEST_AOT_RUSTUP",str(Path.home()/".cargo/bin/rustup"))
            resolved = cls.command("resolve-pinned-rustc",[rustup,"which","rustc","--toolchain","1.97.1"],timeout=120)
            rustc = resolved.stdout.strip()
        cls.env["RUSTC"] = str(Path(rustc).resolve())
        rust_version = cls.command("pinned-rustc-version",[cls.env["RUSTC"],"-vV"],timeout=120)
        cargo_version = cls.command("pinned-cargo-version",[cls.cargo,"+1.97.1","--version"],timeout=120)
        if not re.search(r"^release: 1\.97\.1$",rust_version.stdout,re.M) or not re.match(r"cargo 1\.97\.1(?:\s|$)",cargo_version.stdout):
            raise RuntimeError("generated-runtime builds require exact Cargo and rustc1.97.1")
        # Preserve explicitly configured compiler wrappers and bind their
        # selection; do not silently discard a caller's compiler requirements.
        cls.proof["compiler_environment"] = {name:cls.env.get(name) for name in (
            "RUSTC","RUSTUP_TOOLCHAIN","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER")}
        cls.proof["rustc_sha256"] = sha(cls.env["RUSTC"])
        cls.proof["cargo_version"] = cargo_version.stdout.strip()
        cls.proof["rustc_verbose_version"] = rust_version.stdout
        cls.save()
        version = cls.command("frontend-version",[cls.sdk/"clang","--version"],timeout=120)
        if not re.search(r"clang version 22\.1\.6(?:\s|$)",version.stdout):
            raise RuntimeError("exact Clang22.1.6 frontend required")
        library = baseline.llvm_library()
        library_sha = os.environ.get("OCORE_TEST_LLVM_SHA256",importer.PINNED_SHA256)
        if sha(library) != library_sha:
            raise RuntimeError("actual LLVM parser differs from selected digest")
        cls.proof["llvm_parser_sha256"] = library_sha
        resume = os.environ.get("OCORE_TEST_AOT_RESUME_PROOF")
        if resume:
            cls.reuse_build(Path(resume))
            cls.observe_products()
            return
        cls.descriptors = {}
        cls.proof["fixtures"] = []
        arch = {"arm64":"aarch64"}.get(platform.machine(),platform.machine())
        for name,entry,body in (
            ("native","native_add","long long native_add(long long x) { return x+1; }\n"),
            ("trap","native_trap","long long native_trap(long long x) { __builtin_trap(); }\n")):
            source = cls.directory/(name+".c")
            llvm = cls.directory/(name+".ll")
            source.write_text(body)
            cls.command(name+"-frontend",[cls.sdk/"clang","--target="+arch+"-unknown-linux-gnu",
                                        *FLAGS,source,"-o",llvm],timeout=120)
            module = importer.import_module(llvm,library_path=library,expected_sha256=library_sha)
            if len(module["functions"]) != module["provenance"]["source_function_count"]:
                raise RuntimeError("whole original fixture function inventory changed")
            descriptor = {"schema":"ocore-native-i64-leaf-v1","entry":entry,"module":module}
            cls.descriptors[name] = json.dumps(descriptor,separators=(",",":"))
            cls.proof["fixtures"].append({"name":name,"source_sha256":sha(source),"llvm_sha256":sha(llvm),
                                           "descriptor_sha256":text_sha(cls.descriptors[name]),
                                           "function_count":len(module["functions"]),"global_count":len(module["globals"])})
        native = "let x = text^(41)_text;\nlet x = ocore_i64(text^("+cls.descriptors["native"]+")_text, $x);\ntext^($x)_text"
        trap = "let x = text^(41)_text;\nlet x = ocore_i64(text^("+cls.descriptors["trap"]+")_text, $x);\nlet x = ocore_i64(text^("+cls.descriptors["native"]+")_text, $x);\ntext^($x)_text"
        cls.sources = {}
        for name,body in (("native",native),("plain","text^(ordinary-aot-ok)_text"),("trap",trap)):
            case = cls.directory/name
            case.mkdir()
            source = case/"program.O"
            source.write_text(body)
            cls.sources[name] = source
        cls.product = cls.directory/"program"
        built = cls.command("product-compile",[cls.olangc,cls.sources["native"],"--target","binary",
                                               "-o",cls.product,"--keep-build-dir"])
        found = re.findall(r"^olangc: keeping build directory: (.+)$",built.stderr,re.M)
        if len(found) != 1:
            raise RuntimeError("actual product compile did not retain one generated project")
        cls.project = Path(found[0]).resolve()
        cls.target = cls.project/"target"
        if cls.product.read_bytes()[:4] != b"\x7fELF":
            raise RuntimeError("actual olangc binary product is not ELF")
        cls.engine = engine_sources(cls.project/"src")
        core = {"native_leaf.rs":ROOT/"crates/ostadix-api/src/native_leaf.rs",
                "native_leaf_identity.rs":ROOT/"crates/ostadix-api/src/native_leaf_identity.rs",
                "lifecycle_trace.rs":ROOT/"crates/ostadix-api/src/lifecycle_trace.rs",
                "ocore/mod.rs":ROOT/"crates/ostadix-api/src/ocore/native_core.rs"}
        for name in ("common","native_ir","native_verify","native_abi","native_codegen","native_map",
                     "native_eh","native_exception_codegen","native_atomic_codegen","native_float_layout"):
            core["ocore/"+name+".rs"] = ROOT/"crates/ostadix-api/src/ocore"/(name+".rs")
        for relative,source in core.items():
            if (cls.project/"src"/relative).read_bytes() != source.read_bytes():
                raise RuntimeError(f"generated native computation core differs from engine: {relative}")
        cls.proof.update({"product_sha256":sha(cls.product),"generated_project":str(cls.project),
                          "shared_cargo_target":str(cls.target),"engine_source_sha256":cls.engine,
                          "owned_native_source_sha256":{name:sha(path) for name,path in core.items()}})
        materialized = {}
        for name in ("plain","trap"):
            destination = cls.directory/(name+"-generated")
            cls.command(name+"-materialize",[cls.olangc,cls.sources[name],"--target","binary",
                                            "-o",cls.directory/name/"program","--materialize-only",destination],timeout=120)
            if engine_sources(destination/"src") != cls.engine:
                raise RuntimeError("real generated mains must share byte-identical runtime sources")
            materialized[name] = destination
        manifest_path = cls.project/"Cargo.toml"
        original_manifest = manifest_path.read_text()
        metadata = tomllib.loads(original_manifest)
        lib_name = metadata["lib"]["name"]
        for name,directory in materialized.items():
            if tomllib.loads((directory/"Cargo.toml").read_text())["lib"]["name"] != lib_name:
                raise RuntimeError("real emitted main library identity differs from the retained runtime")
        observer = cls.directory/"graph-observer.rs"
        observer.write_text(OBSERVER.replace("__RUNTIME__",lib_name)
                            .replace("__NATIVE_SOURCE__",json.dumps(str(cls.sources["native"])))
                            .replace("__TRAP_SOURCE__",json.dumps(str(cls.sources["trap"]))))
        extra = ""
        targets = {"plain_aot":materialized["plain"]/"src/main.rs",
                   "trap_aot":materialized["trap"]/"src/main.rs","graph_observer":observer}
        for name,path in targets.items():
            extra += "\n[[bin]]\nname = "+json.dumps(name)+"\npath = "+json.dumps(str(path))+"\n"
        manifest_path.write_text(original_manifest+extra)
        lock_sha = sha(cls.project/"Cargo.lock")
        cls.proof["extra_targets"] = {name:{"path":str(path),"sha256":sha(path)} for name,path in targets.items()}
        cls.proof["cargo_manifest_original_sha256"] = text_sha(original_manifest)
        cls.proof["cargo_manifest_extra_bins_sha256"] = sha(manifest_path)
        cls.command("extra-generated-mains-build",[cls.cargo,"+1.97.1","build","--offline","--locked",
                    "--release","--jobs","1","--manifest-path",manifest_path,"--target-dir",cls.target,
                    "--bin","plain_aot","--bin","trap_aot","--bin","graph_observer"],cwd=cls.project)
        if sha(cls.project/"Cargo.lock") != lock_sha or engine_sources(cls.project/"src") != cls.engine:
            raise RuntimeError("extra metadata-only targets changed the generated engine or dependency lock")
        cls.proof["cargo_lock_sha256"] = lock_sha
        cls.proof["product_main_sha256"] = sha(cls.project/"src/main.rs")
        cls.products = {"native":cls.product,"plain":cls.target/"release/plain_aot",
                        "trap":cls.target/"release/trap_aot","observer":cls.target/"release/graph_observer"}
        cls.proof["executable_sha256"] = {name:sha(path) for name,path in cls.products.items()}
        cls.observe_products()

    @classmethod
    def reuse_build(cls, proof_path):
        # Reuse is explicit and content-bound. This branch never presents the
        # retained compile as a new compile; all observations below run afresh.
        proof_path = proof_path.resolve()
        expected = os.environ.get("OCORE_TEST_AOT_RESUME_SHA256")
        if not expected or sha(proof_path) != expected:
            raise RuntimeError("resume requires the exact original compile-proof digest")
        previous = json.loads(proof_path.read_text())
        if previous.get("schema") != "ostadix.native-hgraph-aot-gate/v1":
            raise RuntimeError("unrecognized retained compile proof")
        for name in ("product-compile","extra-generated-mains-build"):
            records = [item for item in previous["commands"] if item["name"] == name]
            if len(records) != 1 or records[0]["exit_code"] != 0:
                raise RuntimeError("retained proof lacks one successful actual "+name)
        for item in previous["commands"]:
            for stream in ("stdout","stderr"):
                if sha(item[stream]) != item[stream+"_sha256"]:
                    raise RuntimeError("retained command evidence changed")
        for key in ("compiler_sha256","profile_environment","compiler_environment",
                    "rustc_sha256","cargo_version","rustc_verbose_version","llvm_parser_sha256"):
            if cls.proof[key] != previous[key]:
                raise RuntimeError("retained build selection changed: "+key)
        old = proof_path.parent
        cls.project = Path(previous["generated_project"])
        cls.target = Path(previous["shared_cargo_target"])
        if cls.target != cls.project/"target":
            raise RuntimeError("retained generated target no longer belongs to its project")
        cls.engine = previous["engine_source_sha256"]
        if engine_sources(cls.project/"src") != cls.engine:
            raise RuntimeError("retained generated runtime changed")
        checks = {cls.project/"Cargo.toml":previous["cargo_manifest_extra_bins_sha256"],
                  cls.project/"Cargo.lock":previous["cargo_lock_sha256"],
                  cls.project/"src/main.rs":previous["product_main_sha256"]}
        for target in previous["extra_targets"].values():
            checks[Path(target["path"])] = target["sha256"]
        for path,digest in checks.items():
            if sha(path) != digest:
                raise RuntimeError("retained generated main/manifest/lock changed: "+str(path))
        for relative,digest in previous["owned_native_source_sha256"].items():
            source = ROOT/"crates/ostadix-api/src"/relative
            if relative == "ocore/mod.rs":
                source = source.with_name("native_core.rs")
            if sha(source) != digest or sha(cls.project/"src"/relative) != digest:
                raise RuntimeError("retained native core differs from current source: "+relative)
        cls.sources = {name:old/name/"program.O" for name in ("native","plain","trap")}
        for name,source in cls.sources.items():
            generated = cls.project if name == "native" else old/(name+"-generated")
            if sha(source) != previous["product_runs"][name]["source_sha256"]:
                raise RuntimeError("retained original .O input changed")
            if (generated/"src/program.O").read_bytes() != source.read_bytes():
                raise RuntimeError("retained include_str program bytes changed")
            if engine_sources(generated/"src") != cls.engine:
                raise RuntimeError("retained materialized runtime changed")
        cls.descriptors = {}
        prefix = "let x = text^(41)_text;\nlet x = ocore_i64(text^("
        for fixture in previous["fixtures"]:
            name = fixture["name"]
            if sha(old/(name+".c")) != fixture["source_sha256"] or sha(old/(name+".ll")) != fixture["llvm_sha256"]:
                raise RuntimeError("retained original frontend input/output changed")
            text = cls.sources[name].read_text()
            if not text.startswith(prefix):
                raise RuntimeError("retained original descriptor source changed")
            descriptor,end = json.JSONDecoder().raw_decode(text[len(prefix):])
            raw = text[len(prefix):len(prefix)+end]
            if text_sha(raw) != fixture["descriptor_sha256"]:
                raise RuntimeError("retained original descriptor changed")
            module = descriptor["module"]
            if (module["provenance"]["input_sha256"] != fixture["llvm_sha256"]
                or len(module["functions"]) != fixture["function_count"]
                or len(module["globals"]) != fixture["global_count"]):
                raise RuntimeError("retained whole-unit descriptor inventory changed")
            cls.descriptors[name] = raw
        cls.product = old/"program"
        cls.products = {"native":cls.product,"plain":cls.target/"release/plain_aot",
                        "trap":cls.target/"release/trap_aot","observer":cls.target/"release/graph_observer"}
        if sha(cls.product) != previous["product_sha256"]:
            raise RuntimeError("retained actual product executable changed")
        for name,path in cls.products.items():
            if sha(path) != previous["executable_sha256"][name]:
                raise RuntimeError("retained executable changed: "+name)
        # The current observer template must match the genuinely compiled one.
        lib_name = tomllib.loads((cls.project/"Cargo.toml").read_text())["lib"]["name"]
        observer = OBSERVER.replace("__RUNTIME__",lib_name)\
            .replace("__NATIVE_SOURCE__",json.dumps(str(cls.sources["native"])))\
            .replace("__TRAP_SOURCE__",json.dumps(str(cls.sources["trap"])))
        if Path(previous["extra_targets"]["graph_observer"]["path"]).read_text() != observer:
            raise RuntimeError("retained compiled observer differs from the current test")
        retained_keys = ("generated_project","shared_cargo_target","engine_source_sha256",
                         "owned_native_source_sha256","product_sha256","extra_targets",
                         "cargo_manifest_original_sha256","cargo_manifest_extra_bins_sha256",
                         "cargo_lock_sha256","product_main_sha256","executable_sha256","fixtures")
        cls.proof.update({key:previous[key] for key in retained_keys})
        cls.proof["retained_compile_evidence"] = {"proof":str(proof_path),"sha256":expected,
            "new_compile_performed":False,"original_case_directory":str(old)}
        cls.save()

    @classmethod
    def observe_products(cls):
        cls.runs = {}
        for name in ("native","plain","trap"):
            working = cls.directory/(name+"-run")
            working.mkdir()
            env = cls.env.copy()
            trace = working/"lifecycle.log"
            env["O_LIFECYCLE_TRACE"] = str(trace)
            result = cls.command(name+"-product-run",[cls.products[name]],cwd=working,env=env,
                                 success=name!="trap",timeout=120)
            records = trace.read_text().splitlines() if trace.exists() else []
            prepared = [json.loads(line.split("event=native_leaf.prepared ",1)[1])
                        for line in records if "event=native_leaf.prepared " in line]
            executed = [line for line in records if "event=native_leaf.executed " in line]
            cls.runs[name] = (result,prepared,executed)
            cls.proof.setdefault("product_runs",{})[name] = {"executable_sha256":sha(cls.products[name]),
                "source_sha256":sha(cls.sources[name]),"prepared":prepared,"executed":executed,
                "lifecycle":str(trace),"exit_code":result.returncode}
        cls.observations = {}
        for name in ("native","trap"):
            result = cls.command(name+"-companion-observation",[cls.products["observer"],name],timeout=120)
            cls.observations[name] = json.loads(result.stdout)
        cls.proof["separate_companion_observations"] = cls.observations
        cls.save()

    def test_01_actual_binary_product_binds_its_own_native_execution(self):
        result,prepared,executed = self.runs["native"]
        self.assertEqual(result.stdout,"42")
        self.assertEqual(len(prepared),1)
        self.assertEqual(len(executed),1)
        leaf = prepared[0]
        self.assertEqual(leaf["profile"],"linux-elf-i64-acyclic-v1")
        self.assertEqual(leaf["adapter_executable_sha256"],sha(self.product))
        self.assertEqual(leaf["descriptor_sha256"],text_sha(self.descriptors["native"]))
        self.assertIn("descriptor="+leaf["descriptor_sha256"],executed[0])
        self.assertIn("executable="+leaf["executable_sha256"],executed[0])
        self.assertNotEqual(sha(self.product),sha(self.olangc))
        self.assertEqual(engine_sources(self.project/"src"),self.engine)
        self.proof["gates"]["actual_native_product"] = True
        self.save()

    def test_02_plain_emitted_main_reuses_the_exact_generated_runtime(self):
        result,prepared,executed = self.runs["plain"]
        self.assertEqual(result.stdout,"ordinary-aot-ok")
        self.assertEqual((prepared,executed),([],[]))
        self.assertEqual(engine_sources(self.project/"src"),self.engine)
        self.proof["gates"]["ordinary_non_native_product_main"] = True
        self.save()

    def test_03_trap_product_and_separate_companion_withhold_successors(self):
        result,prepared,executed = self.runs["trap"]
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,"")
        self.assertIn("native scalar leaf failed",result.stderr)
        self.assertEqual(len(prepared),2)
        self.assertEqual(executed,[])
        for leaf in prepared:
            self.assertEqual(leaf["adapter_executable_sha256"],sha(self.products["trap"]))
        normal = self.observations["native"]
        failed = self.observations["trap"]
        for name,observation in self.observations.items():
            self.assertEqual(observation["observer_executable_sha256"],sha(self.products["observer"]))
            self.assertEqual(observation["source_sha256"],sha(self.sources[name]))
            self.assertEqual(observation["observation_scope"],"separate companion against the exact generated runtime")
            for leaf in observation["native_leaves"]:
                self.assertEqual(leaf["adapter_executable_sha256"],sha(self.products["observer"]))
        self.assertTrue(normal["observed_program_success"])
        self.assertEqual(normal["value"],json.dumps("42"))
        versions = lambda observation: [output["version"] for publication in observation["publications"]
                    for output in publication["outputs"] if output.get("kind")=="resource_state"
                    and output.get("resource")=="scope:x"]
        self.assertEqual(versions(normal),[1,2])
        self.assertFalse(failed["observed_program_success"])
        self.assertEqual(versions(failed),[1])
        self.assertEqual(len(failed["stores"]),3)
        trap = next(node["plan_node"] for node in failed["native_nodes"]
                    if node["descriptor_sha256"]==text_sha(self.descriptors["trap"]))
        successor = next(node["plan_node"] for node in failed["native_nodes"]
                         if node["descriptor_sha256"]==text_sha(self.descriptors["native"]))
        self.assertIn({"event":"failed","plan_node":trap},failed["events"])
        self.assertNotIn({"event":"started","plan_node":successor},failed["events"])
        blocked = {trap,successor,*failed["stores"][1:]}
        self.assertFalse(any(publication["plan_node"] in blocked for publication in failed["publications"]))
        self.proof["gates"]["trap_product_and_separately_observed_graph"] = True
        self.save()


if __name__ == "__main__":
    unittest.main()
