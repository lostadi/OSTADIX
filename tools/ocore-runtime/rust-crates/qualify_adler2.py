#!/usr/bin/env python3
"""Execute one original Adler-32 Rust API against whole original/owned RV64 objects.

The C carrier and return-normalizing RV64 veneer are test infrastructure. They
are identical for both object sets; no Rust source, CGU or native module is edited.
This qualifies the pinned emitted slice API, not a stable Rust FFI or full runtime.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts import ocore_runtime_capture as capture


def info(path):
    path = Path(path).resolve()
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(raw)
            size += len(raw)
    return {"path":str(path), "bytes":size, "sha256":digest.hexdigest()}


def checked(artifact):
    actual = info(artifact["path"])
    if any(actual[key] != artifact[key] for key in ("path", "bytes", "sha256")):
        raise ValueError("bound artifact changed: " + artifact["path"])
    return Path(artifact["path"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("audit", type=Path)
    parser.add_argument("--ocorec", type=Path, default=Path.home()/".local/bin/ocorec")
    parser.add_argument("--llvm-library", type=Path, required=True)
    parser.add_argument("--llvm-sha256", required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--llvm-nm", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {"schema":"ocore-original-rust-api-qualification-v1", "complete":False,
              "scope":"pinned original adler2::adler32_slice on Linux RV64 LP64D",
              "commands":[], "fresh_owned_units":[], "runtime_complete":False, "native_execution_qualified":False,
              "full_rust_compiler_complete":False, "native_ostadix_platform_qualified":False}

    def save():
        (output / "report.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command):
        start = time.monotonic()
        result = subprocess.run(list(map(str, command)), capture_output=True, cwd=output, timeout=120)
        stdout, stderr = output/(name+".stdout"), output/(name+".stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        record["commands"].append({"name":name, "argv":list(map(str, command)), "cwd":str(output),
            "exit_code":result.returncode, "seconds":round(time.monotonic()-start, 6),
            "stdout":info(stdout), "stderr":info(stderr)})
        save()
        if result.returncode:
            raise ValueError(name + " failed: " + result.stderr.decode(errors="replace")[-1500:])
        return result.stdout

    save()
    try:
        if platform.system() != "Linux" or platform.machine() != "riscv64":
            raise ValueError("this explicit API carrier requires the actual Linux RV64 host")
        original = json.loads(args.capture.read_text())
        audit = json.loads(args.audit.read_text())
        if not original.get("capture_complete") or capture.make_report(args.capture.resolve().parent, persist=False) != original:
            raise ValueError("original source capture did not independently re-admit")
        ids = set(original["lowering_unit_ids"])
        audited = {unit["id"]:unit for unit in audit["units"]}
        if (not audit.get("audit_complete") or set(audited) != ids or len(audited) != len(audit["units"])
                or any(unit["status"] != "verified-object" for unit in audited.values())):
            raise ValueError("every original configured-library CGU must have a verified owned object")
        if audit["source_capture"] != info(args.capture):
            raise ValueError("whole-unit audit belongs to different source capture bytes")
        inputs = [info(args.capture), info(args.audit), info(args.clang), info(args.llvm_nm)]
        if not re.fullmatch(r"[0-9a-f]{64}", args.llvm_sha256):
            raise ValueError("an exact lowercase LLVM parser SHA-256 is required")
        library = info(args.llvm_library)
        if library["sha256"] != args.llvm_sha256:
            raise ValueError("selected LLVM parser library SHA-256 mismatch")
        compiler = info(args.ocorec)
        if not os.access(compiler["path"], os.X_OK):
            raise ValueError("selected trusted ocorec is not executable")
        tools = output / "tools"
        tools.mkdir()
        frozen_compiler = tools / "ocorec"
        shutil.copy2(compiler["path"], frozen_compiler)
        if info(frozen_compiler)["sha256"] != compiler["sha256"] or info(args.ocorec) != compiler:
            raise ValueError("trusted ocorec changed while freezing its executable")
        compiler_snapshot = info(frozen_compiler)
        record.update(trusted_ocorec={**compiler, "snapshot":compiler_snapshot}, llvm_library=library)
        inputs.extend([compiler, compiler_snapshot, library])
        originals, owned, candidates = [], [], []
        for event in original["invocations"]:
            for unit in event.get("units", []):
                if unit["id"] not in ids:
                    continue
                native = event["saved_cgus"][unit["saved_cgu_index"]]["object"]
                originals.append(checked(native))
                result = audited[unit["id"]]
                checked(result["object"])
                checked(result["module"])
                checked(result["verification"])
                raw_input = checked(unit["ir"])
                index = len(record["fresh_owned_units"])
                fresh = output / ("owned-cgu-" + str(index))
                fresh.mkdir()
                module_path, verification_path, object_path = fresh/"module.json", fresh/"verification.json", fresh/"module.o"
                flags = ["--llvm-library", library["path"], "--llvm-sha256", library["sha256"]]
                run(f"cgu-{index}-import", [frozen_compiler, raw_input, "--input-kind", "llvm-ir", "--emit", "mir",
                                          "--target", "riscv64-unknown-none", "-o", module_path, *flags])
                fresh_module = info(module_path)
                if fresh_module["sha256"] != result["module"]["sha256"]:
                    raise ValueError("fresh original-bitcode import differs from the claimed audit module")
                run(f"cgu-{index}-verify", [frozen_compiler, module_path, "--input-kind", "native-ir",
                                          "--verify-native", "--receipt", verification_path])
                verification = json.loads(verification_path.read_text())
                module = json.loads(module_path.read_text())
                if not verification.get("verified") or verification["module_sha256"] != fresh_module["sha256"]:
                    raise ValueError("fresh independent verification is not module-bound")
                run(f"cgu-{index}-object", [frozen_compiler, module_path, "--input-kind", "native-ir", "--emit", "obj",
                                          "--target", "riscv64-unknown-none", "-o", object_path])
                fresh_object = info(object_path)
                fresh_record = {"unit_id":unit["id"], "original_bitcode":info(raw_input), "module":fresh_module,
                                "verification":info(verification_path), "object":fresh_object}
                record["fresh_owned_units"].append(fresh_record)
                save()
                if fresh_object["sha256"] != result["object"]["sha256"]:
                    raise ValueError("fresh owned object differs from the claimed audit object")
                owned.append(object_path)
                inputs.extend([fresh_module, fresh_record["verification"], fresh_object])
                if module["provenance"]["input_sha256"] != unit["ir"]["sha256"]:
                    raise ValueError("module is not bound to the whole original bitcode input")
                target = module["target"]
                if (target["triple"] != "riscv64-unknown-linux-gnu" or target["abi"] != "lp64d"
                        or target["pointer_bits"] != 64 or target["little_endian"] is not True):
                    raise ValueError("original target does not match the explicit carrier ABI")
                for function in module["functions"]:
                    if function["entry"] is not None and function["name"].endswith("6adler213adler32_slice"):
                        candidates.append((function, module["types"]))
                inputs.extend([native, result["object"], result["module"], result["verification"], unit["ir"]])
        if len(candidates) != 1:
            raise ValueError("the entire unit set must provide exactly one original slice API")
        function, types = candidates[0]
        signature = function["signature"]
        if (signature["abi"] != "c" or signature["variadic"] or signature.get("return_storage") is not None
                or [types[i] for i in signature["params"]] != [{"kind":"pointer", "address_space":0}, {"kind":"int", "bits":64}]
                or types[signature["result"]] != {"kind":"int", "bits":32}
                or signature["param_attributes"] != [[], []] or signature["result_attributes"] != []):
            raise ValueError("observed LLVM slice ABI is outside the exact pointer,length/bare-i32 profile")
        symbol = function["name"]
        if not re.fullmatch(r"_R[A-Za-z0-9_]+", symbol):
            raise ValueError("unexpected original Rust symbol spelling")
        record.update(capture=info(args.capture), whole_unit_audit=info(args.audit), original_objects=list(map(info, originals)),
                      owned_objects=list(map(info, owned)), observed_api={"symbol":symbol, "signature":signature},
                      clang=info(args.clang), llvm_nm=info(args.llvm_nm), whole_cgu_count=len(ids))
        if len(owned) != len(ids):
            raise ValueError("not every original CGU received fresh owned native generation")
        for label, objects in (("original", originals), ("owned", owned)):
            raw = run(label+"-undefined-symbols", [args.llvm_nm, "--undefined-only", *objects])
            # llvm-nm prefixes filenames for multiple objects; inspect one at a
            # time so a header cannot be mistaken for an unresolved provider.
            if len(objects) == 1 and raw.strip():
                raise ValueError(label + " object set has unresolved providers")
            if len(objects) != 1:
                for index, object_ in enumerate(objects):
                    if run(label+"-undefined-"+str(index), [args.llvm_nm, "--undefined-only", object_]).strip():
                        raise ValueError(label + " CGU has unresolved providers")
        cases = [("empty",0,0), ("byte-range",256,0), ("single-zero",1,2), ("single-ff",1,3),
                 ("before-block",5551,1), ("exact-block",5552,1), ("after-block",5553,1),
                 ("two-block-before",11103,1), ("two-block",11104,1), ("two-block-after",11105,1),
                 ("max-byte-block",5552,3), ("long-deterministic",1048576,1)]
        vectors = []
        for name, length, mode in cases:
            state = 0x12345678
            payload = bytearray(length)
            for index in range(length):
                state ^= (state << 13) & 0xffffffff
                state ^= state >> 17
                state ^= (state << 5) & 0xffffffff
                payload[index] = (index & 255) if mode == 0 else (state & 255) if mode == 1 else 0 if mode == 2 else 255
            vectors.append({"name":name, "bytes":length, "mode":mode, "payload_sha256":hashlib.sha256(payload).hexdigest(),
                            "expected_adler32":zlib.adler32(payload) & 0xffffffff})
        carrier = output / "carrier.c"
        entries = ",\n".join('{"%s",%d,%d}' % (name,length,mode) for name,length,mode in cases)
        carrier.write_text('''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
extern uint32_t rust_slice(const unsigned char*,size_t) __asm__("ocore_test_adler32_slice");
static unsigned char payload[1048576];
static const struct { const char *name; size_t len; unsigned mode; } cases[]={
''' + entries + '''};
int main(void){
 for(size_t c=0;c<sizeof(cases)/sizeof(cases[0]);++c){
  uint32_t state=0x12345678u,s1=1,s2=0;
  for(size_t i=0;i<cases[c].len;++i){
   state^=state<<13;state^=state>>17;state^=state<<5;
   payload[i]=cases[c].mode==0?(unsigned char)i:cases[c].mode==1?(unsigned char)state:cases[c].mode==2?0:255;
   s1=(s1+payload[i])%65521u;s2=(s2+s1)%65521u;
  }
  uint32_t got=rust_slice(payload,cases[c].len),expected=(s2<<16)|s1;
  if(got!=expected){fprintf(stderr,"%s checksum mismatch %08x/%08x\\n",cases[c].name,(unsigned)got,(unsigned)expected);return 1;}
  printf("%s %zu %08x\\n",cases[c].name,cases[c].len,(unsigned)got);
 }
 return 0;
}
''')
        veneer = output / "slice-abi.S"
        veneer.write_text('''.text
.globl ocore_test_adler32_slice
.type ocore_test_adler32_slice,@function
ocore_test_adler32_slice:
 addi sp,sp,-16
 sd ra,8(sp)
 call ''' + symbol + '''
 ld ra,8(sp)
 addi sp,sp,16
 # Supply the C LP64D narrow-return extension; the original Rust i32 ABI
 # promises only the low32 result bits. Original code is never rewritten.
 sext.w a0,a0
 ret
.size ocore_test_adler32_slice,.-ocore_test_adler32_slice
.section .note.GNU-stack,"",@progbits
''')
        record.update(carrier=info(carrier), abi_veneer=info(veneer), vectors=vectors,
                      abi_boundary="RV64 a0/a1 forward pointer/length; low32 return normalized with sext.w to C LP64D")
        flags = ["--target=riscv64-unknown-linux-gnu", "-march=rv64gc", "-mabi=lp64d", "-O1", "-fno-builtin", "-fno-pie", "-no-pie"]
        expected_text = "".join('%s %d %08x\n' % (v['name'],v['bytes'],v['expected_adler32']) for v in vectors).encode()
        executables = {}
        for label, objects in (("original", originals), ("owned", owned)):
            executable = output / (label+"-api")
            run(label+"-link", [args.clang, *flags, carrier, veneer, *objects, "-o", executable])
            if run(label+"-execute", [executable]) != expected_text:
                raise ValueError(label + " results disagree with independent Python zlib and C modular controls")
            executables[label] = info(executable)
        for artifact in inputs:
            checked(artifact)
        record.update(complete=True, success=True, api_native_execution_qualified=True, case_count=len(vectors),
                      executables=executables, input_artifacts_unchanged=True,
                      harness_dependencies="same hosted C carrier/libc for reference and owned objects; no complete platform closure claimed")
        save()
        print(json.dumps({"report":str(output/'report.json'), "success":True, "cases":len(vectors), "whole_cgus":len(ids)}))
        return 0
    except Exception as error:
        record.update(complete=True, success=False, error=str(error))
        save()
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
