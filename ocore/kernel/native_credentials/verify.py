#!/usr/bin/env python3
"""Real CPL3 credential getters across the existing native idle/TLS carrier.

Compose an owned fixture from the complete current idle fixture with explicit
single-occurrence edits, then reuse its unchanged build, two-rebuild, QMP and
HLT/state oracle. This is not original libc or a complete Linux provider.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "ocore/kernel/native_idle"


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("current native idle carrier changed at: " + before[:100])
    return text.replace(before, after)


def compose(inputs, deny_role):
    original_probe = (BASE/"probe.oc").read_text()
    probe = replace_once(original_probe, "use runtime::serial::write;", """use runtime::serial::write;
use runtime::linux_credentials::init as credentials_init;
use runtime::linux_credentials::admit as credentials_admit;
use runtime::linux_credentials::read_for as credentials_read;
use runtime::linux_credentials::dispatch as credentials_dispatch;""")
    probe = replace_once(probe, "const LINUX_TASK_STARTUP: bool = false;", """static mut CREDENTIAL_CALLS: [u64; 4] = [0; 4];
static CREDENTIAL_PREFIX: [u8; 20] = b"CREDENTIAL CALLS:   ";
const LINUX_TASK_STARTUP: bool = false;""")
    probe = replace_once(probe, "|| threads_init() != 1 || namespaces_init()", "|| threads_init() != 1 || credentials_init() != 1 || namespaces_init()")
    probe = replace_once(probe,
        "CONFIG[10] = 1000; CONFIG[11] = 1000; CONFIG[12] = 1000; CONFIG[13] = 1000; CONFIG[14] = 0;",
        "CONFIG[10] = 1000 + index as u64 * 10; CONFIG[11] = 2000 + index as u64 * 10; CONFIG[12] = 3000 + index as u64 * 10; CONFIG[13] = 4000 + index as u64 * 10; CONFIG[14] = 0;")
    anchor = "if OWNERS[index] == 0 || bind_process(namespace,OWNERS[index]) != 1 { fail(0x1e0 + index as u64); }"
    extra = f"""
        if index as u64 != {deny_role if deny_role >= 0 else 99} {{
            if credentials_admit(OWNERS[index],CONFIG[10],CONFIG[11],CONFIG[12],CONFIG[13]) != 1 {{ fail(0x500 + index as u64); }}
            let mut field: usize = 0;
            while field < 4 {{ if credentials_read(OWNERS[index],field) != CONFIG[10 + field] as i64 {{ fail(0x510 + field as u64); }} field += 1; }}
        }}"""
    probe = replace_once(probe, anchor, anchor+extra)
    probe = replace_once(probe, "if n == 24 { return request_yield(); }", """if n == 102 || n == 104 || n == 107 || n == 108 {
        CREDENTIAL_CALLS[index] += 1;
        return credentials_dispatch(n) as u64;
    }
    if n == 24 { return request_yield(); }""")
    probe = replace_once(probe, "EXITS[index] = status; return 1;", """if CREDENTIAL_CALLS[index] != 8 { fail(0x520 + index as u64); }
    write(&CREDENTIAL_PREFIX[0],20); number(CREDENTIAL_CALLS[index]);
    EXITS[index] = status; return 1;""")
    fixture = (BASE/"fixture.c").read_text()
    helper = r'''
static void check_credentials(U *sp){
 U *cursor=sp+4;while(*cursor)cursor++;cursor++;
 U observed[4]={~0UL,~0UL,~0UL,~0UL};
 for(;cursor[0];cursor+=2)if(cursor[0]>=11&&cursor[0]<=14)observed[cursor[0]-11]=cursor[1];
 const U number[4]={102,107,104,108};
 for(unsigned f=0;f<4;f++){
  U expected=1000UL*(f+1)+10UL*role;CHECK(observed[f]==expected);
  S result=sc(number[f],0,0,0,0);
  CHECK(result==((int)role==CREDENTIAL_DENY_ROLE?-3:(S)expected));
 }
}
'''
    fixture = replace_once(fixture, "void probe(U *sp){", f"#define CREDENTIAL_DENY_ROLE {deny_role}\n"+helper+"\nvoid probe(U *sp){")
    fixture = replace_once(fixture, "role=arg[0]-'0';", "role=arg[0]-'0';check_credentials(sp);")
    fixture = replace_once(fixture, "CHECK(!sc(CONTROL,3,0,0,0));", "check_credentials(sp);CHECK(!sc(CONTROL,3,0,0,0));")
    inputs.mkdir()
    (inputs/"probe.oc").write_text(probe)
    (inputs/"fixture.c").write_text(fixture)
    for name in ["platform.S", "scheduler_test_hooks.oc.inc"]:
        shutil.copyfile(BASE/name, inputs/name)
    for path in inputs.iterdir():
        path.chmod(0o444)
    return [identity(BASE/name) for name in ["probe.oc", "fixture.c", "platform.S", "scheduler_test_hooks.oc.inc", "verify.py"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--codec-manifest", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, default=Path.home()/".local/opt/qemu-11.1.3/bin/qemu-system-x86_64")
    parser.add_argument("--deny-role", type=int, default=-1, choices=range(-1,4))
    parser.add_argument("--credential-source", type=Path, help="Explicit captured private semantic mutation; never a guest-selectable input")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, out/"controller.py")
    (out/"controller.py").chmod(0o444)
    report = {"schema":"ostadix.native-linux-credential-cpl3/v1", "ok":False, "scope":__doc__,
              "deny_role":args.deny_role, "controller":identity(out/"controller.py")}
    before = None
    try:
        report["base_sources"] = compose(out/"inputs", args.deny_role)
        before = report["base_sources"]
        spec = importlib.util.spec_from_file_location("credential_idle_carrier", BASE/"verify.py")
        carrier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(carrier)
        carrier.HERE = out/"inputs"
        selected = args.credential_source.resolve() if args.credential_source else ROOT/"ocore/runtime/x86_64/linux_credentials.oc"
        report["credential_source"] = identity(selected)
        carrier.BASE.RUNTIME_NAMES = [*carrier.BASE.RUNTIME_NAMES, str(selected.with_suffix(""))]
        sys.argv = [str(BASE/"verify.py"), "--output", str(out/"carrier"), "--compiler", str(args.compiler),
                    "--codec-manifest", str(args.codec_manifest), "--qemu", str(args.qemu)]
        code = carrier.main()
        report["carrier_returncode"] = code
        report["carrier_result"] = identity(out/"carrier/result.json")
        if code:
            raise RuntimeError("actual credential carrier rejected; retained child result is authoritative")
        console = (out/"carrier/console.log").read_bytes()
        counts = re.findall(rb"CREDENTIAL CALLS:   ([0-9a-f]{16})\n",console)
        if counts != [b"0000000000000008"]*4:
            raise RuntimeError("missing four actual getter-count observations: "+repr(counts))
        report["credential_calls_per_retired_task"] = [int(c,16) for c in counts]
        report["guest_policy_values"] = [[1000*(field+1)+10*role for field in range(4)] for role in range(4)]
        report["base_sources_after"] = [identity(p["path"]) for p in before]
        report["base_source_stable"] = before == report["base_sources_after"]
        if not report["base_source_stable"]:
            raise RuntimeError("base carrier source changed")
        report["ok"] = True
    except Exception as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"ok":report["ok"], "result":str(out/"result.json"), "error":report.get("error")},indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
