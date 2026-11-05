#!/usr/bin/env python3
"""Boot one exact X12 development ISO in a new private OVMF/QEMU TCG guest.

The serial menu entry is selected through its declared GRUB hotkey. All state
is the ISO's RAM copy. No existing console/state, host filesystem share, or
physical disk is attached. Root-only mode qualifies carrier startup, not the
unified console. Full mode checks shared files, original Linux compilation,
typed exit, return to the host menu and clean outer poweroff.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time

HOST_MENU = b"[r] resume  [p] power off  [n] networking  [s] host diagnostic shell:"


def identity(path):
    path = Path(path); value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""): value.update(block)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": value.hexdigest()}


def terminal_text(data):
    data = re.sub(rb"\x1b\][^\x07]*(?:\x07|\x1b\\)", b"", data)
    data = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
    data = re.sub(rb"\x1b[()][A-Z0-9]|\x1b[=>]", b"", data)
    return data.replace(b"\r", b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd"))
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--memory-mib", type=int, default=8192)
    parser.add_argument("--root-only", action="store_true")
    parser.add_argument("--network-test", action="store_true")
    parser.add_argument("--virtual-time", action="store_true",
                        help="single-vCPU deterministic instruction clock for nested functional checks; not performance")
    parser.add_argument("--slow-timeout", type=int, choices=(900,),
                        help="after a retained default startup failure, validate the unchanged runner with explicit900s caller budget")
    args = parser.parse_args()
    output = args.output.absolute(); output.mkdir(mode=0o700, parents=True, exist_ok=False)
    iso = args.iso.resolve(strict=True); qemu = Path(shutil.which(args.qemu) or args.qemu).resolve(strict=True)
    before = identity(iso)
    record = {"schema": "ostadix.okernel-x12-iso-qemu/v1", "ok": False,
              "started_unix_seconds": time.time(), "iso": before, "firmware": identity(args.firmware),
              "qemu": identity(qemu), "verifier": identity(Path(__file__).resolve()),
              "scope": __doc__, "root_only": args.root_only, "network_test": args.network_test,
              "virtual_time": args.virtual_time,
              "clock_profile": "fixed instruction clock; functional evidence only" if args.virtual_time else "ordinary TCG wall-clock profile",
              "slow_validation_timeout_seconds": args.slow_timeout,
              "default_nested_startup_qualified": False,
              "selected_profile_startup_qualified": False,
              "events": [], "existing_vm_actions": [], "physical_hardware_qualified": False,
              "native_driver_lowering": False, "efficiency_qualified": False}
    (output / "verifier.py").write_bytes(Path(__file__).read_bytes())
    capture = bytearray(); process = None; control = None; stream = None
    started = time.monotonic(); sequence = 0; token = secrets.token_hex(10)
    stage = "menu"; initial_network_sent = False; stage_start = 0
    expected_shared = ("OKERNEL_ISO_SHARED_" + token).encode() + b"\x00\xff\x11\x13\n"
    shared_digest = hashlib.sha256(expected_shared).hexdigest()
    record["expected_shared_file"] = {"bytes": len(expected_shared), "sha256": shared_digest}
    failure_seen = None
    failure_scan_after = 0
    failure_scope_start = 0
    failed_stage = None
    slow_launched = False
    slow_start = 0
    def event(name, **fields):
        record["events"].append({"event": name, "seconds": time.monotonic() - started, **fields})
        print("ISO check: " + name, flush=True)
    def qmp(command, arguments=None):
        nonlocal sequence
        sequence += 1
        stream.write((json.dumps({"execute": command, "arguments": arguments or {}, "id": sequence}) + "\n").encode())
        while True:
            line = stream.readline()
            if not line: raise RuntimeError("outer QMP closed")
            reply = json.loads(line)
            if reply.get("id") == sequence:
                if "error" in reply: raise RuntimeError(str(reply["error"]))
                return reply.get("return")
    def send(data):
        process.stdin.write(data); process.stdin.flush()
        record.setdefault("inputs", []).append({"seconds": time.monotonic()-started,
                                                 "bytes_hex": data.hex(), "stage": stage})
    def interrupted(signum, frame): raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="okx12.", dir="/tmp") as private:
            socket_path = Path(private) / "q"
            command = [str(qemu), "-machine", "q35", "-accel", "tcg,thread=multi", "-cpu", "max",
                       "-smp", "2", "-m", str(args.memory_mib), "-drive",
                       "if=pflash,format=raw,readonly=on,file=" + str(args.firmware).replace(",", ",,"),
                       "-drive", "if=none,id=live,format=raw,media=cdrom,readonly=on,file=" + str(iso).replace(",", ",,"),
                       "-device", "ide-cd,drive=live", "-boot", "order=d", "-display", "none",
                       "-device", "virtio-rng-pci", "-serial", "stdio", "-monitor", "none",
                       "-qmp", "unix:" + str(socket_path) + ",server=on,wait=off"]
            if args.virtual_time:
                command[command.index("tcg,thread=multi")] = "tcg,thread=single"
                command[command.index("-smp")+1] = "1"
                command += ["-icount", "shift=0,align=off,sleep=off"]
            if args.network_test:
                command += ["-netdev", "user,id=outer", "-device", "virtio-net-pci,netdev=outer"]
            else: command += ["-nic", "none"]
            record["command"] = command
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
            record["owned_outer_qemu_pid"] = process.pid
            for _ in range(300):
                if process.poll() is not None: raise RuntimeError("outer QEMU exited before QMP")
                control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); control.settimeout(30)
                try: control.connect(str(socket_path)); break
                except OSError: control.close(); control = None; time.sleep(.1)
            if control is None: raise TimeoutError("outer QMP startup")
            stream = control.makefile("rwb", buffering=0)
            if "QMP" not in json.loads(stream.readline()): raise RuntimeError("invalid outer QMP greeting")
            qmp("qmp_capabilities")
            selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while time.monotonic() - started < args.timeout:
                    for key, _ in selector.select(.2):
                        block = os.read(key.fd, 65536)
                        if block:
                            capture.extend(block); (output / "console.log").write_bytes(capture)
                    if len(capture) > 16*1024*1024: raise RuntimeError("outer serial capture limit")
                    text = terminal_text(bytes(capture))
                    if any(marker in text for marker in (b"Kernel panic", b"OKERNEL X12 BOOTSTRAP: FAIL")):
                        raise RuntimeError("boot/controller failure; inspect console.log")
                    if (b"Unified execution failed:" in terminal_text(bytes(capture[failure_scan_after:])) and failure_seen is None):
                        failure_seen = time.monotonic()
                        record["guest_controller_failed"] = True
                        failed_stage = stage
                        failure_scope_start = failure_scan_after
                        event("guest-controller-failure-observed")
                        stage = "failure-menu"
                        if not slow_launched:
                            # This is the test's own known failed tmux. Detach
                            # its retained dead pane to return to the ISO menu.
                            send(b"\x02d")
                    if stage == "failure-menu":
                        if HOST_MENU in terminal_text(bytes(capture[failure_scope_start:])):
                            stage_start = len(capture); send(b"s\n"); stage = "failure-shell"
                        elif time.monotonic() - failure_seen > 90:
                            raise RuntimeError("controller failed and host menu did not return")
                    if stage == "failure-shell" and b"# " in terminal_text(bytes(capture[stage_start:])):
                        diagnostic = ("import json,base64;from pathlib import Path;"
                            "s=Path('/run/okernel/state');"
                            "p=Path((s/'latest-unified-session').read_text().strip());"
                            "assert p.parent==s;"
                            "names=('result.json','qemu-stderr.log','console.log','linux-console.log','plan9-console.log','native-observation.json');"
                            "d={n:base64.b64encode((p/n).read_bytes()[-65536:]).decode() for n in names if (p/n).is_file()};"
                            "print('OKERNEL_ISO_FAILURE_DIAGNOSTIC_'+json.dumps({'session':str(p),'tail_files_base64':d},sort_keys=True))")
                        send(("python3 -B -c " + shlex.quote(diagnostic)
                              + "; printf '\\nOKERNEL_ISO_FAILURE_CAPTURE_DONE\\n'\n").encode())
                        stage = "failure-diagnostic"
                    if stage == "failure-diagnostic":
                        fresh = terminal_text(bytes(capture[stage_start:]))
                        if b"\nOKERNEL_ISO_FAILURE_CAPTURE_DONE\n" in fresh:
                            for line in fresh.splitlines():
                                prefix = b"OKERNEL_ISO_FAILURE_DIAGNOSTIC_"
                                if line.startswith(prefix):
                                    try: record["guest_failure_diagnostic"] = json.loads(line[len(prefix):])
                                    except (ValueError, UnicodeDecodeError): pass
                            if "guest_failure_diagnostic" in record:
                                event("guest-controller-failure-diagnostic-captured")
                                if args.slow_timeout and not slow_launched and failed_stage == "unified":
                                    record["default_startup_failure_diagnostic"] = record.pop("guest_failure_diagnostic")
                                    record["default_nested_startup_qualified"] = False
                                    command = ("export PATH=/opt/okernel/runtime/host-bin:/usr/bin:/bin; "
                                        "export OKERNEL_UNIFIED_HOST_PYTHON=/usr/bin/python3.12; "
                                        "/usr/bin/python3.12 -B /opt/okernel/runtime/okernel-unified check && "
                                        "/usr/bin/python3.12 -B /opt/okernel/runtime/runtime/scripts/okernel_unified_world.py run "
                                        "--state /run/okernel/state --build /opt/okernel/runtime/build "
                                        "--qemu /opt/okernel/runtime/tools/bin/qemu-system-aarch64 --timeout " + str(args.slow_timeout)
                                        + "; _slow_rc=$?; printf '\\nOKERNEL_ISO_SLOW_CALLER_STATUS:%s\\n' \"$_slow_rc\"; exit\n")
                                    record["slow_validation_launch"] = {"command": command,
                                        "scope": "same inventory-checked embedded runner and saved pair; explicit caller timeout; image and default unchanged"}
                                    slow_launched = True
                                    failure_seen = None
                                    failure_scan_after = len(capture)
                                    slow_start = len(capture)
                                    send(command.encode()); stage = "unified"
                                    event("explicit-slow-caller-started", timeout_seconds=args.slow_timeout)
                                    continue
                                raise RuntimeError("guest controller failed; captured private guest session tails before cleanup")
                            record["guest_failure_diagnostic_unavailable"] = True
                            event("guest-controller-failure-diagnostic-unavailable")
                            raise RuntimeError("guest controller failed; guest diagnostic unavailable, raw serial retained")
                    if failure_seen is not None and time.monotonic() - failure_seen > 180:
                        raise RuntimeError("guest controller failed; diagnostic capture deadline")
                    if stage == "menu" and b"OKernel serial test console" in text:
                        send(b"s\r"); stage = "carrier"; event("selected-serial-entry")
                    if stage == "carrier" and b"Type n within eight seconds" in text:
                        if not all(marker in text for marker in (b"OKERNEL X12 READONLY ROOT: PASS", b"OKERNEL X12 ORIGINAL MODULE PROBE: complete", b"OKERNEL X12 SAVED PAIR: PASS")):
                            raise RuntimeError("carrier readiness missing required bound markers")
                        event("readonly-root-module-probe-and-checked-seed")
                        if args.network_test:
                            send(b"n\n"); stage = "host-network"
                        elif args.root_only:
                            record["ok"] = True; break
                        else:
                            send(b"\n"); stage = "unified"
                    if stage == "host-network" and b"Interface (for example" in text and not initial_network_sent:
                        send(b"eth0\n"); initial_network_sent = True
                    if stage == "host-network" and b"Live host networking is configured." in text:
                        event("original-live-host-dhcp")
                        if args.root_only:
                            record["ok"] = True; break
                        stage = "unified"
                    ready_text = terminal_text(bytes(capture[slow_start:])) if slow_launched else text
                    if stage == "unified" and b"Linux and original Plan 9 share this workspace." in ready_text:
                        if slow_launched:
                            if b"Frozen unified runtime: PASS" not in terminal_text(bytes(capture[slow_start:])):
                                raise RuntimeError("slow caller did not verify the immutable embedded runtime")
                        elif not args.virtual_time:
                            record["default_nested_startup_qualified"] = True
                        record["selected_profile_startup_qualified"] = True
                        event("foreground-unified-console")
                        command = ("printf 'OKERNEL_ISO_SHARED_" + token + "\\000\\377\\021\\023\\n' > /n/okernel/work/iso-" + token
                            + "; p9 --timeout-ms 300000 rc -I -c 'cat /n/work/iso-" + token + "' > /work/iso-p9-" + token
                            + " && cmp /n/okernel/work/iso-" + token + " /work/iso-p9-" + token
                            + " && sha256sum /n/okernel/work/iso-" + token + " /work/iso-p9-" + token
                            + " && printf '#include <stdio.h>\\nint main(void){puts(\"OKERNEL_ISO_SOURCE_" + token + "\");return 0;}\\n' > /n/okernel/work/iso-" + token + ".c"
                            + " && cc /n/okernel/work/iso-" + token + ".c -o /work/iso-" + token
                            + " && /work/iso-" + token + "; _iso_rc=$?; printf '\\nOKERNEL_ISO_COMMAND_" + token + ":%s\\n' \"$_iso_rc\"\n")
                        send(command.encode()); stage = "application"
                    if stage == "application":
                        # Echo contains the literal %s, never this decimal status.
                        # Full raw domain logs are independently checked after save.
                        marker = re.search(rb"OKERNEL_ISO_COMMAND_" + token.encode() + rb":([0-9]+)", text)
                        if marker:
                            if (marker.group(1) != b"0" or text.count(shared_digest.encode()) < 2
                                    or b"OKERNEL_ISO_SOURCE_" + token.encode() not in text):
                                raise RuntimeError("shared-file/source-build command failed")
                            event("original-plan9-shared-read-and-original-linux-source-build")
                            stage_start = len(capture); send(b"exit\n"); stage = "exit"
                    if stage == "exit" and HOST_MENU in terminal_text(bytes(capture[stage_start:])):
                        if slow_launched and b"OKERNEL_ISO_SLOW_CALLER_STATUS:0" not in terminal_text(bytes(capture[stage_start:])):
                            raise RuntimeError("explicit slow caller did not return success")
                        event("typed-exit-returned-to-host-menu")
                        stage_start = len(capture); send(b"s\n"); stage = "host-audit-shell"
                    if stage == "host-audit-shell" and b"# " in terminal_text(bytes(capture[stage_start:])):
                        audit = ("import json,re,sys;from pathlib import Path;"
                            "sys.path.insert(0,'/opt/okernel/runtime/runtime/scripts');"
                            "from okernel_native_volume import Volume;"
                            "s=Path('/run/okernel/state');h=json.loads((s/'head.json').read_bytes());"
                            "p=Path(h['session']);assert p.parent==s;"
                            "r=json.loads((p/'result.json').read_bytes());"
                            "assert r.get('ok') is True and r.get('after')==h;"
                            "assert all(r.get(k) is True for k in ('paired_snapshot','virtual_cpu_stopped','native_operations_quiescent'));"
                            "assert len(r.get('console_exit_requests',[]))==1;"
                            "e=r['console_exit_requests'][0];"
                            "assert e.get('event')=='console-exit' and e.get('generation')==r['plan9_service']['generation']==format(r['epoch'],'016x');"
                            "assert e['request_id'] in h.get('console_exit_consumed',[]);"
                            "v=Volume.from_file(h['namespace']['path']);"
                            "assert v.get('/work/iso-" + token + "')==bytes.fromhex('" + expected_shared.hex() + "');"
                            "b=(p/'linux-console.log').read_bytes().replace(b'\\r\\n',b'\\n');"
                            "assert re.search(rb'(?:^|\\n)OKERNEL_ISO_COMMAND_" + token + ":0\\n',b);"
                            "assert b'\\nOKERNEL_ISO_SOURCE_" + token + "\\n' in b;"
                            "print(json.dumps({'saved_disk':h['disk']['sha256'],'saved_namespace':h['namespace']['sha256'],'flags':True}))")
                        command = ("python3 -B -c " + shlex.quote(audit)
                            + "; _audit_rc=$?; printf '\\nOKERNEL_ISO_SAVE_AUDIT_" + token + ":%s\\n' \"$_audit_rc\"\n")
                        send(command.encode()); stage = "host-audit"
                    if stage == "host-audit":
                        marker = re.search(rb"OKERNEL_ISO_SAVE_AUDIT_" + token.encode() + rb":([0-9]+)", text)
                        if marker:
                            if marker.group(1) != b"0": raise RuntimeError("retained paired save/native shared bytes audit failed")
                            event("retained-paired-save-and-native-file-audit")
                            stage_start = len(capture); send(b"exit\n"); stage = "host-menu"
                    if stage == "host-menu" and HOST_MENU in terminal_text(bytes(capture[stage_start:])):
                        send(b"p\n"); stage = "poweroff"
                    if process.poll() is not None:
                        if (stage == "poweroff" and process.returncode == 0
                                and b"OKERNEL X12 POWEROFF" in text):
                            event("clean-outer-poweroff"); record["ok"] = True; break
                        raise RuntimeError("outer QEMU stopped before qualified poweroff: " + str(process.returncode))
                else: raise TimeoutError("ISO acceptance deadline at stage " + stage)
            finally: selector.close()
            record["final_stage"] = stage
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        record["final_stage"] = stage
        if process is not None and process.poll() is None:
            try:
                if stream is not None: qmp("quit")
            except (OSError, ValueError, RuntimeError): pass
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        if stream is not None: stream.close()
        if control is not None: control.close()
        signal.signal(signal.SIGTERM, previous)
        record["owned_outer_qemu_exit"] = process.returncode if process is not None else None
        try: record["iso_unchanged"] = identity(iso) == before
        except OSError as error:
            record["iso_unchanged"] = False
            record["iso_final_identity_error"] = str(error)
        if not record["iso_unchanged"]: record["ok"] = False
        record["elapsed_seconds"] = time.monotonic() - started
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print("OKernel X12 ISO acceptance: " + ("PASS" if record["ok"] else "FAIL")
          + "\nEvidence: " + str(output / "result.json"), flush=True)
    return 0 if record["ok"] else 1


if __name__ == "__main__": raise SystemExit(main())
