#!/usr/bin/env python3
"""Exercise one live OKernel namespace, original packages, source and restart.

The native peer speaks 9P2000 with its own /work grant. It does not implement
the Plan 9 executable ABI. Linux retains the original Linux userspace ABI.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_domain", ROOT / "scripts/okernel_package_domain.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def verify(state: Path, qemu: str, timeout: float, *, source: bool = True, plan9port: bool = False):
    evidence = state / "unified-acceptance.json"
    if evidence.exists():
        history = state / "acceptance-history"
        history.mkdir(exist_ok=True)
        (history / ("unified-" + uuid.uuid4().hex + ".json")).write_bytes(evidence.read_bytes())
    record = {"schema": "ostadix.unified-okernel-acceptance/v1", "ok": False, "started": time.time(),
              "checks": [], "sessions": [],
              "scope": "Linux userspace below native O-core EL2 with a common native 9P2000 store and independent native protocol peer under QEMU/TCG",
              "remaining": ["full Plan 9 executable/kernel ABI", "other binary package ABIs", "physical Intel X12 qualification"]}
    runner.write_json(evidence, record)
    domain = None
    challenge = "linux-shared-" + uuid.uuid4().hex
    mk_workspace = "/n/okernel/work/mk-proof-" + uuid.uuid4().hex
    record["plan9_mk_workspace"] = mk_workspace
    try:
        domain = runner.Domain(state, qemu, timeout=timeout)
        record["sessions"].append(str(domain.session))
        if not domain.namespace or not domain.network:
            raise ValueError("verification requires explicit native namespace and mediated network grants")
        domain.ready()
        domain.command("pkg-namespace status && test -d /n/okernel/services")
        # These are ordinary Linux syscalls on the actual mounted native store.
        domain.command("printf '%s\\n' " + shlex.quote(challenge) + " > /n/okernel/work/from-linux")
        expected = f"native-9p-peer generation={domain.namespace_epoch:016x}"
        domain.command("i=0; until grep -qx " + shlex.quote(expected) + " /n/okernel/work/from-plan9 2>/dev/null; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done; grep -qx " + shlex.quote("linux=" + challenge) + " /n/okernel/work/from-plan9")
        domain.command("mkdir -p /n/okernel/work/linux-directory && printf 'rename-and-truncate\\n' > /n/okernel/work/linux-directory/first && mv /n/okernel/work/linux-directory/first /n/okernel/work/linux-directory/second && printf 'short\\n' > /n/okernel/work/linux-directory/second && test \"$(cat /n/okernel/work/linux-directory/second)\" = short && rm /n/okernel/work/linux-directory/second && rmdir /n/okernel/work/linux-directory")
        record["checks"].extend(["Linux native 9P mount and ordinary directory/create/write/read/rename/truncate/remove operations",
                                 "independent native Plan 9 protocol peer exchanges the same shared objects under a separate /work grant"])
        domain.command("printf '#include <stdio.h>\\nint main(void){puts(\"OKERNEL_UNIFIED_SOURCE_PASS\");return 0;}\\n' > /n/okernel/work/unified.c; cc /n/okernel/work/unified.c -o /work/unified && /work/unified")
        domain.wait(b"OKERNEL_UNIFIED_SOURCE_PASS", line=True)
        domain.command("pkg update && pkg install curl git cmake", timeout=timeout)
        domain.command("curl --fail --location https://zlib.net/ -o /work/upstream-zlib.html && test -s /work/upstream-zlib.html && git --version && cmake --version")
        record["checks"].extend(["online original signed APK repository resolution and package installation by name", "real DNS/HTTPS from the mediated network device", "C source read from shared native namespace and compiled/executed by original guest GCC"])
        if source:
            domain.command("pkg install zlib && cp /n/okernel/pkg/zlib /work/zlib-route-first", timeout=timeout)
            domain.command("pkg install zlib && cmp /n/okernel/pkg/zlib /work/zlib-route-first", timeout=timeout)
            domain.command("receipt=$(sed -n 's/^receipt=//p' /n/okernel/pkg/zlib); test -n \"$receipt\" && cd \"/n/okernel$receipt\" && sha256sum -c manifest.sha256 && test \"$(cat status)\" = complete")
            record["checks"].append("two independent original zlib source builds by name with identical full build receipts and output hashes published in the native namespace")
        if plan9port:
            domain.command("pkg install plan9port", timeout=timeout)
            # Retain a completed original source installation before testing
            # further application behavior. A later assertion must not discard
            # an expensive successful build or force another fresh compile.
            domain.save()
            record["source_install_pair"] = json.loads((state / "head.json").read_text())
            domain.close()
            domain = runner.Domain(state, qemu, timeout=timeout)
            record["sessions"].append(str(domain.session))
            domain.ready()
            domain.command("9 rc -c 'echo OKERNEL_ORIGINAL_RC_PASS; echo rc-shared-file > /n/okernel/work/rc-output' && grep -qx rc-shared-file /n/okernel/work/rc-output", timeout=timeout)
            domain.wait(b"OKERNEL_ORIGINAL_RC_PASS", line=True)
            domain.command("mkdir " + shlex.quote(mk_workspace) + " && cd " + shlex.quote(mk_workspace) + " && printf 'first\\n' > input && printf 'all:V: output\\noutput: input\\n\\tcat input > output\\n\\techo rebuilt >> count\\n' > mkfile && 9 mk all && cmp input output && test \"$(wc -l < count)\" -eq 1 && printf 'second\\n' >> input && 9 mk all && cmp input output && test \"$(wc -l < count)\" -eq 2 && 9 mk all && test \"$(wc -l < count)\" -eq 2", timeout=timeout)
            domain.command("receipt=$(sed -n 's/^receipt=//p' /n/okernel/pkg/plan9port); test -n \"$receipt\" && cd \"/n/okernel$receipt\" && sha256sum -c manifest.sha256 && test \"$(cat status)\" = complete")
            record["checks"].append("original Plan9port rc writes shared files; original mk builds and correctly rebuilds changed dependencies in the same native namespace (Linux ABI)")
        domain.command("printf '%s\\n' " + shlex.quote(challenge) + " > /n/okernel/work/restart-proof")
        first_epoch = domain.namespace_epoch
        domain.save()
        record["first_pair"] = json.loads((state / "head.json").read_text())
        domain.close()
        domain = runner.Domain(state, qemu, timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        if domain.namespace_epoch == first_epoch:
            raise RuntimeError("namespace epoch was reused across restart")
        domain.command("test \"$(cat /n/okernel/work/restart-proof)\" = " + shlex.quote(challenge) + " && /work/unified && apk info -e gcc git curl cmake && test -s /work/upstream-zlib.html")
        expected = f"native-9p-peer generation={domain.namespace_epoch:016x}"
        domain.command("i=0; until grep -qx " + shlex.quote(expected) + " /n/okernel/work/from-plan9; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done; grep -qx " + shlex.quote("linux=" + challenge) + " /n/okernel/work/from-plan9")
        if source:
            domain.command("cmp /n/okernel/pkg/zlib /work/zlib-route-first && test -f /usr/local/lib/libz.a")
        if plan9port:
            domain.command("9 rc -c 'echo OKERNEL_ORIGINAL_RC_RESTART_PASS' && grep -qx rc-shared-file /n/okernel/work/rc-output && cd " + shlex.quote(mk_workspace) + " && cmp input output && 9 mk all && test \"$(wc -l < count)\" -eq 2")
            domain.wait(b"OKERNEL_ORIGINAL_RC_RESTART_PASS", line=True)
        domain.save()
        record.update(ok=True, finished=time.time(), restart_pair=json.loads((state / "head.json").read_text()),
                      boot_epochs=[first_epoch, domain.namespace_epoch])
        record["checks"].extend(["one atomic generation head binds package disk and shared native object store",
                                 "files, packages, executable and shared namespace survive a real VM restart with fresh namespace sessions"])
        print("Unified OKernel live acceptance: PASS\nEvidence: " + str(evidence), flush=True)
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        runner.write_json(evidence, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=runner.DEFAULT_STATE)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--skip-source", action="store_true", help="skip the two original zlib builds")
    parser.add_argument("--plan9port", action="store_true", help="also build and test the original Plan9port userland")
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.qemu, args.timeout, source=not args.skip_source, plan9port=args.plan9port)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print("Unified OKernel verification failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
