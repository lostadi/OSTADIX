#!/usr/bin/env python3
"""Configure unchanged full OpenJDK source with declared scoped build tools.

The boot JDK and development libraries are hosted build prerequisites, never
substitutes for source-built or O-core-lowered runtime dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


def artifact(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--cxx", required=True)
    parser.add_argument("--jobs", type=int, required=True)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("jobs must be positive")
    for variable in ("OCORE_BOOT_JDK", "OCORE_LLVM22_BIN"):
        if not os.environ.get(variable):
            parser.error(variable + " must select an explicit qualified build tool")
    boot = Path(os.environ["OCORE_BOOT_JDK"]).resolve()
    llvm = Path(os.environ["OCORE_LLVM22_BIN"]).resolve()
    bootstrap = [boot / "release", boot / "lib/modules", boot / "lib/ct.sym",
                 *[boot / "bin" / name for name in ("java", "javac", "jar", "jmod", "jlink")]]
    if any(not path.is_file() for path in bootstrap):
        parser.error("a complete boot JDK with javac/tools/modules/ct.sym is required")
    support = args.build.resolve() / "configure-support"
    support.mkdir(parents=True, exist_ok=True)
    linker = support / "ocore-serial-ld"
    lld = llvm / "ld.lld"
    flock = shutil.which("flock")
    if not lld.is_file() or not flock:
        parser.error("the declared LLVM linker and flock are required for serialized linking")
    linker.write_text("#!/bin/sh\nexec " + shlex.join([flock, "-e", str(support / "ocore-link.lock"), str(lld)]) + ' "$@"\n')
    linker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = str(llvm) + os.pathsep + environment["PATH"]
    argv = ["bash", str(args.source.resolve() / "configure"),
            "--with-toolchain-type=clang", "--with-jvm-variants=server", "--disable-warnings-as-errors",
            "--with-boot-jdk=" + str(boot), "--with-jobs=" + str(args.jobs),
            "--with-memory-size=2048", "--with-boot-jdk-jvmargs=-Xms128M -Xmx1024M",
            "--with-extra-ldflags=--ld-path=" + str(linker), "CC=" + args.cc, "CXX=" + args.cxx]
    receipts = [artifact(path) for path in bootstrap] + [artifact(lld), artifact(linker)]
    deps_root = os.environ.get("OCORE_OPENJDK_DEPS_ROOT")
    if deps_root:
        deps = Path(deps_root).resolve()
        include, lib = deps / "usr/include", deps / "usr/lib/x86_64-linux-gnu"
        for name in ("X11/Xlib.h", "alsa/asoundlib.h", "cups/cups.h"):
            if not (include / name).is_file():
                parser.error("scoped full-desktop development header missing: " + name)
        data = deps / "usr/share/autoconf"
        original_cfg = data / "autom4te.cfg"
        relocated_cfg = support / "ocore-autom4te.cfg"
        relocated_cfg.write_text(original_cfg.read_text().replace("/usr/share/autoconf", str(data)))
        environment.update({"AUTOCONF": str(deps / "usr/bin/autoconf"),
                            "AUTOM4TE": str(deps / "usr/bin/autom4te"),
                            "autom4te_perllibdir": str(data), "AC_MACRODIR": str(data),
                            "AUTOM4TE_CFG": str(relocated_cfg), "trailer_m4": str(data / "autoconf/trailer.m4")})
        environment["LD_LIBRARY_PATH"] = str(lib) + os.pathsep + environment.get("LD_LIBRARY_PATH", "")
        argv += ["--x-includes=" + str(include), "--x-libraries=" + str(lib),
                 "--with-cups-include=" + str(include), "--with-alsa-include=" + str(include), "--with-alsa-lib=" + str(lib)]
        receipts += [artifact(original_cfg), artifact(relocated_cfg), artifact(deps / "usr/bin/autoconf")]
    result = {"schema": "ocore-openjdk-bootstrap-prerequisites-v1", "configure_argv": argv,
              "bootstrap_artifacts": receipts, "compile_jobs": args.jobs, "link_jobs": 1,
              "source_profile_reduced": False, "build_prerequisites_lowered": False,
              "dependency_closure_complete": False, "native_execution_qualified": False, "runtime_complete": False}
    (support / "ocore-bootstrap-prerequisites.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    return subprocess.run(argv, cwd=args.build, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
