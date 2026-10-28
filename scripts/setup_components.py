#!/usr/bin/env python3
"""Build independent host-supported components without dispatching their effects.

Missing platform/tool/source requirements are reported per component. A selected
build failure is an error, not evidence of successful setup. Check/dry-run do not
build or change files; Bash features use an isolated read-only probe. Android
builds produce debug artifacts only.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


@dataclass
class Component:
    name: str
    commands: list[list[str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    note: str = ""
    cwd: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    artifact: str = ""


def native_dependency_missing(root: Path, app: Path) -> list[str]:
    manifest = app / "app/src/main/resources/META-INF/ostadix/native-sha256.txt"
    native_dir = root / "apps/android-terminal/build/intermediates/package/lib/arm64-v8a"
    missing = []
    if not manifest.is_file():
        return ["admitted Android terminal native dependency hash manifest"]
    for line in manifest.read_text().splitlines():
        words = line.split()
        if len(words) != 2:
            continue
        path = native_dir / words[1]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != words[0]:
            missing.append(f"admitted Android terminal native dependency {words[1]}")
    return missing


def plan(root: Path, *, system: str | None = None, machine: str | None = None,
         apps: bool = True, jni: bool = True, native: bool = True, kernel: bool = True, assume_wasi: bool = False,
         which=shutil.which, environ=None) -> list[Component]:
    env = os.environ if environ is None else environ
    system, machine = system or platform.system(), machine or platform.machine()
    home = Path(env.get("HOME", str(Path.home())))
    sdk_candidates = [home / "android-sdk", home / "Android/Sdk", home / "Library/Android/sdk", Path("/usr/lib/android-sdk")]
    if env.get("LOCALAPPDATA"):
        sdk_candidates.append(Path(env["LOCALAPPDATA"]) / "Android/Sdk")
    explicit_sdk = env.get("ANDROID_SDK_ROOT") or env.get("ANDROID_HOME")
    sdk = Path(explicit_sdk) if explicit_sdk else next((path for path in sdk_candidates if path.is_dir()), sdk_candidates[0])
    tool_dirs = []
    if env.get("JAVA_HOME"):
        tool_dirs.append(Path(env["JAVA_HOME"]) / "bin")
    for base in (sdk / "build-tools", Path("/usr/lib/jvm"), Path("/Library/Java/JavaVirtualMachines")):
        if base.is_dir():
            for directory in sorted(base.iterdir(), key=lambda path: tuple(int(n) for n in re.findall(r"\d+", path.name)), reverse=True):
                if directory.is_dir():
                    tool_dirs.append(directory if base == sdk / "build-tools" else directory / ("Contents/Home/bin" if system == "Darwin" else "bin"))
    tool_dirs.extend((sdk / "platform-tools", sdk / "cmdline-tools/latest/bin",
                      Path("/opt/homebrew/bin"), Path("/usr/local/bin"),
                      Path("/opt/homebrew/opt/openjdk/bin"), Path("/usr/local/opt/openjdk/bin"),
                      Path("/opt/homebrew/opt/llvm/bin"), Path("/usr/local/opt/llvm/bin"),
                      Path("/opt/homebrew/opt/lld/bin"), Path("/usr/local/opt/lld/bin")))
    tool_path = os.pathsep.join([str(path) for path in tool_dirs if path.is_dir()] + [env.get("PATH", os.defpath)])

    def resolve(tool):
        for directory in tool_dirs:
            candidate = directory / tool
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return which(tool)

    bash = env.get("OSTADIX_BASH") or resolve("bash")
    modern_bash = True
    if env.get("OSTADIX_BASH") and not Path(bash).is_file():
        modern_bash = False
    if bash and Path(bash).is_file():
        probe_env = {key: value for key, value in os.environ.items() if key not in {"BASH_ENV", "ENV"}}
        try:
            modern_bash = subprocess.run([bash, "--noprofile", "--norc", "-c", "set -e; mapfile -t values < /dev/null; declare -A entries; entries[probe]=yes; [[ ${entries[probe]} == yes ]]"],
                                         env=probe_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            modern_bash = False
    result = []

    def add(name, tools=(), commands=(), missing=(), note="", cwd=None, extra_env=None, artifact=""):
        component = Component(name, [list(command) for command in commands], list(missing), note,
                              cwd or root, {"PATH": tool_path, "TMPDIR": env.get("TMPDIR", tempfile.gettempdir()), **(extra_env or {})}, artifact)
        component.missing.extend(f"executable {tool}" for tool in tools if not resolve(tool))
        result.append(component)
        return component

    add("root-runtime", note="Root build includes native O-core/JIT, OIR/WASM compiler, Control, Information, Live-World and O-Git; availability and supported ISA profiles remain command-specific")
    add("python-reference", tools=("python3",), note="Repository-local o_lang; native command resolver also exposes checked-in Python/Ruby/shell tools and backend adapters")
    add("c17", note="Built by setup.sh; legacy_cpp is an archived reference without a supported build recipe")
    if jni:
        missing = [] if system in {"Linux", "Darwin", "FreeBSD", "OpenBSD", "NetBSD", "DragonFly"} else ["Unix host implementation (use WSL on Windows)"]
        add("jni-runtime", ("cargo",), [["cargo", "build", "--release", "--locked", "--manifest-path", str(root / "apps/android-terminal/runtime/Cargo.toml"), "--target-dir", str(root / "apps/android-terminal/runtime/target")]],
            missing, "Host JNI shared library; Android APK requires its separate admitted ARM64/Termux closure", artifact="apps/android-terminal/runtime/target/release/libostadix_runtime.{so,dylib}")
    else:
        add("jni-runtime", missing=("disabled by --minimal/--no-jni",))

    if native and kernel:
        linker = env.get("OCORE_LLD") or resolve("ld.lld") or resolve("rust-lld") or resolve("lld")
        if not linker:
            rustup_home = Path(env.get("RUSTUP_HOME", str(home / ".rustup")))
            linker = next((str(path) for path in sorted(rustup_home.glob("toolchains/*/lib/rustlib/*/bin/rust-lld")) if os.access(path, os.X_OK)), None)
        add("ocore-kernel", ("bash", "clang", "rustc", "file"), [["bash", str(root / "ocore/kernel/build.sh")]],
            missing=() if linker and os.access(linker, os.X_OK) else ("LLD-compatible linker (OCORE_LLD, ld.lld, rust-lld, lld or installed Rust sysroot)",),
            note="Builds the freestanding x86_64 kernel; no QEMU boot or physical-device writes",
            extra_env={"OCOREC_BIN": str(root / "target/release/ocorec"), "OCORE_PROBE_MODE": "0", **({"OCORE_LLD": linker} if linker else {})}, artifact="target/ocore-kernel/kernel.elf")
    else:
        add("ocore-kernel", missing=("disabled by --minimal/--no-ocore",))
    if native:
        wasi = add("wasi-artifact", ("rustc", "cargo"), [[str(root / "target/release/olangc"), str(root / "examples/hello.O"), "--target", "wasm", "-o", str(root / "target/setup-components/hello.wasm")]],
                   note="WASI compile artifact; foreign backend execution requires explicit runtimes/providers, and is not claimed as browser execution", artifact="target/setup-components/hello.wasm")
        # Detect the standard library without executing rustup in read-only modes.
        rustup_home = Path(env.get("RUSTUP_HOME", str(home / ".rustup")))
        toolchain_file = root / "rust-toolchain.toml"
        channel_match = re.search(r'^channel\s*=\s*"([^"]+)"', toolchain_file.read_text(), re.MULTILINE) if toolchain_file.is_file() else None
        channel = channel_match[1] if channel_match else "stable"
        if not assume_wasi and not any(rustup_home.glob(f"toolchains/{channel}*/lib/rustlib/wasm32-wasip1/lib/libstd-*.rlib")):
            wasi.missing.append(f"installed wasm32-wasip1 standard library for embedded toolchain {channel} (rustup target add wasm32-wasip1)")
    else:
        add("wasi-artifact", missing=("disabled by --minimal",))

    for label, tools in (("MATLAB", ("matlab",)), ("Wolfram", ("wolframscript",)), ("iPhone host tools", ("ideviceinfo", "iproxy"))):
        available = [tool for tool in tools if resolve(tool)]
        add(label, note=f"Detected {', '.join(available)}; use the native backend/device command explicitly" if available else "No automatic licensed-runtime download or device pairing",
            missing=() if available else ("existing licensed runtime" if label in {"MATLAB", "Wolfram"} else "libimobiledevice tools/device pairing for apps/iphone16-pro programs",))
    add("external-runtime-lowering", missing=("pinned source checkout, exact frontend/build recipe and complete admitted dependency inventory",),
        note="Capture/import workflows are installed through the native catalog; setup does not establish complete external-runtime lowering")
    add("guest-and-kernel-personalities", note="Native catalog exposes checked-in kernel builders and pinned guest preparation; images/sources and execution are explicit workflows")

    if not apps:
        add("standalone-apps", missing=("disabled by --minimal/--no-apps",))
        return result

    mobile = root / "apps/mobile-console"
    add("mobile-console", ("cargo",), [["cargo", "build", "--release", "--locked", "--manifest-path", str(mobile / "Cargo.toml"), "--target-dir", str(mobile / "target")]],
        () if system == "Linux" else ("Linux/Android USB configfs implementation",),
        "Builds CLI only; never starts a root daemon or reconfigures USB", artifact="apps/mobile-console/target/release/mobile-console")
    browser = root / "apps/browser-chat-pdf"
    add("browser-chat-pdf", ("node", "npm", "bash"), [["npm", "ci", "--ignore-scripts"], ["npm", "run", "build:mobile"], ["node", "scripts/validate.mjs", "--root", str(browser)]],
        () if (browser / "package-lock.json").is_file() else ("package-lock.json",),
        "Builds and validates the mobile bookmarklet and unpacked desktop extension; browser activation remains manual", cwd=browser,
        artifact="apps/browser-chat-pdf/mobile/dist and extension source")

    standard_jar = Path(env.get("ANDROID_JAR", str(sdk / "platforms/android-34/android.jar")))
    common = ("bash", "aapt2", "apksigner", "d8", "jar", "javac", "keytool", "sed")
    xposed = Path(env.get("LIBXPOSED_API_AAR", "/data/data/com.termux/files/usr/tmp/libxposed-api-102.0.0.aar"))
    xposed_hash = "423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0"
    terminal_prefix = Path(env.get("TERMUX_PREFIX", "/data/data/com.termux/files/usr"))
    terminal_jar = Path(env.get("ANDROID_JAR", str(sdk / "platforms/android-37.2/android.jar")))
    android_names = ("android-terminal", "prismatic-launcher", "accessory-connector", "pixel-ai-probe", "prismatic-systemui", "aicore-ostadix-extension")
    for name in android_names:
        app = root / "apps" / name
        required = list(common)
        missing = []
        jar = terminal_jar if name == "android-terminal" else standard_jar
        if not jar.is_file():
            missing.append(f"Android platform jar {jar}")
        if name in {"prismatic-systemui", "aicore-ostadix-extension"}:
            required.extend(("sha256sum", "unzip"))
            if not xposed.is_file():
                missing.append(f"pinned official libxposed API AAR {xposed}")
            elif hashlib.sha256(xposed.read_bytes()).hexdigest() != xposed_hash:
                missing.append("pinned libxposed API AAR SHA-256 mismatch")
        if name == "android-terminal":
            required.extend(("cargo", "clang", "dpkg-deb", "env", "java", "ld.lld", "python3", "readelf", "sha256sum"))
            if system != "Linux" or machine not in {"aarch64", "arm64"} or not (terminal_prefix / "bin/bash").is_file():
                missing.append("native ARM64 Android/Termux toolchain and pinned Bash/shared-library closure")
        if name == "aicore-ostadix-extension":
            required.extend(("java", "javap", "readelf"))
            missing.extend(native_dependency_missing(root, app))
        if name == "pixel-ai-probe":
            required.extend(("gradle", "java", "python3", "grep", "sha256sum", "sort", "unzip"))
        if name == "accessory-connector":
            required.extend(("java", "python3", "grep"))
        if not modern_bash:
            missing.append("Bash 4+ with mapfile/associative arrays (install Homebrew bash or set OSTADIX_BASH)")
        add(name, required, [[bash or "bash", str(app / "build.sh")]], missing,
            "Builds debug APK only; never installs, grants permissions, starts services or changes a device",
            extra_env={"ANDROID_JAR": str(jar)}, artifact=f"apps/{name}/build/outputs/apk/debug")
    for name, api in (("nano-factory-reader", "34"), ("nano-local-loader", "37.2")):
        jar = Path(env.get("ANDROID_JAR", str(sdk / f"platforms/android-{api}/android.jar")))
        missing = [] if jar.is_file() else [f"Android platform jar {jar}"]
        if name == "nano-local-loader" and not modern_bash:
            missing.append("Bash 4+ mapfile support")
        required = ["bash", "javac", "jar", "d8", "sha256sum"]
        if name == "nano-local-loader":
            required.extend(("rg", "sort"))
        add(name, required, [[bash or "bash", str(root / "tools" / name / "build.sh")]], missing,
            "Builds Android DEX jar only; no device dispatch", extra_env={"ANDROID_JAR": str(jar)}, artifact=f"tools/{name}/build/*.jar")
    return result


def execute(components: list[Component], *, dry_run=False, check=False, local_bins=True) -> int:
    failures = []
    for item in components:
        if item.name == "aicore-ostadix-extension" and not (check or dry_run):
            item.missing = [reason for reason in item.missing if not reason.startswith("admitted Android terminal native dependency")]
            item.missing.extend(native_dependency_missing(item.cwd, item.cwd / "apps/aicore-ostadix-extension"))
        if item.missing:
            print(f"  [skip] {item.name}: {'; '.join(item.missing)}")
            continue
        print(f"  [{'available' if check else 'setup'}] {item.name}: {item.note}")
        if item.artifact:
            print(f"    artifact: {item.artifact}")
        if check:
            continue
        for command in item.commands:
            if dry_run:
                prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in item.env.items())
                print(f"[DRY] (cd {shlex.quote(str(item.cwd))} && {prefix + ' ' if prefix else ''}{shlex.join(command)})")
                continue
            if item.name == "wasi-artifact":
                (item.cwd / "target/setup-components").mkdir(parents=True, exist_ok=True)
            try:
                child_env = {**os.environ, **item.env}
                if item.name in {"mobile-console", "jni-runtime"}:
                    child_env.pop("CARGO_BUILD_TARGET", None)
                subprocess.run(command, cwd=item.cwd, env=child_env, check=True)
            except (OSError, subprocess.CalledProcessError) as error:
                print(f"  [failed] {item.name}: {error}", file=sys.stderr)
                failures.append(item.name)
                break
        if item.name == "mobile-console" and item.name not in failures and local_bins:
            source = item.cwd / item.artifact
            destination = Path.home() / ".local/bin/mobile-console"
            if dry_run:
                print(f"[DRY] install native {source} into {destination}")
            else:
                import importlib.util
                spec = importlib.util.spec_from_file_location("ostadix_native_install", item.cwd / "scripts/install_native_binaries.py")
                installer = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(installer)
                try:
                    installer.validate_native(source)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    installer.atomic_copy(source, destination)
                except (OSError, ValueError) as error:
                    print(f"  [failed] {item.name} installation: {error}", file=sys.stderr)
                    failures.append(item.name)
    if failures:
        print(f"Component build failed: {', '.join(failures)}", file=sys.stderr)
    return bool(failures)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--no-apps", action="store_true")
    parser.add_argument("--no-jni", action="store_true")
    parser.add_argument("--no-native", action="store_true")
    parser.add_argument("--no-kernel", action="store_true")
    parser.add_argument("--no-local-bins", action="store_true")
    parser.add_argument("--assume-wasi", action="store_true", help="Dry-run only: WASI standard library is scheduled by setup.sh")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--json", action="store_true", help="Print read-only capability plan")
    args = parser.parse_args(argv)
    if args.assume_wasi and not args.dry_run:
        parser.error("--assume-wasi requires --dry-run")
    components = plan(args.repo_root.resolve(), apps=not args.no_apps, jni=not args.no_jni, native=not args.no_native,
                      kernel=not args.no_kernel, assume_wasi=args.assume_wasi)
    if args.json:
        print(json.dumps([{"name": item.name, "available": not item.missing, "missing": item.missing, "note": item.note,
                           "commands": item.commands, "cwd": str(item.cwd), "env": item.env, "artifact": item.artifact} for item in components], indent=2))
        return 0
    return int(execute(components, dry_run=args.dry_run, check=args.check, local_bins=not args.no_local_bins))


if __name__ == "__main__":
    raise SystemExit(main())
