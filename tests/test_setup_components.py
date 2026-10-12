"""Capability-driven setup builds, with isolated tools and no device execution."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("setup_components", ROOT / "scripts/setup_components.py")
components = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = components
spec.loader.exec_module(components)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="component setup test ")
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)

    def plan(self, **kwargs):
        return components.plan(ROOT, system="Linux", machine="x86_64", environ={"HOME": str(self.home)}, **kwargs)

    def test_no_optional_tool_never_dispatches_and_reports_concrete_requirements(self):
        plan = self.plan(which=lambda _: None)
        android = next(item for item in plan if item.name == "android-terminal")
        self.assertTrue(any("ARM64 Android/Termux" in reason for reason in android.missing))
        self.assertTrue(any("Android platform jar" in reason for reason in android.missing))
        with patch.object(components.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(components.execute(plan, check=True), 0)
            self.assertEqual(components.execute(plan, dry_run=True), 0)
        run.assert_not_called()
        self.assertEqual(list(self.home.iterdir()), [])

    def test_all_independent_cargo_manifests_have_build_dispatch(self):
        plan = self.plan(which=lambda name: f"/fake/{name}", assume_wasi=True)
        commands = [argument for item in plan for command in item.commands for argument in command]
        for manifest in ("apps/android-terminal/runtime/Cargo.toml", "apps/mobile-console/Cargo.toml"):
            self.assertIn(str(ROOT / manifest), commands)
        for item in plan:
            for command in item.commands:
                if command[0] == "cargo":
                    self.assertIn("--locked", command)
                    self.assertIn("--target-dir", command)
        self.assertFalse(next(item for item in plan if item.name == "mobile-console").missing)

    def test_opt_out_removes_build_commands(self):
        plan = self.plan(which=lambda name: f"/fake/{name}", apps=False, jni=False, native=False)
        self.assertFalse(any(item.commands for item in plan))
        self.assertTrue(next(item for item in plan if item.name == "standalone-apps").missing)

    def test_android_java_apk_is_available_on_sdk_host_without_termux(self):
        sdk = self.home / "sdk/platforms/android-34"
        sdk.mkdir(parents=True)
        (sdk / "android.jar").write_bytes(b"test sdk")
        plan = components.plan(ROOT, system="Linux", machine="x86_64", which=lambda name: f"/fake/{name}",
                               environ={"HOME": str(self.home), "ANDROID_SDK_ROOT": str(self.home / "sdk")})
        self.assertFalse(next(item for item in plan if item.name == "prismatic-launcher").missing)
        self.assertTrue(next(item for item in plan if item.name == "android-terminal").missing)
        systemui = next(item for item in plan if item.name == "prismatic-systemui")
        self.assertTrue(any("libxposed" in reason for reason in systemui.missing))

    def test_build_failure_keeps_other_components_and_reports_failure(self):
        script = self.home / "fake-tool"
        log = self.home / "calls"
        script.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMPONENT_LOG"\n[ "$1" != fail ]\n')
        script.chmod(0o755)
        plan = [components.Component("bad", [[str(script), "fail"]], cwd=self.home),
                components.Component("good", [[str(script), "pass"]], cwd=self.home)]
        with patch.dict(os.environ, {"COMPONENT_LOG": str(log)}), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(components.execute(plan), 1)
        self.assertEqual(log.read_text().splitlines(), ["fail", "pass"])

    def test_read_only_modes_do_not_execute_available_tools(self):
        plan = self.plan(which=lambda name: f"/fake/{name}", assume_wasi=True)
        with patch.object(components.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(components.execute(plan, dry_run=True), 0)
            self.assertIn("--locked", output.getvalue())
            self.assertEqual(components.execute(plan, check=True), 0)
        run.assert_not_called()
        self.assertEqual(list(self.home.iterdir()), [])

    def test_wasi_standard_library_missing_is_visible(self):
        plan = self.plan(which=lambda name: f"/fake/{name}")
        wasi = next(item for item in plan if item.name == "wasi-artifact")
        self.assertTrue(any("wasm32-wasip1" in reason for reason in wasi.missing))

    def test_sdk_build_tools_and_java_home_are_used_without_global_path(self):
        sdk = self.home / "sdk"
        tools = sdk / "build-tools/34.0.0"
        java = self.home / "jdk/bin"
        for directory, names in ((tools, ("aapt2", "apksigner", "d8")), (java, ("javac", "java", "jar", "keytool"))):
            directory.mkdir(parents=True)
            for name in names:
                path = directory / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
        jar = sdk / "platforms/android-34/android.jar"
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"test sdk")
        plan = components.plan(ROOT, system="Linux", machine="x86_64", which=lambda name: "/bin/bash" if name == "bash" else "/usr/bin/sed" if name == "sed" else None,
                               environ={"HOME": str(self.home), "ANDROID_SDK_ROOT": str(sdk), "JAVA_HOME": str(java.parent), "PATH": "/bin"})
        app = next(item for item in plan if item.name == "prismatic-launcher")
        self.assertFalse(app.missing)
        self.assertIn(str(tools), app.env["PATH"])
        self.assertIn(str(java), app.env["PATH"])

    def test_macos_android_build_uses_actual_modern_bash_features(self):
        sdk = self.home / "sdk/platforms/android-34"
        sdk.mkdir(parents=True)
        (sdk / "android.jar").write_bytes(b"test sdk")
        env = {"HOME": str(self.home), "ANDROID_SDK_ROOT": str(self.home / "sdk"), "OSTADIX_BASH": "/bin/bash"}
        plan = components.plan(ROOT, system="Darwin", machine="arm64", which=lambda name: "/bin/bash" if name == "bash" else f"/fake/{name}", environ=env)
        self.assertFalse(next(item for item in plan if item.name == "prismatic-launcher").missing)
        self.assertFalse(next(item for item in plan if item.name == "pixel-ai-probe").missing)
        legacy = self.home / "legacy-bash"
        legacy.write_text("#!/bin/sh\nexit 1\n")
        legacy.chmod(0o755)
        env["OSTADIX_BASH"] = str(legacy)
        plan = components.plan(ROOT, system="Darwin", machine="arm64", which=lambda name: f"/fake/{name}", environ=env)
        self.assertTrue(any("Bash 4+" in reason for reason in next(item for item in plan if item.name == "prismatic-launcher").missing))

    def test_wasi_std_from_wrong_toolchain_does_not_mark_artifact_available(self):
        installed = self.home / ".rustup/toolchains/1.0.0-test/lib/rustlib/wasm32-wasip1/lib"
        installed.mkdir(parents=True)
        (installed / "libstd-fake.rlib").write_bytes(b"wrong std")
        plan = self.plan(which=lambda name: f"/fake/{name}")
        self.assertTrue(next(item for item in plan if item.name == "wasi-artifact").missing)

    def test_kernel_uses_supported_explicit_linker_instead_of_requiring_ld_lld(self):
        linker = self.home / "rust-lld"
        linker.write_text("#!/bin/sh\nexit 0\n")
        linker.chmod(0o755)
        plan = components.plan(ROOT, system="Linux", machine="x86_64", environ={"HOME": str(self.home), "OCORE_LLD": str(linker)},
                               which=lambda name: None if name in {"ld.lld", "rust-lld", "lld"} else f"/fake/{name}")
        kernel = next(item for item in plan if item.name == "ocore-kernel")
        self.assertFalse(kernel.missing)
        self.assertEqual(kernel.env["OCORE_LLD"], str(linker))

    def test_sdk_default_android_studio_location_is_discovered(self):
        sdk = self.home / "Android/Sdk/platforms/android-34"
        sdk.mkdir(parents=True)
        (sdk / "android.jar").write_bytes(b"test sdk")
        plan = self.plan(which=lambda name: f"/fake/{name}")
        app = next(item for item in plan if item.name == "prismatic-launcher")
        self.assertFalse(app.missing)
        self.assertEqual(app.env["ANDROID_JAR"], str(sdk / "android.jar"))

    def test_aicore_rechecks_native_hash_dependencies_after_prior_build(self):
        root = self.home / "source"
        app = root / "apps/aicore-ostadix-extension"
        manifest = app / "app/src/main/resources/META-INF/ostadix/native-sha256.txt"
        manifest.parent.mkdir(parents=True)
        native = root / "apps/android-terminal/build/intermediates/package/lib/arm64-v8a/runtime.so"
        data = b"test native dependency"
        manifest.write_text(f"{hashlib.sha256(data).hexdigest()} runtime.so\n")
        builder = self.home / "fake-builder"
        builder.write_text(f"#!/bin/sh\nmkdir -p '{native.parent}'\nprintf 'test native dependency' > '{native}'\n")
        builder.chmod(0o755)
        marker = self.home / "aicore-built"
        consumer = self.home / "fake-consumer"
        consumer.write_text(f"#!/bin/sh\nprintf built > '{marker}'\n")
        consumer.chmod(0o755)
        plan = [components.Component("android-terminal", [[str(builder)]], cwd=root),
                components.Component("aicore-ostadix-extension", [[str(consumer)]], ["admitted Android terminal native dependency runtime.so"], cwd=root)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(components.execute(plan), 0)
        self.assertEqual(marker.read_text(), "built")

    def test_math_alone_does_not_claim_wolframscript_backend_available(self):
        plan = self.plan(which=lambda name: f"/fake/{name}" if name == "math" else None)
        wolfram = next(item for item in plan if item.name == "Wolfram")
        self.assertTrue(wolfram.missing)


if __name__ == "__main__":
    unittest.main()
