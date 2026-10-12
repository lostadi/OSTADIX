"""Regression tests for setup planning and isolated installation dispatch."""

from __future__ import annotations

from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETUP = PROJECT_ROOT / "setup.sh"
BASH = Path("/bin/bash")
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class SetupScriptTests(unittest.TestCase):
    maxDiff = None

    def test_native_install_dispatch_keeps_required_argv_under_system_bash_nounset(self) -> None:
        # Execute the real function bodies, not setup's global installation
        # flow. On macOS /bin/bash is 3.2, whose nounset rejects empty arrays.
        # A shell stub captures argv without invoking Python or installing files.
        source = SETUP.read_text(encoding="utf-8")
        for name in ("refresh_cargo_bin_binaries", "install_local_binaries"):
            body = source.split(f"\n{name}() {{\n", 1)[1].split("\n}\n", 1)[0]
            for dry_run, full in ((False, False), (False, True), (True, False), (True, True)):
                with self.subTest(function=name, dry_run=dry_run, full=full):
                    with tempfile.TemporaryDirectory(prefix="native install test ") as directory:
                        home = Path(directory)
                        root = home / "source with spaces"
                        cargo_bin = home / "cargo with spaces" / "bin"
                        capture = home / "arguments"
                        script = (
                            'set -euo pipefail\n'
                            'python3() { printf "%s\\0" "$@" > "$NATIVE_ARGV_CAPTURE"; }\n'
                            f"{name}() {{\n{body}\n}}\n{name}\n"
                        )
                        result = subprocess.run(
                            [str(BASH), "-c", script],
                            cwd=home,
                            env={
                                "HOME": str(home),
                                "PATH": SYSTEM_PATH,
                                "PROJECT_ROOT": str(root),
                                "CARGO_BIN_DIR": str(cargo_bin),
                                "DRY_RUN": str(dry_run).lower(),
                                "FULL": str(full).lower(),
                                "INSTALL_NOTEBOOK": str(full).lower(),
                                "BUILD_WORKSPACE_TOOLS": str(full).lower(),
                                "INSTALL_LOCAL_BINS": "true",
                                "NATIVE_ARGV_CAPTURE": str(capture),
                            },
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=10,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 0, self.combined_output(result))
                        expected = [
                            str(root / "scripts/install_native_binaries.py"),
                            "--repo-root", str(root), "--bin-dir",
                            str(cargo_bin if name == "refresh_cargo_bin_binaries" else home / ".local/bin"),
                        ]
                        if name == "install_local_binaries":
                            expected.append("--include-c")
                        if dry_run:
                            expected.append("--dry-run")
                        if full:
                            expected.append("--include-notebook")
                            expected.append("--include-workspace-tools")
                        self.assertEqual(
                            capture.read_bytes(),
                            b"".join(argument.encode() + b"\0" for argument in expected),
                        )
                        self.assertFalse(root.exists())
                        self.assertFalse(cargo_bin.exists())
                        self.assertFalse((home / ".local").exists())

    def test_editor_setup_dispatch_is_default_optional_and_forwards_read_only_modes(self) -> None:
        source = SETUP.read_text(encoding="utf-8")
        body = source.split("\ninstall_editor_support() {\n", 1)[1].split("\n}\n", 1)[0]
        for enabled, check, dry_run, failure in ((True, False, False, False), (True, True, False, False), (True, False, True, False), (False, False, False, False), (True, False, False, True)):
            with self.subTest(enabled=enabled, check=check, dry_run=dry_run, failure=failure), tempfile.TemporaryDirectory(prefix="editor setup test ") as directory:
                home = Path(directory)
                root = home / "source with spaces"
                capture = home / "arguments"
                script = (
                    "set -euo pipefail\n"
                    "has_cmd() { return 0; }\n"
                    'python3() { printf "%s\\0" "$@" > "$EDITOR_ARGV_CAPTURE"; return "$EDITOR_FAKE_EXIT"; }\n'
                    f"install_editor_support() {{\n{body}\n}}\ninstall_editor_support\n"
                )
                result = subprocess.run([str(BASH), "-c", script], cwd=home, env={
                    "HOME": str(home), "PATH": SYSTEM_PATH, "PROJECT_ROOT": str(root),
                    "INSTALL_EDITOR_SUPPORT": str(enabled).lower(), "CHECK_ONLY": str(check).lower(), "DRY_RUN": str(dry_run).lower(),
                    "EDITOR_ARGV_CAPTURE": str(capture), "EDITOR_FAKE_EXIT": "7" if failure else "0",
                }, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, self.combined_output(result))
                if enabled:
                    expected = [str(root / "tools/syntax/install.py"), "--auto"]
                    if check:
                        expected.append("--check")
                    elif dry_run:
                        expected.append("--dry-run")
                    self.assertEqual(capture.read_bytes(), b"".join(value.encode() + b"\0" for value in expected))
                else:
                    self.assertFalse(capture.exists())
                if failure:
                    self.assertIn("Setup will continue", result.stderr)
                self.assertFalse(root.exists())

    def test_editor_support_opt_out_aliases_and_default_dry_run_do_not_change_home(self) -> None:
        for option in (None, "--no-editor-support", "--no-syntax"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                arguments = ["--minimal", "--yes", "--dry-run", "--deps-only", "--no-env"]
                if option:
                    arguments.append(option)
                result = self.run_setup(*arguments, home=home)
                self.assertEqual(result.returncode, 0, self.combined_output(result))
                self.assertIn(f"editor_support={'false' if option else 'true'}", result.stdout)
                self.assertIn("Editor syntax support skipped" if option else "Setting up syntax support for available editors", result.stdout)
                self.assertFalse((home / ".nanorc").exists())
                self.assertFalse((home / ".zshrc").exists())
                self.assertFalse((home / ".vim").exists())
                self.assertFalse((home / ".config").exists())
                self.assertFalse((home / "data").exists())

    def run_setup(
        self,
        *arguments: str,
        home: Path,
        platform: str = "linux",
        distro: str = "debian",
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "HOME": str(home),
            "PATH": SYSTEM_PATH,
            "LANG": "C",
            "LC_ALL": "C",
            "SHELL": str(BASH),
            "TMPDIR": str(home),
            "CARGO_HOME": str(home / "cargo"),
            "XDG_DATA_HOME": str(home / "data"),
            "OSTADIX_ENV_FILE": str(home / "config" / "env.sh"),
            "OSTADIX_GUESTS_DIR": str(home / "guests"),
            "OSTADIX_SHELL_RC": str(home / "shellrc"),
            "OSTADIX_SETUP_PLATFORM": platform,
            "OSTADIX_SETUP_DISTRO": distro,
            "OSTADIX_SETUP_TEST_OVERRIDES": "1",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [str(BASH), str(SETUP), *arguments],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    @staticmethod
    def combined_output(result: subprocess.CompletedProcess[str]) -> str:
        return result.stdout + result.stderr

    @staticmethod
    def dry_run_packages(output: str, command: str) -> list[str]:
        line = next(
            candidate
            for candidate in output.splitlines()
            if candidate.startswith("[DRY]") and command in candidate
        )
        words = shlex.split(line)
        marker = words.index("--no-install-recommends")
        return words[marker + 1 :]

    def test_unknown_option_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup("--not-a-real-option", home=Path(temp_dir))

        self.assertEqual(result.returncode, 2, self.combined_output(result))
        self.assertIn("Unknown option: --not-a-real-option", result.stderr)

    def test_platform_override_is_rejected_without_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup("--deps-only", home=Path(temp_dir))

        self.assertEqual(result.returncode, 2, self.combined_output(result))
        self.assertIn("test-only and require --dry-run", result.stderr)

    def test_unmanaged_env_target_fails_before_package_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            env_file = home / "unmanaged.sh"
            env_file.write_text("export USER_DATA=keep\n", encoding="utf-8")
            result = self.run_setup(
                "--dry-run",
                "--deps-only",
                "--env-file",
                str(env_file),
                home=home,
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertIn("refusing to overwrite unmanaged environment file", output)
        self.assertNotIn("apt-get", output)

    def test_minimal_and_full_conflict_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup("--minimal", "--full", home=Path(temp_dir))

        self.assertEqual(result.returncode, 2, self.combined_output(result))
        self.assertIn("--minimal and --full are mutually exclusive", result.stdout)

    def test_full_macos_plan_has_ocore_and_nix_but_not_guest_lab(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--full",
                "--yes",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
                platform="macos",
                distro="unknown",
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        brew_line = next(
            line
            for line in output.splitlines()
            if line.startswith("[DRY]") and "brew install --quiet" in line
        )
        brew_words = shlex.split(brew_line)
        quiet_index = brew_words.index("--quiet")
        self.assertEqual(
            brew_words[quiet_index + 1 :],
            [
                "gcc",
                "make",
                "python@3.12",
                "curl",
                "git",
                "pkg-config",
                "openssl",
                "sqlite",
                "racket",
                "llvm",
                "lld",
                "binutils",
                "qemu",
                "cmake",
                "node", "ruby", "ghc", "ocaml", "sbcl", "mono", "wabt", "wasmtime", "openjdk",
            ],
        )
        self.assertIn("nix=true", output)
        self.assertIn("ocore=true", output)
        self.assertIn("guest_tools=false", output)
        self.assertIn("ubuntu_vm=false", output)
        self.assertNotIn("Guest lab directory:", output)
        self.assertNotIn("multipass", output.lower())

    def test_debian_composed_native_kernel_guest_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-ocore",
                "--with-linux-kernel-tools",
                "--with-guest-tools",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        self.assertEqual(
            self.dry_run_packages(output, "apt-get install"),
            [
                "build-essential",
                "gcc",
                "g++",
                "make",
                "python3",
                "python3-pip",
                "python3-venv",
                "curl",
                "git",
                "pkg-config",
                "libssl-dev",
                "sqlite3",
                "ca-certificates",
                "perl",
                "file",
                "clang",
                "lld",
                "llvm",
                "binutils",
                "qemu-system-x86",
                "qemu-system-arm",
                "cmake",
                "nodejs", "npm", "ruby", "racket", "ghc", "ocaml", "sbcl", "mono-devel", "octave", "wabt", "default-jdk-headless", "python3-matplotlib",
                "qemu-efi-aarch64",
                "qemu-utils",
                "gzip",
                "xz-utils",
                "zstd",
                "xorriso",
                "cpio",
                "squashfs-tools",
                "openssl",
                "bc",
                "bison",
                "flex",
                "libelf-dev",
                "dwarves",
                "rsync",
                "kmod",
                "libncurses-dev",
            ],
        )
        self.assertIn("ocore=true", output)
        self.assertIn("linux_kernel_tools=true", output)
        self.assertIn("guest_tools=true", output)
        self.assertNotIn("multipass", output.lower())

    def test_fedora_guest_tools_dry_run_requires_manual_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-guest-tools",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
                platform="linux",
                distro="fedora",
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 2, output)
        self.assertIn(
            "automatic --with-guest-tools installation is validated only for "
            "macOS/Homebrew and Debian-family Linux hosts",
            output,
        )
        self.assertIn("then use --with-guest-tools --check", output)
        self.assertNotIn("dnf install", output)

    def test_windows_ubuntu_vm_plan_remains_independent_of_guest_lab(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-ubuntu-vm",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
                platform="windows",
                distro="unknown",
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("winget install --id Canonical.Multipass", output)
        self.assertNotIn("SoftwareFreedomConservancy.QEMU", output)
        self.assertIn("guest_tools=false", output)
        self.assertIn("ubuntu_vm=true", output)

    def test_dry_run_does_not_create_env_hook_or_guest_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            env_file = home / "nested" / "ostadix-env.sh"
            shell_rc = home / "custom-shell.rc"
            guests_dir = home / "guest-media"
            result = self.run_setup(
                "--with-guest-tools",
                "--persist-env",
                "--dry-run",
                "--deps-only",
                "--env-file",
                str(env_file),
                home=home,
                extra_env={
                    "OSTADIX_SHELL_RC": str(shell_rc),
                    "OSTADIX_GUESTS_DIR": str(guests_dir),
                },
            )
            output = self.combined_output(result)
            self.assertEqual(result.returncode, 0, output)
            self.assertIn(f"[DRY] write managed environment file: {env_file}", output)
            self.assertIn(f"[DRY] append managed environment hook to {shell_rc}", output)
            self.assertIn(f"[DRY] mkdir -p {guests_dir}", output)
            self.assertFalse(env_file.exists())
            self.assertFalse(shell_rc.exists())
            self.assertFalse(guests_dir.exists())
            self.assertEqual(list(home.iterdir()), [])

    def test_dry_run_makes_gemini_registration_device_conditional(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--minimal", "--yes", "--dry-run", "--no-env",
                home=Path(temp_dir),
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("/.gemini exists, register ostadix", output)

    def test_guest_plan_states_explicit_nonclaim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-guest-tools",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(
            "Pinned Alpine/FreeBSD/9front/Guix/Redox media is fetched only by an explicit lab command.",
            output,
        )
        self.assertIn("Supply any additional foreign media explicitly.", output)
        self.assertIn(
            "No foreign OS image is downloaded or booted by setup.sh.",
            output,
        )
        self.assertIn(
            "These host-side boots do not establish foreign-kernel support in O-core.",
            output,
        )

    def test_help_lists_profile_and_safety_options(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup("--help", home=Path(temp_dir))

        self.assertEqual(result.returncode, 0, self.combined_output(result))
        for option in (
            "--minimal",
            "--full",
            "--with-nix",
            "--no-nix",
            "--with-ocore",
            "--with-ocore-media",
            "--with-hosted-runtimes",
            "--with-linux-kernel-tools",
            "--with-guest-tools",
            "--with-ubuntu-vm",
            "--verify-ocore",
            "--check",
            "--deps-only",
            "--env-file PATH",
            "--no-env",
            "--persist-env",
            "--dry-run",
        ):
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)

    def test_macos_ocore_media_profile_is_explicit_and_composable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-ocore-media",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
                platform="macos",
                distro="unknown",
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        brew_line = next(
            line
            for line in output.splitlines()
            if line.startswith("[DRY]") and "brew install --quiet" in line
        )
        packages = shlex.split(brew_line)
        self.assertIn("x86_64-elf-grub", packages)
        self.assertIn("mtools", packages)
        self.assertIn("xorriso", packages)
        self.assertIn("qemu", packages)
        self.assertIn("ocore=true", output)
        self.assertIn("ocore_media=true", output)

    def test_debian_ocore_media_profile_has_firmware_and_fat_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--with-ocore-media",
                "--dry-run",
                "--deps-only",
                "--no-env",
                home=Path(temp_dir),
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        packages = self.dry_run_packages(output, "apt-get install")
        self.assertIn("grub-efi-amd64-bin", packages)
        self.assertIn("mtools", packages)
        self.assertIn("ovmf", packages)
        self.assertIn("xorriso", packages)

    def test_ocore_media_check_requires_iso_grub_platform_modules(self) -> None:
        setup = SETUP.read_text(encoding="utf-8")

        self.assertIn('${OSTADIX_GRUB_EFI_DIRECTORY:-}', setup)
        self.assertIn('"GRUB x86_64 EFI platform"', setup)
        for module in ("modinfo.sh", "normal.mod", "multiboot2.mod"):
            with self.subTest(module=module):
                self.assertIn(module, setup)
        self.assertIn("GRUB x86_64 EFI/rescue modules, mtools, xorriso, and OVMF", setup)
        self.assertIn("resolve-x86_64-ovmf-code.sh", setup)
        self.assertIn("resolve_ostadix_x86_64_ovmf_code qemu-system-x86_64", setup)

    def test_normal_build_plans_every_public_rust_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            result = self.run_setup(
                "--minimal",
                "--dry-run",
                "--no-env",
                home=home,
            )

            output = self.combined_output(result)
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("cargo build --release --locked", output)
            for binary in (
                "O",
                "o-cli",
                "olangc",
                "ocorec",
                "o-link",
                "o-unlink",
                "ogit",
                "o-live-host",
                "o-node",
                "octl",
                "o-registry",
                "o-info",
                "ostadix-device",
                "ocore-kernel-world-record",
            ):
                with self.subTest(binary=binary):
                    self.assertIn(f"--bin {binary}", output)
                    installed = home / "cargo" / "bin" / binary
                    self.assertIn(f"replace {installed}", output)
            native_device = home / ".local" / "bin" / "ostadix-device"
            self.assertIn(
                f"replace {native_device} from {PROJECT_ROOT / 'target' / 'release' / 'ostadix-device'}",
                output,
            )
            evaluator_alias = home / "cargo" / "bin" / "ostadix-evaluator"
            self.assertIn(
                f"replace {evaluator_alias} from {PROJECT_ROOT / 'target' / 'release' / 'O'}",
                output,
            )
            local_alias = home / ".local" / "bin" / "ostadix-evaluator"
            self.assertIn(
                f"replace {local_alias} from {PROJECT_ROOT / 'target' / 'release' / 'O'}",
                output,
            )

    def test_full_build_selects_the_notebook_target_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_setup("--full", "--dry-run", "--no-env", home=Path(directory))
        self.assertEqual(result.returncode, 0, self.combined_output(result))
        self.assertIn("--features notebook --bin o-notebook", result.stdout)
        self.assertIn("/bin/o-notebook from", result.stdout)

    def test_default_setup_selects_all_root_bins_workspace_and_native_apps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_setup("--dry-run", "--no-env", home=Path(directory))
        self.assertEqual(result.returncode, 0, self.combined_output(result))
        import tomllib
        manifest = tomllib.loads((PROJECT_ROOT / "Cargo.toml").read_text())
        for target in manifest["bin"]:
            self.assertIn(f"--bin {target['name']}", result.stdout)
        self.assertIn("--package ostadix --bins", result.stdout)
        self.assertIn("--features notebook", result.stdout)
        self.assertIn("default-jdk-headless", result.stdout)
        self.assertIn("[DRY]", result.stdout)
        self.assertIn("mobile-console/Cargo.toml", result.stdout)
        self.assertIn("android-terminal/runtime/Cargo.toml", result.stdout)
        self.assertIn("Android platform jar", result.stdout)

    def test_complete_profile_opt_outs_preserve_base_commands_and_report_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_setup("--dry-run", "--no-env", "--no-notebook", "--no-apps", "--no-jni", "--no-hosted-runtimes", "--no-ocore", "--no-nix", home=Path(directory))
        self.assertEqual(result.returncode, 0, self.combined_output(result))
        self.assertNotIn("--features notebook", result.stdout)
        self.assertNotIn("--bin o-notebook", result.stdout)
        self.assertNotIn("mobile-console/Cargo.toml", result.stdout)
        self.assertIn("--bin ocore-kernel-world-record", result.stdout)
        self.assertIn("standalone-apps: disabled", result.stdout)
        self.assertIn("jni-runtime: disabled", result.stdout)
        self.assertNotIn("default-jdk-headless", result.stdout)

    def test_windows_mcp_native_copy_keeps_exe_suffix(self) -> None:
        source = SETUP.read_text()
        body = source.split("\nbuild_mcp_server() {\n", 1)[1].split("\n}\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / "source with spaces"
            mcp = root / "mcp/ostadix_lang_mcp_server"
            (mcp / "target/release").mkdir(parents=True)
            (mcp / "Cargo.toml").write_text('[package]\nname="fixture"\n')
            binary = mcp / "target/release/ostadix-mcp.exe"
            binary.write_bytes(b"MZ test native MCP")
            (root / "scripts").mkdir()
            (root / "scripts/ostadix_mcp_client.py").write_text("#!/usr/bin/env python3\n")
            script = 'set -euo pipefail\nrun_cmd() { :; }\nremove_managed_file() { rm -f "$1"; }\nhas_cmd() { return 0; }\n' + f"build_mcp_server() {{\n{body}\n}}\nbuild_mcp_server\n"
            result = subprocess.run([str(BASH), "-c", script], env={"HOME": str(home), "PATH": SYSTEM_PATH, "PROJECT_ROOT": str(root), "PLATFORM": "windows", "INSTALL_MCP": "true", "INSTALL_LOCAL_BINS": "true", "DRY_RUN": "false"}, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, self.combined_output(result))
            self.assertEqual((home / ".local/bin/ostadix-mcp.exe").read_bytes(), binary.read_bytes())
            self.assertFalse((home / ".local/bin/ostadix-mcp").exists())

    def test_managed_env_activates_later_created_python_and_preserves_custom_interpreters(self) -> None:
        source = SETUP.read_text()
        body = source.split("\nrender_environment_file() {\n", 1)[1].split("\nwrite_environment_file() {", 1)[0].rsplit("\n}", 1)[0]
        with tempfile.TemporaryDirectory(prefix="python environment test ") as directory:
            home = Path(directory)
            python_env = home / "managed Python"
            profile = home / "env.sh"
            script = f"render_environment_file() {{\n{body}\n}}\nrender_environment_file\n"
            env = {"HOME": str(home), "PATH": SYSTEM_PATH, "PROJECT_ROOT": str(home / "source"), "GUESTS_DIR": str(home / "guests"), "PYTHON_ENV": str(python_env)}
            rendered = subprocess.run([str(BASH), "-c", script], env=env, text=True, capture_output=True, check=True)
            profile.write_text(rendered.stdout)
            # Setup writes the env first and builds the virtual environment later.
            (python_env / "bin").mkdir(parents=True)
            for name in ("python", "python3"):
                path = python_env / "bin" / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            custom = home / "custom Python/bin"
            custom.mkdir(parents=True)
            executable = custom / "python3"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            for mode in ("default", "home-custom", "virtualenv", "conda"):
                with self.subTest(mode=mode):
                    active_env = dict(env)
                    if mode != "default":
                        active_env["PATH"] = str(custom) + ":" + SYSTEM_PATH
                    if mode == "virtualenv":
                        active_env["VIRTUAL_ENV"] = str(custom.parent)
                    if mode == "conda":
                        active_env["CONDA_PREFIX"] = str(custom.parent)
                    result = subprocess.run([str(BASH), "-c", f"source {shlex.quote(str(profile))}\ncommand -v python3"], env=active_env, text=True, capture_output=True, check=True)
                    expected = python_env / "bin/python3" if mode == "default" else executable
                    self.assertEqual(result.stdout.strip(), str(expected))

    def test_native_install_opt_out_and_legacy_alias_have_the_same_scope(self) -> None:
        for option in ("--no-local-bins", "--no-wrappers"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                result = self.run_setup("--minimal", "--dry-run", "--no-env", option, home=Path(directory))
                self.assertEqual(result.returncode, 0, self.combined_output(result))
                self.assertNotIn(f"replace {Path(directory) / '.local/bin/o-cli'}", result.stdout)
                self.assertIn(f"replace {Path(directory) / 'cargo/bin/o-cli'}", result.stdout)

    def test_verify_preflights_installed_hosted_v2_command_surfaces_in_temp_state(self) -> None:
        setup = SETUP.read_text(encoding="utf-8")

        self.assertIn('"$CARGO_BIN_DIR/o-node" serve --help', setup)
        self.assertIn('"$CARGO_BIN_DIR/octl" node session --help', setup)
        self.assertIn("ostadix-hosted-verify.XXXXXX", setup)
        self.assertIn('"$CARGO_BIN_DIR/o-node" pki init', setup)
        self.assertIn('"$CARGO_BIN_DIR/o-node" identity init', setup)
        self.assertIn('"$CARGO_BIN_DIR/octl" node session principal', setup)
        self.assertIn("trap 'rm -rf -- \"$hosted_verify_dir\"' EXIT HUP INT TERM", setup)

    def test_python_setup_is_repository_local_and_never_runs_pip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_setup(
                "--minimal",
                "--dry-run",
                "--no-env",
                home=Path(temp_dir),
            )

        output = self.combined_output(result)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("repository-local o_lang package", output)
        self.assertNotIn("pip install", output)

    def test_python_reference_version_matches_rust_package(self) -> None:
        cargo_toml = (PROJECT_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        package_version = next(
            line.split("=", 1)[1].strip().strip('"')
            for line in cargo_toml.splitlines()
            if line.startswith("version")
        )
        python_version = next(
            line.split("=", 1)[1].strip().strip('"')
            for line in (PROJECT_ROOT / "o_lang" / "__init__.py")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.startswith("__version__")
        )
        self.assertEqual(python_version, package_version)

    def test_platform_entrypoints_are_thin_canonical_delegates(self) -> None:
        scripts = sorted((PROJECT_ROOT / "setup" / "os").glob("setup-*.sh"))
        self.assertEqual(len(scripts), 12)
        for script in scripts:
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                self.assertIn('exec "$SCRIPT_DIR/../../setup.sh" "$@"', text)
                self.assertNotIn("cargo build", text)
                self.assertNotIn("pip install", text)


if __name__ == "__main__":
    unittest.main()
