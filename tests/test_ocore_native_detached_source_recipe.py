"""Real detached compiler/embedded-producer contracts, not runtime acceptance.

The C/Rust sources here are explicitly authored producer fixtures. They cannot
qualify CPython, rustc/std, a language engine, provider closure or an ISA matrix.
The compiler must first pass the isolated build/artifact provenance gate.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import test_ocore_native_source_recipe as original

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class DetachedNativeSourceRecipeTests(original.NativeSourceRecipeTests):
    @classmethod
    def setUpClass(cls):
        receipt_path = os.environ.get("OCORE_TEST_ISOLATED_BUILD_RECEIPT")
        if not receipt_path:
            raise RuntimeError("an actually qualified isolated compiler build receipt is required")
        cls.build_receipt = json.loads(Path(receipt_path).read_text())
        if not cls.build_receipt.get("compiler_build_qualified"):
            raise RuntimeError("unqualified/cached compiler artifacts cannot run this required suite")
        cls.detached = Path(tempfile.mkdtemp(prefix="ostadix-detached-compiler-v5-"))
        binary_dir = cls.detached / "target/debug"
        binary_dir.mkdir(parents=True)
        cls.binary_pins = {}
        for name in ("olangc", "ocorec"):
            record = cls.build_receipt["binaries"][name]
            if record.get("fresh") is not False:
                raise RuntimeError("the compiler must be freshly built in the isolated target")
            pin = record["copied_executable"]
            source = Path(pin["path"])
            if digest(source) != pin["sha256"]:
                raise RuntimeError("compiled binary identity changed before detached copy")
            destination = binary_dir / name
            shutil.copy2(source, destination)
            if digest(destination) != pin["sha256"] or digest(source) != pin["sha256"]:
                raise RuntimeError("detached compiler copy differs from actual built artifact")
            cls.binary_pins[destination] = pin["sha256"]
        cls.asset_pins = {}
        for key, rel in (
            ("capture_worker", "scripts/ocore_runtime_capture.py"),
            ("producer_registry", "scripts/ocore_producer_registry.json"),
            ("rust_payload_helper", "tools/ocore-runtime/rust/payload_inventory.py"),
        ):
            expected = cls.build_receipt["source_before"][rel]
            if digest(SOURCE_ROOT / rel) != expected:
                raise RuntimeError("validation asset source differs from the compiled source")
            cls.asset_pins[key] = expected
        cls.previous_root = original.ROOT
        cls.previous_cwd = Path.cwd()
        original.ROOT = cls.detached
        os.chdir(cls.detached)
        cls.addClassCleanup(setattr, original, "ROOT", cls.previous_root)
        cls.addClassCleanup(os.chdir, cls.previous_cwd)
        # Keep this detached directory/its binaries as evidence, not a cleanup
        # fallback into the repository next to the original compiler.
        super().setUpClass()
        cls.rustc = Path("/home/orangepi/.rustup/toolchains/1.97.1-riscv64gc-unknown-linux-gnu/bin/rustc")
        version = original.run([cls.rustc, "--version"])
        if version.returncode or not version.stdout.startswith("rustc 1.97.1 "):
            raise RuntimeError("actual pinned Rust 1.97.1 producer required")

    def tearDown(self):
        for path, expected in self.binary_pins.items():
            self.assertEqual(digest(path), expected)
        self.assertEqual(Path.cwd(), self.detached)
        self.assertFalse((self.detached / "scripts").exists())
        self.assertFalse((self.detached / "tools").exists())

    def assert_embedded_assets(self, output):
        receipt = json.loads((output / "source-recipe.json").read_text())
        for key, expected in self.asset_pins.items():
            record = receipt[key]
            self.assertEqual(record["sha256"], expected)
            self.assertEqual(digest(record["path"]), expected)
            self.assertTrue(Path(record["path"]).resolve().is_relative_to(output.resolve()))
        self.assertFalse(receipt["runtime_complete"])
        self.assertFalse(receipt["native_execution_qualified"])

    def successful_lowering(self, kind):
        output = super().successful_lowering(kind)
        self.assert_embedded_assets(output)
        return output

    def test_detached_embedded_registry_and_public_module_set_readmission(self):
        output = self.successful_lowering("ir")
        artifact = output / "lowered/runtime.native-ir.json"
        regenerated = self.case / "readmitted"
        result = original.run([
            self.olangc, artifact, "--native-runtime", "--native-isa", self.target,
            "--native-runtime-output", "obj", "-o", regenerated,
        ])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        coverage = json.loads((regenerated / "coverage.json").read_text())
        self.assertTrue(coverage["module_set_complete"])
        self.assertFalse(coverage["runtime_complete"])
        self.assertFalse(coverage["native_execution_qualified"])
        self.assertEqual(len(list(regenerated.glob("unit-*/module.o"))), 2)
        self.assert_original_source()

    def test_detached_registry_resource_mutation_blocks_original_source_lowering(self):
        self.recipe["commands"].append({
            "name": "adversarial-compiled-registry-resource-mutation",
            "argv": [sys.executable, "-c",
                     "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b' ')",
                     "{build}/../driver/scripts/ocore_producer_registry.json"],
        })
        self.write_recipe()
        diagnostic = self.capture_failure()
        self.assertIn("embedded capture implementation changed", diagnostic)
        self.assertFalse((self.case / "compiled/lowered/runtime.native-ir.json").exists())

    def test_detached_original_rust_producer_fixture_uses_owned_import(self):
        # A complete, explicitly authored no_std producer fixture. This does
        # not replace or qualify any original Rust compiler/runtime sources.
        (self.source / "runtime.rs").write_text(
            '#![no_std]\n#[no_mangle]\npub extern "C" fn rust_engine_add(a:u64,b:u64)->u64 { a.wrapping_add(b) }\n')
        (self.source / "cold.rs").write_text(
            '#![no_std]\n#[no_mangle]\npub extern "C" fn rust_cold_path(a:i32)->i32 { a.wrapping_sub(7) }\n')
        inventory = (original.INVENTORY_SOURCE.replace('".c"', '".rs"')
                     .replace('".o"', '".rlib"').replace('"kind":"clang"', '"kind":"rustc"'))
        (self.source / "inventory.py").write_text(inventory)
        (self.source / "Makefile").write_text(
            "SOURCES := runtime.rs cold.rs\n"
            "OBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:.rs=.rlib))\n"
            ".PHONY: all list-sources\nall: $(OBJECTS)\n"
            "$(BUILDDIR)/%.rlib: $(SOURCE)/%.rs\n"
            "\t$(RUSTC) --crate-name $* --crate-type rlib --edition=2021 --emit=link -Cembed-bitcode=yes -Ccodegen-units=1 -Cpanic=abort -Cdebuginfo=0 -Copt-level=0 $< -o $@\n"
            "list-sources:\n\t@printf '%s\\n' $(SOURCES)\n")
        for argv in (
            ["git", "add", "runtime.rs", "cold.rs", "inventory.py", "Makefile"],
            ["git", "-c", "user.name=Lee Daghlar Ostadi", "-c", "user.email=ostadi.lee@gmail.com",
             "commit", "-qm", "complete authored Rust producer fixture"],
        ):
            result = original.run(argv, cwd=self.source)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.recipe["name"] = "detached-authored-rust-producer-contract-fixture"
        self.recipe["source"]["revision"] = original.run(
            ["git", "rev-parse", "HEAD"], cwd=self.source).stdout.strip()
        # The registered direct-rustc adapter follows Cargo's wrapper protocol:
        # the original pinned frontend is its first argument. An actual rustc
        # command alone deliberately bypasses capture and must be rejected.
        self.recipe["commands"][0]["argv"].append("RUSTC={rustc_wrapper} {rustc}")
        self.recipe["toolchain"]["rust_capture_policy"] = "rust-embedded-bc-v1"
        # On this pinned upstream Rust, --emit=obj does not embed bitcode even
        # with -Cembed-bitcode=yes. Original rlib members do; capture must prove
        # the native-output/bitcode edge instead of replaying a replacement TU.
        self.recipe["coverage"]["required_outputs"] = ["runtime.rlib", "cold.rlib"]
        for floor in self.recipe["coverage"]["required_units"]:
            floor["kind"] = "rustc"
            floor["source"] = Path(floor["source"]).with_suffix(".rs").name
        self.original_source = self.source_snapshot()
        self.write_recipe()
        result, output = self.invoke(
            kind="ir", jobs=1,
            extra=("--native-runtime-rustc", self.rustc,
                   "--native-runtime-llvm-dis", self.sdk / "llvm-dis"),
        )
        (self.case / "rust-driver.stdout").write_text(result.stdout)
        (self.case / "rust-driver.stderr").write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_embedded_assets(output)
        coverage = json.loads((output / "lowered/coverage.json").read_text())
        self.assertEqual(coverage["required_lowering_unit_count"], 2)
        self.assertEqual(coverage["lowered_unit_count"], 2)
        self.assertTrue(coverage["module_set_complete"])
        artifact = json.loads((output / "lowered/runtime.native-ir.json").read_text())
        functions = {f["name"] for m in artifact["modules"]
                     for f in json.loads(m["native_ir"])["functions"]}
        self.assertTrue({"rust_engine_add", "rust_cold_path"}.issubset(functions))
        self.assert_original_source()


if __name__ == "__main__":
    unittest.main()
