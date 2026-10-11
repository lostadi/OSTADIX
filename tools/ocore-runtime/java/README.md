# Full OpenJDK and compiler-method lowering

The retained target is upstream OpenJDK 25.0.4.1, commit
`7b65d74bcbd7c3a0b4c1f5c5bd85e64aa2e51b4a`, with full HotSpot server,
JNI, garbage collectors, C1/C2, JDK modules and their declared dependencies.
Execution is required on native OSTADIX for x86-64, AArch64 and RV64GC.
The Java compiler implementation additionally requires every concrete method
body in verified O-core IR before execution. Classfile packaging, native VM
compilation and method inventory do not satisfy that lowering requirement.

`openjdk.recipe.json` uses the shared source-capture runner and LLVM 22.1.6.
It captures a hosted source build as frontend evidence. It requires a complete
build-generated native-unit inventory; the named units are an essential floor.
The post-configure profile check rejects filtered C1/C2, GC and related features,
headless trimming, and supplied prebuilt module/class/library imports. A real
boot JDK is a declared build-time requirement. OSTADIX OS services, compiled
library closure and genuine managed-code lowering remain explicit requirements.

For a source capture, select an explicit complete bootstrap SDK in
`OCORE_BOOT_JDK` and the pinned LLVM binaries in `OCORE_LLVM22_BIN`.
The original upstream configuration accepts boot JDK 24 or 25. The scoped
configure helper requires `javac`, `jar`, `jmod`, `jlink`, the module image and
`ct.sym`; a JRE cannot satisfy that requirement. It records their hashes, uses
the capture compiler wrappers, and serializes linker invocations. Optional
`OCORE_OPENJDK_DEPS_ROOT` supplies privately extracted Autoconf and full desktop
development dependencies without installing them globally.

```bash
export OCORE_BOOT_JDK=/path/to/qualified/boot-jdk
export OCORE_LLVM22_BIN=/path/to/LLVM-22.1.6/bin
export OCORE_OPENJDK_DEPS_ROOT=/path/to/scoped/build-dependencies
python3 scripts/ocore_runtime_capture.py capture \
  tools/ocore-runtime/java/openjdk.recipe.json \
  --source /path/to/pinned/openjdk-source \
  --build /path/to/new/build --output /path/to/new/capture --jobs 2 \
  --cc "$OCORE_LLVM22_BIN/clang" --cxx "$OCORE_LLVM22_BIN/clang++" \
  --llvm-nm "$OCORE_LLVM22_BIN/llvm-nm" \
  --unit-inventory /path/to/full/build-generated/role-inventory.json
```

The recipe requests the full upstream `compile-commands` graph and `images`,
retaining `compile_commands.json` and the resulting `images/jdk` tree.
The configured graph alone does not establish the complete role inventory or
library closure: configure probes, host tools, runtime libraries, generated
sources, compiler bodies and native output membership require explicit evidence.
Missing inventory, failed required units and unaccounted dependencies keep
capture admission incomplete. Bootstrap tools and supplied development packages
are hosted prerequisites, with their runtime implementations still requiring
their own source capture and lowering. Building javac class files supplies
original compiler bytes for the managed-method inventory; it does not lower
those bodies into O-core.

## Original compiler-method inventory

Read classes, class directories, JARs or JMODs without executing their methods:

```bash
python3 scripts/ocore_java_inventory.py inventory \
  --input jdk.compiler=/path/to/jmods/jdk.compiler.jmod \
  --output /tmp/jdk.compiler.inventory.json
```

This single-module scan reports missing declared dependency modules. Complete
method coverage requires those modules too, including declared static requires.
Multi-release JAR selection follows the requested Java feature and its manifest.
Class files are structurally parsed with bounded binary reads, JVM modified
UTF-8, constant-pool references, method descriptors, Code attributes, exception
ranges and module descriptors. This reader does not replace the JVM verifier.

The installed pinned JRE can provide a measured module closure through its
standard `jrt:/` filesystem even when standalone JDK tools are absent:

```bash
python3 scripts/ocore_java_inventory.py runtime-image \
  --java /usr/lib/jvm/java-25-openjdk-amd64/bin/java \
  --output-dir /tmp/javac-original-classes \
  --output /tmp/javac-original-inventory.json
```

`ExtractRuntimeImage.java` is a host inventory helper run by the original Java
source launcher. It includes all declared requires, records the actual image,
Java executable and helper hashes, and refuses a nonempty output directory.
Use `--all-modules` to inventory the full installed JDK module image. Installed
Ubuntu class bytes are a measured baseline; rebuilding pinned upstream source
must produce its own inventory and hashes.

The checked-in measurement records five javac dependency modules, 9,260 classes,
76,662 bytecode bodies, 699 native declarations and 5,068 abstract declarations.
`jdk.compiler` alone contains 13,475 bodies. These counts establish an original
implementation inventory; the measurement records zero lowered compiler methods.

## Exact verified body coverage

```bash
python3 scripts/ocore_java_inventory.py compare \
  --inventory /tmp/javac-original-inventory.json \
  --native-module /path/to/compiler.native.json \
  --native-module /path/to/native-providers.native.json \
  --native-bindings /path/to/native-bindings.json \
  --verifier /path/to/current/ocorec \
  --output /tmp/javac-method-coverage.json
```

The command recomputes original inputs to reject stale or shrunk inventories.
It invokes `ocorec MODULE --verify-native --receipt FILE` on an immutable copy of
each module and requires a fresh SHA-256-bound structural-verification receipt.
Self-reported `verified: true` fields do not count. Compare each target layout
separately; multiple target realizations cannot hide missing target coverage.

Every Code-bearing method, including private, synthetic, bridge, lambda,
constructor, initializer, interface default and cold bodies, needs an exact
`managed_method` identity on a concrete verified NativeModule function:

```json
{
  "module": "jdk.compiler",
  "loader_namespace": "boot",
  "class_name": "com/sun/tools/javac/main/JavaCompiler",
  "method_name": "compile",
  "descriptor": "()V",
  "class_sha256": "<SHA-256 of the entire original class file>",
  "code_sha256": "<SHA-256 of the original Code bytecode array>"
}
```

This illustrative descriptor is not an assertion about an upstream signature.
The class hash binds exception tables, stack maps and other original metadata.
Declarations, duplicate definitions, missing bodies, changed hashes and unexpected
methods fail. Native/abstract records have an empty Code hash; they cannot be
misrepresented as bytecode bodies. Native bindings use a separate manifest:

```json
{
  "format": "ocore-java-method-exports-v1",
  "native_bindings": [
    {
      "method": "<the complete original native method identity object>",
      "provider_module_sha256": "<included verified module SHA-256>",
      "provider_symbol": "Java_example_nativeMethod"
    }
  ]
}
```

Every native binding needs an actual definition in an included verified module.
Abstract declarations retain dispatch information without fabricated bodies.
An exact body inventory receipt is structural evidence: it does not establish
that the translated method faithfully implements its bytecode, that ordinary
native linkage is closed, or that Java runs on OSTADIX. Semantic equivalence,
closed linkage, managed metadata and native execution remain separate gates.

Authentic class/method hashes can be attached to an unrelated return-only native
body. The permanent actual-verifier counterexample confirms that this still has
inventory coverage while semantic equivalence and runtime completion remain
false. Current structural verification does not connect a Java descriptor to a
managed calling convention or establish derivation from the original bytecode.

Admission must separately bind the pinned original source/profile inventory,
trusted exporter and verifier identities, and the bytecode/C1 translation to an
explicit managed ABI. That ABI needs receiver, reference and dispatch contracts,
class initialization, Java exceptions, GC roots, safepoints and deoptimization.
JNI providers need their own ABI/behavior checks. Original compiler execution
and cross-ISA semantic tests then qualify the implementation. Caller-selected
inventory inputs and verifier executables are trust anchors; hashing them records
their identity without proving their authenticity.

## Prepared upstream C1 hook

`c1-exporter-hook.patch` applies to the pinned `c1_Compilation.cpp/.hpp` and adds
the abstract `OcoreC1ExportSink` interface. It has been checked against those exact
upstream files with `git apply --check`. The optional constructor sink receives
the existing C1 HIR immediately after `build_hir()` and its bailout check, before
`FrameMap`, register allocation and ISA encoding. Offline export requires
`install_code=false`; failures use the existing bailout path. Existing compiler
algorithms and the default C1 call path are retained.

The patch is prepared and is not applied to or built as an upstream JVM here.
No semantic sink implementation, all-method build-time driver, C2 exporter,
runtime-stub exporter or JIT publication adapter is provided by this hook.
There is no fallback that counts PrintIR dumps, bytecode wrappers or interpreter
execution as a lowered method. The next implementation must traverse the existing
HIR and emit original method bodies plus shared managed references, safepoints,
GC roots, exception/monitor behavior, symbolic class initialization/resolution,
deoptimization/OSR state and exact source identities into verified O-core modules.

Class initialization and dynamic bootstrap methods execute at their original
runtime points. Retained reflection data, defining-loader identities, dynamic
loading, JNI callbacks and optimized-code invalidation must continue to work.
The same complete frontend and verifier must also admit newly loaded/generated
methods; C1/C2 and every interpreter/stub generator must ultimately publish only
accounted O-core realizations on all three targets.
