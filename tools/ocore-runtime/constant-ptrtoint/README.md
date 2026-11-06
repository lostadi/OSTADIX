# Executable constant pointer-to-integer component

`Operand::PointerToInteger` retains a typed constant pointer child in an
executable scalar integer expression. It is not a runtime pointer resolver.
The supported profile has integral AS0 pointers, little-endian 64-bit pointer
and index representations, default address spaces, and scalar integer results
of widths 1 through 64 or 128. Results truncate to their low bits, or extend to
128 bits with a zero high word. Symbol, GEP addend, alias, weak/GOT and code-block
identity remain subject to the ordinary verifier, ABI and dependency checks.

The importer and independent LLVM C API reader retain the original typed child
and exact use position, including aggregate fields, select arms and phi edges.
Primitive inventory checks supplement full fresh-source equality; they do not
replace it. The scalar interpreter and pure `.O` leaf refuse these pointer
operands even when the module has no globals. TLS, symbolic packed-vector
lanes, unknown enclosing constant expressions and unsupported layouts fail
closed. Existing relative32 object initializers keep their separate contract;
this component does not admit absolute integer initializers.

The three `*.a64l.recipe.json` recipes select the complete unchanged musl 1.2.5
`src/misc/a64l.c` unit at revision
`0784374d561435f7c787a555aeab8ede699ed298`. Its original Makefile is evaluated
and invoked for the declared object with original headers. Both `a64l` and
`l64a` definitions are retained, along with the strong `strchr` declaration.
No source body is replaced or filtered, and no captured flags are removed.
This explicit component configuration is distinct from the complete-library
capture. Reference objects are evidence, not owned generated code.

The original source recipe requires separately built tools and the exact pinned
LLVM 22 parser. Its current public group admission must refuse the unresolved
strong `strchr` dependency after the complete unit has been captured/imported;
no closed original source-group artifact is produced. The source compilation
and independently emitted unit object are distinct bounded evidence. A closed
authored fixture tests public fresh-source readmission and coherent forgeries;
it does not turn the unresolved original group into a complete artifact.
For example, the original recipe command below retains that explicit refusal:

```sh
olangc tools/ocore-runtime/constant-ptrtoint/x86_64.a64l.recipe.json \
  --native-runtime --native-isa x86_64-unknown-none \
  --native-runtime-source /absolute/path/to/pinned/musl \
  --native-runtime-output obj --native-runtime-jobs 2 \
  --llvm-library /absolute/path/to/libLLVM.so.22.1 \
  --llvm-sha256 EXPECTED_PARSER_SHA256 -o /absolute/new/output
```

Execution fixtures bind the original reference libc archive supplying `strchr`,
Clang test bootstrap, actual Linux process and foreign-ISA emulator as explicit
external test dependencies. They check both original functions and retained
memory effects, raw return values and defined FP state. These facilities are
not lowered implementation closure. This component does not qualify full libc,
CRT, TLS, Linux kernel services, arbitrary inline assembly, i686/ARMv7, physical
drivers, a complete native OS, or whole-system efficiency. Unsupported original
units and incomplete complete-library captures remain visible.

The separately declared `*.a64l-group.recipe.json` component includes all four
original C units `a64l.c`, `strchr.c`, `strchrnul.c` and `strlen.c`. Its helper
evaluates the same full original Make object graph and invokes those four
original targets. Every definition, declaration and weak alias is retained.
This finite original source group can close its C symbol dependencies without
linking any reference archive into its owned objects. Full fresh-source group
readmission remains distinct from the single-unit refusal above. The reference
execution uses its four original compiler objects; owned execution uses only
the four emitted O-core objects. Both use an explicitly external test bootstrap
and Linux/QEMU-user environment. This does not make full libc/CRT/platform or
whole-runtime closure complete.
