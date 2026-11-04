pub mod ocore {
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/native_interpret.rs"]
 pub mod native_interpret;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/ast.rs"]
 pub mod ast;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/lexer.rs"]
 pub mod lexer;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/hir.rs"]
 pub mod hir;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/mir.rs"]
 pub mod mir;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/parser.rs"]
 pub mod parser;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/typeck.rs"]
 pub mod typeck;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/codegen.rs"]
 pub mod codegen;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/codegen_aarch64.rs"]
 pub mod codegen_aarch64;
 #[path = "/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/codegen_riscv64.rs"]
 pub mod codegen_riscv64;
 #[path = "/tmp/assembly-machine-selected-realization-SOURCE-r2-20261102/overlay/crates/ostadix-api/src/ocore/driver.rs"]
 pub mod driver;
 pub use driver::{compile, compile_with_function_sections, CompileOptions, CompileOutput, EmitKind};
 include!("/tmp/Main-SourceO-assembly-r1-20261101/source/crates/ostadix-api/src/ocore/native_core.rs");
 #[path = "/tmp/ostadix-configured-assembly-unit-bridge-SOURCE-r3-20261101-actionjoin/native_machine_asm_unit.rs"]
 pub mod native_machine_asm_unit;
}
