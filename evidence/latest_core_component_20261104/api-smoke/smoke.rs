use std::{env,fs,path::{Path,PathBuf}};
use o_lang::ocore::{compile,CompileOptions,EmitKind,Target};
fn emit(input: &Path, output: PathBuf, target: Target, kind: EmitKind) {
    let result=compile(&[input.to_path_buf()],&CompileOptions{target,emit:kind,output:output.clone(),keep_assembly:false}).expect("valid core compilation failed");
    assert_eq!(result.output,output);
    assert!(fs::metadata(output).unwrap().len()>0);
}
fn main() {
    let out=PathBuf::from(env::args().nth(1).expect("output directory"));
    fs::create_dir(&out).unwrap();
    let good=out.join("add.oc");
    fs::write(&good,"module smoke::addition;\nfn add(a: i64, b: i64) -> i64 { return a + b; }\n").unwrap();
    for (target,name) in [(Target::X86_64UnknownNone,"x86_64"),(Target::Aarch64UnknownNone,"aarch64"),(Target::Riscv64UnknownNone,"riscv64")] {
        emit(&good,out.join(format!("{}.s",name)),target.clone(),EmitKind::Assembly);
        emit(&good,out.join(format!("{}-object.o",name)),target,EmitKind::Object);
    }
    emit(&good,out.join("add.hir"),Target::Riscv64UnknownNone,EmitKind::Hir);
    emit(&good,out.join("add.mir"),Target::Riscv64UnknownNone,EmitKind::Mir);
    let bad=out.join("bad.oc");
    fs::write(&bad,"module smoke::bad;\nfn bad() -> i64 { return true; }\n").unwrap();
    emit(&bad,out.join("bad.ast"),Target::Riscv64UnknownNone,EmitKind::Ast);
    let rejected=out.join("bad.s");
    assert!(!rejected.exists());
    let error=compile(&[bad],&CompileOptions{target:Target::Riscv64UnknownNone,emit:EmitKind::Assembly,output:rejected.clone(),keep_assembly:false}).expect_err("return type mismatch accepted");
    let text=format!("{:?}",error); let lower=text.to_lowercase();
    assert!(lower.contains("i64") && lower.contains("bool"),"unexpected rejection: {}",text);
    assert!(!rejected.exists());
    fs::write(out.join("expected-type-error.txt"),text).unwrap();
    println!("{{\"success\":true,\"assembly_targets\":3,\"object_targets\":3,\"hir_emitted\":true,\"mir_emitted\":true,\"parse_accepts_type_error\":true,\"type_error_rejected\":true}}");
}
