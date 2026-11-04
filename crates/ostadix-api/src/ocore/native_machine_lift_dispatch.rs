//! Selected syntax -> architecture semantics. This instruction-level seam is not
//! whole-unit admission: the caller must retain every selected record, resolve
//! all blocks/data/relocations/CFI, verify the complete unit and realize its ABI.
use super::native_machine_asm_reader::{ParsedAssembly,Opcode,Syntax,SyntaxKind};
use super::native_machine_ir::Architecture;
use super::native_machine_lift::{BlockLifter,LiftError,LiftFlow};

pub fn lift_instruction(parsed:&ParsedAssembly,index:usize,b:&mut BlockLifter<'_>) -> Result<LiftFlow,LiftError> {
    if parsed.profile!=*b.profile() {
        return Err(b.fail("semantic builder differs from selected assembly profile"));
    }
    let record=parsed.records.get(index).ok_or_else(||b.fail("selected syntax record is absent"))?;
    if record.required.id!=b.source_item() || record.required.kind!=SyntaxKind::Instruction {
        return Err(b.fail("semantic site differs from independently selected instruction record"));
    }
    let Syntax::Instruction {opcode,operands}=&record.syntax else {
        return Err(b.fail("selected instruction has no parsed instruction semantics"));
    };
    let start=usize::try_from(record.required.span.start).map_err(|_|b.fail("source span exceeds host index"))?;
    let end=usize::try_from(record.required.span.end).map_err(|_|b.fail("source span exceeds host index"))?;
    let raw=parsed.original.get(start..end).ok_or_else(||b.fail("instruction span exceeds consumed source"))?;
    let text=std::str::from_utf8(raw).map_err(|_|b.fail("instruction spelling is not UTF-8"))?;
    let spelling=text.split_whitespace().next().ok_or_else(||b.fail("instruction spelling is empty"))?;
    // Raw spelling is retained: e.g. ADD and ADDS must not collapse into the
    // same flags behavior merely because the syntax opcode shares a family.
    match (b.profile().architecture,*opcode) {
        (Architecture::X86_64,Opcode::X86 {operation,width})=>
            super::native_machine_lift_x86_64::lower_x86(operation,width,spelling,operands,b),
        (Architecture::Aarch64,Opcode::Aarch64(operation))=>
            super::native_machine_lift_aarch64::lower_aarch64(operation,spelling,operands,b),
        (Architecture::Rv64,Opcode::Riscv(operation))=>
            super::native_machine_lift_rv64::lower_rv64(operation,spelling,operands,b),
        _=>Err(b.fail("instruction opcode bank differs from selected canonical architecture")),
    }
}
