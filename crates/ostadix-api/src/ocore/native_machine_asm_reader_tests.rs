    use super::*;
    use super::super::native_machine_ir::{CfiPolicy,MachineInputForm,SourceFile,StateFeature};
    // Authored syntax fixtures, NOT upstream GNU inputs or producer acceptance.
    // Explicit record strings/kinds below select the independent synthetic floor;
    // no parser-success enumeration is used to construct it.
    fn fixture(text:&str,a:Architecture,descriptors:&[(&str,SyntaxKind)]) -> (ReadSelection,Vec<u8>,Target) {
        let source=SourceWitness{format:SOURCE_FORMAT.into(),input_form:MachineInputForm::ConfiguredAssemblyText,unit_id:"authored-syntax-fixture".into(),files:vec![SourceFile{id:9,logical_path:"fixture.S".into(),identity:identity(text.as_bytes())}],decoded_assembly:identity(text.as_bytes()),build_configuration:identity(b"authored-config"),frontend_event:identity(b"authored-no-execution-event")};
        let (abi,target)=match a{Architecture::X86_64=>(MachineAbi::SysvAmd64,Target::X86_64UnknownNone),Architecture::Aarch64=>(MachineAbi::Aapcs64,Target::Aarch64UnknownNone),Architecture::Rv64=>(MachineAbi::RiscvLp64d,Target::Riscv64UnknownNone),_=>panic!("fixture requires 64-bit architecture")};
        let profile=MachineProfile{architecture:a,abi,address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:0,features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::NoCfiDeclared};
        let mut cursor=0;let mut records=Vec::new();
        for (i,(needle,kind)) in descriptors.iter().enumerate(){let start=cursor+text[cursor..].find(needle).expect("explicit floor descriptor occurs");let end=start+needle.len();let s=span(start,end);records.push(RequiredRecord{id:100+i as u64,kind:*kind,span:s,origins:vec![OriginalSpan{file:9,span:s}]});cursor=end;}
        let raw=serde_json::to_vec(&SyntaxInventory{format:SYNTAX_INVENTORY_FORMAT.into(),source:source.clone(),profile:profile.clone(),records}).unwrap();
        (ReadSelection{source,profile,inventory:identity(&raw)},raw,target)
    }
    fn read(text:&str,a:Architecture,d:&[(&str,SyntaxKind)])->ParsedAssembly{let(s,r,t)=fixture(text,a,d);read_configured_assembly(text.as_bytes(),&s,&r,t).unwrap()}
    fn refloor(s:&mut ReadSelection,raw:&mut Vec<u8>,f:impl FnOnce(&mut SyntaxInventory)){let mut v:SyntaxInventory=serde_json::from_slice(raw).unwrap();f(&mut v);*raw=serde_json::to_vec(&v).unwrap();s.inventory=identity(raw);}
    #[test]
    fn assembler_register_aliases_are_canonical_and_width_preserving_on_all_three_targets(){
        for(a,left,right,low,bits)in[(Architecture::X86_64,"%ah","%rax",8,8),(Architecture::Aarch64,"w30","lr",0,32),(Architecture::Rv64,"s0","fp",0,64)]{
            let l=register(left,a).unwrap();let r=register(right,a).unwrap();assert_eq!(l.register,r.register);assert_eq!((l.low_bit,l.bits),(low,bits));
        }
        assert_ne!(register("sp",Architecture::Aarch64),register("xzr",Architecture::Aarch64));
        assert_eq!(operand("xzr",Architecture::Aarch64).unwrap(),Operand::ZeroRegister{bits:64});
        assert!(register("x31",Architecture::Aarch64).is_none());assert!(register("x32",Architecture::Rv64).is_none());
    }
    #[test]
    fn assembler_all_three_instruction_address_forms_are_typed_not_lifted(){
        let p=read("movq -010(%rax,%rcx,4),%rdx\n",Architecture::X86_64,&[("movq -010(%rax,%rcx,4),%rdx",SyntaxKind::Instruction)]);
        assert!(p.syntax_supported);
        assert_eq!(p.records[0].syntax,Syntax::Instruction{
            opcode:Opcode::X86{operation:X86Opcode::Move,width:Some(64)},
            operands:vec![Operand::Address(Address::X86{segment:None,displacement:Expression{first:ExprAtom::Integer(-8),rest:vec![]},base:Some(view(PhysicalRegister::X86Gpr{name:X86Gpr::Rax},64)),index:Some(view(PhysicalRegister::X86Gpr{name:X86Gpr::Rcx},64)),scale:4}),Operand::Register(view(PhysicalRegister::X86Gpr{name:X86Gpr::Rdx},64))]});
        let p=read("stp x19,x20,[sp,#-16]!\n",Architecture::Aarch64,&[("stp x19,x20,[sp,#-16]!",SyntaxKind::Instruction)]);
        assert!(p.syntax_supported);
        assert_eq!(p.records[0].syntax,Syntax::Instruction{
            opcode:Opcode::Aarch64(Aarch64Opcode::StorePair),
            operands:vec![Operand::Register(view(PhysicalRegister::Aarch64Gpr{index:19},64)),Operand::Register(view(PhysicalRegister::Aarch64Gpr{index:20},64)),Operand::Address(Address::Aarch64{base:view(PhysicalRegister::Aarch64Sp,64),offset:Some(Expression{first:ExprAtom::Integer(-16),rest:vec![]}),writeback:true})]});
        let p=read("fsd fs0,030(a0)\n",Architecture::Rv64,&[("fsd fs0,030(a0)",SyntaxKind::Instruction)]);
        assert!(p.syntax_supported);
        assert_eq!(p.records[0].syntax,Syntax::Instruction{
            opcode:Opcode::Riscv(RiscvOpcode::StoreFloatDouble),
            operands:vec![Operand::Register(view(PhysicalRegister::RiscvFpr{index:8},64)),Operand::Address(Address::Riscv{base:view(PhysicalRegister::RiscvGpr{index:10},64),displacement:Expression{first:ExprAtom::Integer(24),rest:vec![]}})]});
        assert!(!p.instruction_semantics_lifted);assert!(!p.machine_body_admitted);assert!(!p.provider_qualified);
    }
    #[test]
    fn assembler_lossless_coverage_preserves_quotes_comments_and_inline_labels(){
        let text="/* header */\nentry: movq %rax,%rbx ; .ascii \"a;#b\\n\" # trailing\n";
        let p=read(text,Architecture::X86_64,&[("entry:",SyntaxKind::Label),("movq %rax,%rbx",SyntaxKind::Instruction),(".ascii \"a;#b\\n\"",SyntaxKind::Data)]);
        assert!(p.syntax_supported);assert_eq!(p.original,text.as_bytes());let mut end=0;
        for c in &p.coverage{let s=match c{Coverage::Trivia(s)|Coverage::Record{span:s,..}=>s};assert_eq!(s.start,end);end=s.end;}assert_eq!(end,text.len()as u64);
        assert!(matches!(&p.records[2].syntax,Syntax::Directive(Directive::Strings{values,..})if values==&vec![b"a;#b\n".to_vec()]));
    }
    #[test]
    fn assembler_numeric_labels_resolve_nearest_forward_and_backward_definitions(){
        let text="1: jmp 1f\n1: jmp 1b\n";
        let p=read(text,Architecture::X86_64,&[("1:",SyntaxKind::Label),("jmp 1f",SyntaxKind::Instruction),("1:",SyntaxKind::Label),("jmp 1b",SyntaxKind::Instruction)]);
        assert!(p.syntax_supported);assert_eq!(p.label_uses.iter().map(|u|u.definition).collect::<Vec<_>>(),vec![Some(2),Some(2)]);
        let p=read("j 7f\n",Architecture::Rv64,&[("j 7f",SyntaxKind::Instruction)]);
        assert_eq!(p.label_uses[0].definition,None);assert_eq!(p.problems[0].kind,ProblemKind::UnresolvedNumericLabel);
    }
    #[test]
    fn assembler_cfi_and_cpp_markers_remain_explicit_typed_records(){
        let text="# 42 \"jump.S\" 1 3\n.cfi_startproc\n.cfi_def_cfa 7,8\n.cfi_offset %rbx,-16\n.cfi_endproc\n";
        let p=read(text,Architecture::X86_64,&[("# 42 \"jump.S\" 1 3",SyntaxKind::Preprocessor),(".cfi_startproc",SyntaxKind::Cfi),(".cfi_def_cfa 7,8",SyntaxKind::Cfi),(".cfi_offset %rbx,-16",SyntaxKind::Cfi),(".cfi_endproc",SyntaxKind::Cfi)]);
        assert!(p.syntax_supported);assert!(matches!(&p.records[0].syntax,Syntax::PreprocessorMarker{line:42,flags,..}if flags==&vec![1,3]));
        assert!(matches!(p.records[2].syntax,Syntax::Directive(Directive::Cfi(Cfi::DefCfa{register:RegisterView{register:PhysicalRegister::X86Gpr{name:X86Gpr::Rsp},..},offset:8}))));
        assert!(!p.original_source_authenticated);assert!(!p.selected_floor_authority_authenticated);
    }
    #[test]
    fn assembler_same_consumed_input_and_inventory_identities_are_required(){
        let text="ret\n";let(mut s,r,t)=fixture(text,Architecture::X86_64,&[("ret",SyntaxKind::Instruction)]);
        let changed=b"nop\n";assert_ne!(identity(changed),s.source.decoded_assembly);
        assert!(matches!(read_configured_assembly(changed,&s,&r,t),Err(ReadError::Identity(e))if e.contains("configured input")));
        s.inventory.sha256="0".repeat(64);assert_ne!(identity(&r),s.inventory);
        assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Identity(e))if e.contains("inventory bytes")));
    }
    #[test]
    fn assembler_missing_unknown_instruction_or_directive_never_forms_a_passing_subset(){
        let text="ret\n.cfi_escape 0x77\nunknown_original_opcode %rax\n";
        let d=[("ret",SyntaxKind::Instruction),(".cfi_escape 0x77",SyntaxKind::Cfi),("unknown_original_opcode %rax",SyntaxKind::Instruction)];
        let p=read(text,Architecture::X86_64,&d);assert_eq!(p.records.len(),3);assert_eq!(p.problems.len(),2);assert!(!p.syntax_supported);
        for omitted in [1,2]{let(mut s,mut r,t)=fixture(text,Architecture::X86_64,&d);refloor(&mut s,&mut r,|v|{let removed=v.records.remove(omitted);assert_eq!(removed.id,100+omitted as u64);});assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Inventory(e))if e.contains("record count")));}
    }
    #[test]
    fn assembler_duplicate_id_and_mutated_span_or_origin_are_refused_at_selected_floor(){
        let text="nop\nret\n";let d=[("nop",SyntaxKind::Instruction),("ret",SyntaxKind::Instruction)];
        for mutation in 0..3{let(mut s,mut r,t)=fixture(text,Architecture::X86_64,&d);refloor(&mut s,&mut r,|v|match mutation{0=>{v.records[1].id=v.records[0].id;assert_eq!(v.records[0].id,v.records[1].id);},1=>{v.records[1].span.start-=1;assert_eq!(v.records[1].span.start,3);},_=>{v.records[0].origins[0].span.end=999;assert_eq!(v.records[0].origins[0].span.end,999);}});assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Inventory(_))));}
    }
    #[test]
    fn assembler_invalid_scale_and_register_operand_survive_as_explicit_problems(){
        for text in ["movq 0(%rax,%rcx,3),%rdx\n","movq %not_a_register,%rax\n"]{
            let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Instruction)]);assert_eq!(p.problems.len(),1);assert_eq!(p.problems[0].kind,ProblemKind::Operand);assert!(matches!(p.records[0].syntax,Syntax::Unsupported));assert!(!p.syntax_supported);
        }
    }
    #[test]
    fn assembler_unexpanded_cpp_and_gas_macro_records_cannot_disappear(){
        let text="#define BODY ret\n.macro body\nret\n.endm\n";
        let p=read(text,Architecture::X86_64,&[("#define BODY ret",SyntaxKind::Preprocessor),(".macro body",SyntaxKind::Macro),("ret",SyntaxKind::Instruction),(".endm",SyntaxKind::Macro)]);
        assert_eq!(p.records.len(),4);assert_eq!(p.problems.len(),3);assert!(p.problems.iter().any(|p|p.kind==ProblemKind::UnsupportedPreprocessor));assert!(!p.syntax_supported);assert!(!p.original_unit_completeness_qualified);
    }
    #[test]
    fn assembler_target_abi_and_missing_32bit_foundations_fail_closed(){
        let text="ret\n";let(mut s,r,t)=fixture(text,Architecture::X86_64,&[("ret",SyntaxKind::Instruction)]);
        assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,Target::Aarch64UnknownNone),Err(ReadError::Profile(_))));
        s.profile.abi=MachineAbi::RiscvLp64d;assert_eq!(s.profile.abi,MachineAbi::RiscvLp64d);assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Profile(_))));
        for a in [Architecture::I686,Architecture::Armv7]{s.profile.architecture=a;s.profile.address_bits=32;assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Profile(_))));}
    }
    #[test]
    fn assembler_unterminated_lexical_input_never_returns_partial_success(){
        for text in [".ascii \"tail\n","ret /* truncated","movq (%rax,%rbx\n"]{
            let(s,r,t)=fixture(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::UnknownDirective)]);
            assert!(matches!(read_configured_assembly(text.as_bytes(),&s,&r,t),Err(ReadError::Lexical{..})));
        }
    }
    #[test]
    fn assembler_target_specific_conditions_and_stack_index_never_cross_accept(){
        for(text,a)in[("jhs destination\n",Architecture::X86_64),("b.p destination\n",Architecture::Aarch64)]{
            let p=read(text,a,&[(text.trim(),SyntaxKind::Instruction)]);assert_eq!(p.records.len(),1);assert_eq!(p.problems[0].kind,ProblemKind::UnsupportedInstruction);assert!(!p.syntax_supported);
        }
        for text in ["movq 0(%rax,%rsp,2),%rdx\n","movq 0(%rip,%rcx,2),%rdx\n"]{
            let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Instruction)]);assert_eq!(p.problems.len(),1);assert_eq!(p.problems[0].kind,ProblemKind::Operand);assert!(matches!(p.records[0].syntax,Syntax::Unsupported));
        }
    }
    #[test]
    fn assembler_segment_state_requirement_is_retained_and_not_implicitly_admitted(){
        let text="movq %fs:8,%rax\n";let(mut s,mut raw,t)=fixture(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Instruction)]);
        let p=read_configured_assembly(text.as_bytes(),&s,&raw,t).unwrap();assert_eq!(p.required_syntax_features,vec![StateFeature::ThreadPointer]);assert_eq!(p.problems[0].kind,ProblemKind::UndeclaredStateFeature);
        s.profile.features.push(StateFeature::ThreadPointer);refloor(&mut s,&mut raw,|v|v.profile.features.push(StateFeature::ThreadPointer));
        let p=read_configured_assembly(text.as_bytes(),&s,&raw,t).unwrap();assert!(p.syntax_supported);assert!(!p.instruction_semantics_lifted);assert!(!p.provider_qualified);
    }

    #[test]
    fn assembler_section_size_and_relocation_data_have_closed_typed_payloads(){
        let text=".section .note.GNU-stack,\"\",@progbits\n.size function,.-function\n.quad target@GOTPCREL+8\n";
        let p=read(text,Architecture::X86_64,&[(".section .note.GNU-stack,\"\",@progbits",SyntaxKind::Section),(".size function,.-function",SyntaxKind::Symbol),(".quad target@GOTPCREL+8",SyntaxKind::Data)]);
        assert!(p.syntax_supported);
        assert!(matches!(&p.records[0].syntax,Syntax::Directive(Directive::Section{name:Some(n),flags:Some(f),section_type:Some(SectionType::Progbits),..})if n==".note.GNU-stack"&&f.is_empty()));
        assert!(matches!(&p.records[1].syntax,Syntax::Directive(Directive::Size{size:Expression{first:ExprAtom::CurrentLocation,rest},..})if rest==&vec![(AddSub::Subtract,ExprAtom::Symbol("function".into()))]));
        assert!(matches!(&p.records[2].syntax,Syntax::Directive(Directive::Integers{element_bytes:8,values})if values==&vec![Expression{first:ExprAtom::Relocation{kind:Relocation::GotPcRel,symbol:"target".into()},rest:vec![(AddSub::Add,ExprAtom::Integer(8))]}]));
    }

    #[test]
    fn assembler_att_bare_register_spellings_stay_symbols_and_indirect_registers_stay_distinct(){
        let text="jmp rax\njmp *%rax\nmovq xmm0,%rax\n";
        let p=read(text,Architecture::X86_64,&[("jmp rax",SyntaxKind::Instruction),("jmp *%rax",SyntaxKind::Instruction),("movq xmm0,%rax",SyntaxKind::Instruction)]);
        assert!(p.syntax_supported);assert!(register("rax",Architecture::X86_64).is_none());assert!(register("xmm0",Architecture::X86_64).is_none());
        assert_eq!(p.records[0].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Jump,width:None},operands:vec![Operand::Expression(Expression{first:ExprAtom::Symbol("rax".into()),rest:vec![]})]});
        assert_eq!(p.records[1].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Jump,width:None},operands:vec![Operand::Indirect(Box::new(Operand::Register(view(PhysicalRegister::X86Gpr{name:X86Gpr::Rax},64))))]});
        assert_eq!(p.records[2].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Move,width:Some(64)},operands:vec![Operand::Expression(Expression{first:ExprAtom::Symbol("xmm0".into()),rest:vec![]}),Operand::Register(view(PhysicalRegister::X86Gpr{name:X86Gpr::Rax},64))]});
        assert_ne!(p.records[0].syntax,p.records[1].syntax);
    }
    #[test]
    fn assembler_gnu_octal_binary_hex_decimal_values_and_bad_digits_are_not_conflated(){
        let text=".quad 010,0b101,0X10,-010,10,0\n";
        let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Data)]);assert!(p.syntax_supported);
        assert_eq!(p.records[0].syntax,Syntax::Directive(Directive::Integers{element_bytes:8,values:[8,5,16,-8,10,0].into_iter().map(|n|Expression{first:ExprAtom::Integer(n),rest:vec![]}).collect()}));
        for text in [".quad 08\n",".quad 0x\n",".quad 0b2\n"]{
            let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Data)]);assert_eq!(p.records.len(),1);assert!(!p.syntax_supported);assert!(matches!(p.records[0].syntax,Syntax::Unsupported));assert!(p.problems[0].reason.contains("expression atom"));
        }
    }
    #[test]
    fn assembler_well_formed_but_unimplemented_operand_dialects_remain_explicit_on_all_targets(){
        // These forms require syntax/state families outside this reader's declared
        // subset. Keeping their whole records is not rejecting upstream source.
        for(text,a,expected,reason)in[
            ("vmovdqa %ymm0,%ymm1\n",Architecture::X86_64,ProblemKind::UnsupportedInstruction,"typed syntax variant"),
            ("ldr x1,[x0,x2]\n",Architecture::Aarch64,ProblemKind::Operand,"address offset requires #"),
            ("fld fs0,%lo(slot)(a0)\n",Architecture::Rv64,ProblemKind::Operand,"unsupported relocation expression")]{
            let p=read(text,a,&[(text.trim(),SyntaxKind::Instruction)]);assert_eq!(p.records.len(),1);assert_eq!(p.records[0].required.span,span(0,text.trim().len()));assert!(matches!(p.records[0].syntax,Syntax::Unsupported));assert_eq!(p.problems.len(),1);assert_eq!(p.problems[0].kind,expected);assert!(p.problems[0].reason.contains(reason));assert!(!p.syntax_supported);assert!(!p.instruction_semantics_lifted);
        }
    }

    #[test]
    fn assembler_zero_numeric_references_have_exact_payloads_and_nearest_targets_on_all_three_isas(){
        for(a,branch,opcode)in[
            (Architecture::X86_64,"jmp",Opcode::X86{operation:X86Opcode::Jump,width:None}),
            (Architecture::Aarch64,"b",Opcode::Aarch64(Aarch64Opcode::Branch)),
            (Architecture::Rv64,"j",Opcode::Riscv(RiscvOpcode::Jump))]{
            let forward=format!("{branch} 0f");let backward=format!("{branch} 0b");let text=format!("0: {forward}\n0: {backward}\n");
            let p=read(&text,a,&[("0:",SyntaxKind::Label),(&forward,SyntaxKind::Instruction),("0:",SyntaxKind::Label),(&backward,SyntaxKind::Instruction)]);
            assert!(p.syntax_supported);assert_eq!(p.records[0].syntax,Syntax::Label(Label::Numeric(0)));assert_eq!(p.records[2].syntax,Syntax::Label(Label::Numeric(0)));
            for(record,direction)in[(1,Direction::Forward),(3,Direction::Backward)]{assert_eq!(p.records[record].syntax,Syntax::Instruction{opcode,operands:vec![Operand::Expression(Expression{first:ExprAtom::NumericLabel{number:0,direction},rest:vec![]})]});}
            assert_eq!(p.label_uses,vec![LabelUse{record:1,number:0,direction:Direction::Forward,definition:Some(2)},LabelUse{record:3,number:0,direction:Direction::Backward,definition:Some(2)}]);
            assert!(!p.instruction_semantics_lifted);
        }
    }
    #[test]
    fn assembler_missing_zero_label_is_unresolved_while_nonempty_binary_remains_integer(){
        for text in ["jmp 0b\n","jmp 0f\n"]{
            let direction=if text.contains("0b"){Direction::Backward}else{Direction::Forward};
            let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Instruction)]);
            assert_eq!(p.records[0].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Jump,width:None},operands:vec![Operand::Expression(Expression{first:ExprAtom::NumericLabel{number:0,direction},rest:vec![]})]});
            assert_eq!(p.label_uses,vec![LabelUse{record:0,number:0,direction,definition:None}]);assert_eq!(p.problems.len(),1);assert_eq!(p.problems[0].kind,ProblemKind::UnresolvedNumericLabel);assert!(p.problems[0].reason.contains("has no matching definition"));assert!(!p.syntax_supported);
        }
        let text=".quad 0b0,0b101,0B101,0B0\n";let p=read(text,Architecture::X86_64,&[(text.trim(),SyntaxKind::Data)]);
        assert!(p.syntax_supported);assert!(p.label_uses.is_empty());assert_eq!(p.records[0].syntax,Syntax::Directive(Directive::Integers{element_bytes:8,values:[0,5,5,0].into_iter().map(|n|Expression{first:ExprAtom::Integer(n),rest:vec![]}).collect()}));
    }
    #[test]
    fn assembler_leading_zero_label_identifiers_are_consistent_and_separate_from_octal_data(){
        let text="010: jmp 010f\n010: jmp 10b\n.quad 010\n";
        let p=read(text,Architecture::X86_64,&[("010:",SyntaxKind::Label),("jmp 010f",SyntaxKind::Instruction),("010:",SyntaxKind::Label),("jmp 10b",SyntaxKind::Instruction),(".quad 010",SyntaxKind::Data)]);
        assert!(p.syntax_supported);assert_eq!(p.records[0].syntax,Syntax::Label(Label::Numeric(10)));assert_eq!(p.records[2].syntax,Syntax::Label(Label::Numeric(10)));
        assert_eq!(p.records[1].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Jump,width:None},operands:vec![Operand::Expression(Expression{first:ExprAtom::NumericLabel{number:10,direction:Direction::Forward},rest:vec![]})]});
        assert_eq!(p.records[3].syntax,Syntax::Instruction{opcode:Opcode::X86{operation:X86Opcode::Jump,width:None},operands:vec![Operand::Expression(Expression{first:ExprAtom::NumericLabel{number:10,direction:Direction::Backward},rest:vec![]})]});
        assert_eq!(p.label_uses,vec![LabelUse{record:1,number:10,direction:Direction::Forward,definition:Some(2)},LabelUse{record:3,number:10,direction:Direction::Backward,definition:Some(2)}]);
        assert_eq!(p.records[4].syntax,Syntax::Directive(Directive::Integers{element_bytes:8,values:vec![Expression{first:ExprAtom::Integer(8),rest:vec![]}]}));
    }

// Included inside native_machine_asm_reader::tests. The floor is authored
// independently via that module's fixture; parsing consumes the actual text.
// These are parser/lifter DATA controls, not original-unit or native acceptance.
use super::super::native_machine_ir as lift_ir;
use super::super::native_machine_lift::{BlockLifter, LiftFlow, LiftIds};
use super::super::native_machine_lift_dispatch::lift_instruction;

fn lift_selected_record(parsed: &ParsedAssembly, index: usize) -> (LiftFlow, Vec<lift_ir::MachineInstruction>) {
    let mut instructions = Vec::new();
    let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[index].required.id, 0,
        &mut ids, &mut instructions);
    let flow = lift_instruction(parsed, index, &mut builder).unwrap();
    drop(builder);
    for (i, instruction) in instructions.iter().enumerate() {
        assert_eq!(instruction.source_item, parsed.records[index].required.id);
        assert_eq!(instruction.state_in, if i == 0 { 0 } else { instructions[i - 1].state_out });
    }
    (flow, instructions)
}

#[test]
fn parsed_rv_word_shift_aliases_keep_raw_spelling_and_word_extension() {
    let forms = ["addiw a0,a1,-1", "addw a0,a1,a2", "subw a0,a1,a2",
        "andi a0,a1,-1", "ori a0,a1,1", "xori a0,a1,1",
        "slliw a0,a1,0", "srliw a0,a1,31", "sraiw a0,a1,31", "srai a0,a1,63"];
    let text = forms.join("\n") + "\n";
    let floor: Vec<_> = forms.iter().map(|s| (*s, SyntaxKind::Instruction)).collect();
    let parsed = read(&text, Architecture::Rv64, &floor);
    assert!(parsed.syntax_supported, "{:?}", parsed.problems);
    assert_eq!(parsed.records.len(), forms.len());
    for (index, spelling) in forms.iter().enumerate() {
        let Syntax::Instruction { operands, .. } = &parsed.records[index].syntax else { panic!("typed instruction absent") };
        if index != 1 && index != 2 {
            assert!(matches!(&operands[2], Operand::Expression(Expression { first: ExprAtom::Integer(_), .. })));
        }
        let (flow, operations) = lift_selected_record(&parsed, index);
        assert_eq!(flow, LiftFlow::Continue);
        if spelling.starts_with("addiw") || spelling.starts_with("addw") || spelling.starts_with("subw")
            || spelling.starts_with("slliw") || spelling.starts_with("srliw") || spelling.starts_with("sraiw") {
            let truncation = operations.iter().position(|i| matches!(&i.operation,
                lift_ir::MachineOperation::Cast { kind: lift_ir::ExtensionKind::Truncate, .. }) && i.result.unwrap().bits == 32).unwrap();
            let extension = operations.iter().position(|i| matches!(&i.operation,
                lift_ir::MachineOperation::Cast { kind: lift_ir::ExtensionKind::SignExtend, .. }) && i.result.unwrap().bits == 64).unwrap();
            assert!(truncation < extension, "word operation must truncate before extending: {spelling}");
        }
    }
    assert!(!parsed.machine_body_admitted && !parsed.native_qualified && !parsed.runtime_qualified);
}

#[test]
fn parsed_rv_lw_and_lwu_reach_distinct_signed_and_unsigned_loads() {
    let text = "lw a0,0(a1)\nlwu a0,0(a1)\n";
    let parsed = read(text, Architecture::Rv64, &[("lw a0,0(a1)", SyntaxKind::Instruction),
        ("lwu a0,0(a1)", SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    for (index, expected) in [(0, lift_ir::ExtensionKind::SignExtend), (1, lift_ir::ExtensionKind::ZeroExtend)] {
        let (_, operations) = lift_selected_record(&parsed, index);
        assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::Load { .. }) && i.result.unwrap().bits == 32));
        assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::Cast { kind, .. } if *kind == expected)
            && i.result.unwrap().bits == 64));
    }
}

#[test]
fn parsed_rv_illegal_word_shift_reaches_encoded_width_rejection() {
    let text = "sraiw a0,a1,32\n";
    let parsed = read(text, Architecture::Rv64, &[(text.trim(), SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert_eq!(error.source_item, parsed.records[0].required.id);
    assert!(error.reason.contains("shift immediate is outside the encoded operand width"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_aarch64_add_and_adds_share_family_but_preserve_flag_effects() {
    let parsed = read("add x0,x1,x2\nadds x0,x1,x2\n", Architecture::Aarch64,
        &[("add x0,x1,x2", SyntaxKind::Instruction), ("adds x0,x1,x2", SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    for record in &parsed.records {
        assert!(matches!(record.syntax, Syntax::Instruction { opcode: Opcode::Aarch64(Aarch64Opcode::Add), .. }));
    }
    let (_, ordinary) = lift_selected_record(&parsed, 0);
    let (_, setting) = lift_selected_record(&parsed, 1);
    assert!(!ordinary.iter().any(|i| matches!(i.operation, lift_ir::MachineOperation::WriteFlags { .. })));
    assert_eq!(setting.iter().filter(|i| matches!(&i.operation, lift_ir::MachineOperation::WriteFlags { view, .. }
        if view.register == lift_ir::PhysicalRegister::Aarch64Nzcv && view.bits == 4)).count(), 1);
}

#[test]
fn parsed_aarch64_carry_aliases_read_flags_and_refuse_immediate_rhs() {
    for form in ["adc w0,w1,w2", "adcs w0,w1,w2", "sbc w0,w1,w2", "sbcs w0,w1,w2"] {
        let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
        assert!(parsed.syntax_supported);
        let (_, operations) = lift_selected_record(&parsed, 0);
        assert_eq!(operations.iter().filter(|i| matches!(i.operation, lift_ir::MachineOperation::ReadFlags { .. })).count(), 1);
        assert!(!operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::ReadRegister { view }
            if view.register == lift_ir::PhysicalRegister::Aarch64Nzcv)));
    }
    let form = "adcs w0,w1,#1";
    let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
    let Syntax::Instruction { operands, .. } = &parsed.records[0].syntax else { panic!("typed instruction absent") };
    assert!(matches!(operands[2], Operand::Immediate(_)));
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert!(error.reason.contains("ADC/SBC requires register operands"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_aarch64_unscaled_alias_keeps_address_and_access_width() {
    for (form, bits) in [("ldur x0,[x1,#-8]", 64), ("ldurb w0,[x1,#-1]", 8),
        ("ldursh x0,[x1,#-2]", 16), ("ldursw x0,[x1,#-4]", 32)] {
        let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
        assert!(parsed.syntax_supported);
        let (_, operations) = lift_selected_record(&parsed, 0);
        assert_eq!(operations.iter().filter(|i| matches!(i.operation, lift_ir::MachineOperation::Load { .. })
            && i.result.unwrap().bits == bits).count(), 1);
    }
}

#[test]
fn parsed_x86_movl_preserves_actual_subregister_zero_extension() {
    let form = "movl %eax,%ecx";
    let parsed = read(&(form.to_owned() + "\n"), Architecture::X86_64, &[(form, SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    let (_, operations) = lift_selected_record(&parsed, 0);
    assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::WriteRegister { view, mode, .. }
        if view.bits == 32 && *mode == lift_ir::WriteMode::ZeroExtendStorage)));
}

#[test]
fn parsed_dispatch_refuses_wrong_selected_source_site_before_emission() {
    let parsed = read("addi a0,a1,1\n", Architecture::Rv64, &[("addi a0,a1,1", SyntaxKind::Instruction)]);
    let expected = parsed.records[0].required.id;
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, expected + 1, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert_eq!(error.source_item, expected + 1);
    assert!(error.reason.contains("semantic site differs"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_dispatch_refuses_changed_abi_profile_before_emission() {
    let parsed = read("addi a0,a1,1\n", Architecture::Rv64, &[("addi a0,a1,1", SyntaxKind::Instruction)]);
    let mut profile = parsed.profile.clone();
    profile.abi = MachineAbi::RiscvLp64;
    assert_ne!(profile, parsed.profile);
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert!(error.reason.contains("builder differs from selected assembly profile"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_supported_first_site_cannot_erase_unsupported_original_record() {
    let parsed = read("addi a0,a1,1\noriginal_unrealized_opcode a0\n", Architecture::Rv64,
        &[("addi a0,a1,1", SyntaxKind::Instruction), ("original_unrealized_opcode a0", SyntaxKind::Instruction)]);
    assert_eq!(parsed.records.len(), 2);
    assert!(!parsed.syntax_supported);
    assert_eq!(parsed.problems.len(), 1);
    assert_eq!(parsed.problems[0].record, 1);
    let (_, first) = lift_selected_record(&parsed, 0); assert!(!first.is_empty());
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[1].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 1, &mut builder).unwrap_err();
    assert_eq!(error.source_item, parsed.records[1].required.id);
    assert!(error.reason.contains("no parsed instruction semantics"));
    drop(builder); assert!(instructions.is_empty());
    assert!(!parsed.machine_body_admitted && !parsed.original_unit_completeness_qualified
        && !parsed.provider_qualified && !parsed.native_qualified && !parsed.runtime_qualified);
}

    #[test]
    fn assembler_rv_byte_half_six_mnemonics_feed_actual_typed_memory_lifter(){
        use super::super::native_machine_lift::{BlockLifter,LiftIds,LiftFlow,ExtensionKind};
        use super::super::native_machine_ir::MachineOperation;
        for(name,expected,bits,load,signed)in[
            ("lb",RiscvOpcode::LoadByteSigned,8u16,true,true),("lbu",RiscvOpcode::LoadByteUnsigned,8,true,false),
            ("lh",RiscvOpcode::LoadHalfSigned,16,true,true),("lhu",RiscvOpcode::LoadHalfUnsigned,16,true,false),
            ("sb",RiscvOpcode::StoreByte,8,false,false),("sh",RiscvOpcode::StoreHalf,16,false,false)]{
            let text=format!("{name} a0,-16(a1)\n");let parsed=read(&text,Architecture::Rv64,&[(text.trim(),SyntaxKind::Instruction)]);
            assert!(parsed.syntax_supported);assert_eq!(parsed.original,text.as_bytes());assert_eq!(parsed.records.len(),1);assert!(!parsed.instruction_semantics_lifted);
            let Syntax::Instruction{opcode:Opcode::Riscv(actual),operands}=&parsed.records[0].syntax else{panic!("expected exact typed RV instruction")};assert_eq!(*actual,expected);
            assert!(matches!(&operands[1],Operand::Address(Address::Riscv{displacement:Expression{first:ExprAtom::Integer(-16),rest},..})if rest.is_empty()));
            let profile=MachineProfile{architecture:Architecture::Rv64,abi:MachineAbi::RiscvLp64d,address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:0,features:vec![StateFeature::UserRegisterBits],cfi:super::super::native_machine_ir::CfiPolicy::NoCfiDeclared};
            let mut ids=LiftIds::new(1,1);let mut ops=Vec::new();let mut b=BlockLifter::new(&profile,100,0,&mut ids,&mut ops);
            let flow=super::super::native_machine_lift_rv64::lower_rv64(*actual,name,operands,&mut b);drop(b);assert!(matches!(flow,Ok(LiftFlow::Continue)));assert!(ops.iter().all(|op|op.source_item==100));
            let loads=ops.iter().filter(|op|matches!(&op.operation,MachineOperation::Load{..})).collect::<Vec<_>>();let stores=ops.iter().filter(|op|matches!(&op.operation,MachineOperation::Store{..})).collect::<Vec<_>>();
            if load{assert_eq!(loads.len(),1);assert!(stores.is_empty());let loaded=loads[0].result.unwrap();assert_eq!(loaded.bits,bits);let kind=if signed{ExtensionKind::SignExtend}else{ExtensionKind::ZeroExtend};assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::Cast{kind:actual,value}if *actual==kind&&*value==loaded.id)&&op.result.unwrap().bits==64));}
            else{assert!(loads.is_empty());assert_eq!(stores.len(),1);let narrowed=ops.iter().find(|op|matches!(&op.operation,MachineOperation::Cast{kind:ExtensionKind::Truncate,..})).expect("store truncation").result.unwrap();assert_eq!(narrowed.bits,bits);assert!(matches!(&stores[0].operation,MachineOperation::Store{value,..}if *value==narrowed.id));}
        }
        // The fixture floor is authored. Parsing/lifting these records is not GNU,
        // complete original-unit, fault, platform, ABI, or native-execution proof.
    }
