use super::*;
use o_lang::ocore::native_machine_ir::*;
// Authored ELF/metadata fixtures only, never original GNU or native authority.
fn put16(bytes:&mut [u8],at:usize,value:u16) {bytes[at..at+2].copy_from_slice(&value.to_le_bytes());}
fn put32(bytes:&mut [u8],at:usize,value:u32) {bytes[at..at+4].copy_from_slice(&value.to_le_bytes());}
fn put64(bytes:&mut [u8],at:usize,value:u64) {bytes[at..at+8].copy_from_slice(&value.to_le_bytes());}
fn source_scope(body:&MachineBodyContract) -> CfiSourceScope {
    CfiSourceScope {selected_inventory:body.selected_inventory.clone(),source:body.source.clone(),symbol:body.symbol.clone(),profile:body.profile.clone()}
}
fn frame_pair(machine:u16,initial:&[u8],base:usize) -> (Vec<u8>,usize) {
    let ra=match machine {62=>16,183=>30,243=>1,_=>panic!("fixture architecture")};
    let mut payload=vec![0,0,0,0,1,b'z',b'R',0,1,0x78,ra,1,0x1b];payload.extend_from_slice(initial);
    while payload.len()%4!=0 {payload.push(0);}
    let mut frame=(payload.len() as u32).to_le_bytes().to_vec();frame.extend(payload);
    let local_fde=frame.len();let mut fde=((local_fde+4) as u32).to_le_bytes().to_vec();
    fde.extend_from_slice(&0i32.to_le_bytes());fde.extend_from_slice(&4i32.to_le_bytes());fde.push(0);
    while fde.len()%4!=0 {fde.push(0);}
    frame.extend_from_slice(&(fde.len() as u32).to_le_bytes());frame.extend(fde);
    (frame,base+local_fde)
}
fn encode_object(machine:u16,frame:&[u8]) -> Vec<u8> {
    let names=b"\0.shstrtab\0.eh_frame\0";let frame_start=96usize;let headers=(frame_start+frame.len()+7)&!7;
    let mut bytes=vec![0;headers+3*64];bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes,16,1);put16(&mut bytes,18,machine);put32(&mut bytes,20,1);
    put64(&mut bytes,40,headers as u64);put16(&mut bytes,52,64);put16(&mut bytes,58,64);put16(&mut bytes,60,3);put16(&mut bytes,62,1);
    bytes[64..64+names.len()].copy_from_slice(names);bytes[frame_start..frame_start+frame.len()].copy_from_slice(frame);
    let strings=headers+64;put32(&mut bytes,strings,1);put32(&mut bytes,strings+4,3);put64(&mut bytes,strings+24,64);put64(&mut bytes,strings+32,names.len() as u64);put64(&mut bytes,strings+48,1);
    let eh=headers+128;put32(&mut bytes,eh,11);put32(&mut bytes,eh+4,1);put64(&mut bytes,eh+24,frame_start as u64);put64(&mut bytes,eh+32,frame.len() as u64);put64(&mut bytes,eh+48,8);
    bytes
}
fn object_fixture(machine:u16,initial:&[u8]) -> (Vec<u8>,OriginalFdeSelection) {
    let target=match machine {62=>Target::X86_64UnknownNone,183=>Target::Aarch64UnknownNone,243=>Target::Riscv64UnknownNone,_=>panic!("fixture architecture")};
    let (body,_)=body_fixture(target);let (frame,fde)=frame_pair(machine,initial,0);
    (encode_object(machine,&frame),OriginalFdeSelection {frame_section_index:2,fde_section_offset:fde,source_scope:source_scope(&body)})
}
fn architecture_fixture(t:Target) -> (Architecture,u16,u8,u8,PhysicalRegister,PhysicalRegister,PhysicalRegister,PhysicalRegister) {
    match t {
        Target::X86_64UnknownNone=>(Architecture::X86_64,62,7,5,PhysicalRegister::X86Gpr {name:X86Gpr::Rdi},PhysicalRegister::X86Gpr {name:X86Gpr::Rax},PhysicalRegister::X86Gpr {name:X86Gpr::Rsp},PhysicalRegister::X86Pc),
        Target::Aarch64UnknownNone=>(Architecture::Aarch64,183,31,0,PhysicalRegister::Aarch64Gpr {index:0},PhysicalRegister::Aarch64Gpr {index:9},PhysicalRegister::Aarch64Sp,PhysicalRegister::Aarch64Pc),
        Target::Riscv64UnknownNone=>(Architecture::Rv64,243,2,10,PhysicalRegister::RiscvGpr {index:10},PhysicalRegister::RiscvGpr {index:5},PhysicalRegister::RiscvGpr {index:2},PhysicalRegister::RiscvPc),
    }
}
fn body_fixture(t:Target) -> (MachineBodyContract,SelectedInstructionInventory) {
    let (architecture,_,_,_,arg,temp,sp,pc)=architecture_fixture(t);
    let reg=|register|RegisterView {register,low_bit:0,bits:64};
    let identity=|digit:char|ArtifactIdentity {bytes:1024,sha256:digit.to_string().repeat(64)};
    let profile=MachineProfile {architecture,abi:match t {Target::X86_64UnknownNone=>MachineAbi::SysvAmd64,Target::Aarch64UnknownNone=>MachineAbi::Aapcs64,Target::Riscv64UnknownNone=>MachineAbi::RiscvLp64d},address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:if t==Target::X86_64UnknownNone {8}else{0},features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::Required};
    let interface=MachineInterface {entry:EntryInterface {policy:EntryPolicy::NoImplicitFrameOrScratch,initialized:vec![reg(arg),reg(sp),reg(pc)],memory:MemoryInterface::None},exits:vec![ExitInterface {id:0,kind:ExitKind::OrdinaryReturn,outputs:vec![reg(temp)],preserved:vec![reg(sp)]}]};
    let source=SourceWitness {format:SOURCE_FORMAT.into(),input_form:MachineInputForm::ConfiguredAssemblyText,unit_id:"inert-decoder-core-adapter-fixture".into(),files:vec![SourceFile {id:0,logical_path:"inert-metadata.source".into(),identity:identity('1')}],decoded_assembly:identity('2'),build_configuration:identity('3'),frontend_event:identity('4')};
    let items=(0..6).map(|id|SourceItem {id,kind:if [2,3,4].contains(&id){SourceItemKind::Instruction}else{SourceItemKind::CfiDirective},decoded_span:SourceSpan {start:id*8,end:id*8+8},origins:vec![OriginalSpan {file:0,span:SourceSpan {start:id*8,end:id*8+8}}]}).collect();
    let inventory=SelectedInstructionInventory {format:INVENTORY_FORMAT.into(),identity:identity('5'),source:source.clone(),symbol:"inert_adapter".into(),profile:profile.clone(),interface:interface.clone(),items};
    let body=MachineBodyContract {format:FORMAT.into(),selected_inventory:inventory.identity.clone(),source,symbol:"inert_adapter".into(),profile,interface,entry:0,blocks:vec![MachineBlock {id:0,source_label:None,state_parameter:0,parameters:vec![],instructions:vec![MachineInstruction {source_item:2,state_in:0,state_out:1,result:Some(Scalar {id:0,bits:64}),operation:MachineOperation::ReadRegister {view:reg(arg)}},MachineInstruction {source_item:3,state_in:1,state_out:2,result:None,operation:MachineOperation::WriteRegister {view:reg(temp),value:0,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator {source_item:4,state:2,control:MachineControl::Return {exit:0}}}],directives:vec![DirectiveRecord {source_item:0,directive:MachineDirective::CfiStart},DirectiveRecord {source_item:1,directive:MachineDirective::CfiRestore {register:reg(arg)}},DirectiveRecord {source_item:5,directive:MachineDirective::CfiEnd}]};
    (body,inventory)
}
#[test]
fn actual_elf_decoder_adapter_and_shared_core_evaluator_compose_on_each_typed_architecture() {
    for &t in Target::ALL {
        let (architecture,machine,cfa,arg,_,_,_,_)=architecture_fixture(t);
        let initial=[0x0c,cfa,8,0x08,arg];let (bytes,selected)=object_fixture(machine,&initial);
        let (body,inventory)=body_fixture(t);
        let out=verify_source_cfi_from_original_fde(&bytes,&selected,&body,&inventory,t).unwrap();
        assert_eq!(out.raw_object.machine,machine);assert_eq!(out.source_program.initial_cie.architecture,architecture);
        assert_eq!(out.source_program.initial_cie.data_alignment,-8);
        assert_eq!(out.source_program.initial_cie.cfa.as_ref().unwrap().offset,8);
        assert_eq!(out.source_program.program.rows[1].register_rules[0].rule,CfiRegisterRule::SameValue);
        assert!(!out.raw_object.fde_pc_verified && !out.raw_object.fde_rules_executed && !out.raw_object.object_provenance_verified && !out.raw_object.source_profile_admitted && !out.raw_object.unwind_execution_verified);
        assert!(!out.source_program.source_object_association_verified && !out.source_program.native_unwind_verified && !out.source_program.program.emitted_program_counter_map_verified);
    }
}
#[test]
fn typed_adapter_preserves_every_decoded_rule_and_signed_byte_offset_without_rescaling() {
    // RV columns: CFA x2, five rules x10..x14 and register source x15.
    let (bytes,selected)=object_fixture(243,&[0x0c,2,8,0x07,10,0x08,11,0x8c,3,0x14,13,2,0x09,14,15]);
    let (_,initial)=decode_initial_cie(&bytes,&selected).unwrap();
    assert_eq!(initial.registers.iter().map(|entry|entry.rule.clone()).collect::<Vec<_>>(),
        vec![CfiRegisterRule::Undefined,CfiRegisterRule::SameValue,CfiRegisterRule::CfaOffset {offset:-24},CfiRegisterRule::CfaValueOffset {offset:-16},CfiRegisterRule::Register {register:RegisterView {register:PhysicalRegister::RiscvGpr {index:15},low_bit:0,bits:64}}]);
    assert_eq!(initial.cfa.unwrap().register.register,PhysicalRegister::RiscvGpr {index:2});
}
#[test]
fn selected_fde_backreference_is_required_instead_of_selecting_the_first_cie() {
    let (bytes,selected)=object_fixture(62,&[0x0c,7,8]);
    let mut wrong=selected.clone();wrong.fde_section_offset=0;
    assert!(decode_initial_cie(&bytes,&wrong).unwrap_err().to_string().contains("FDE record is absent"));
    wrong=selected.clone();wrong.frame_section_index=1;assert!(decode_initial_cie(&bytes,&wrong).is_err());
}
#[test]
fn missing_cfa_wrong_machine_and_unresolved_restore_are_not_implicit_defaults() {
    let (bytes,selected)=object_fixture(243,&[0x08,10]);
    assert!(decode_initial_cie(&bytes,&selected).unwrap_err().to_string().contains("CFA is unspecified"));
    let (bytes,selected)=object_fixture(243,&[0x0c,2,8]);
    let mut mismatched=selected.clone();mismatched.source_scope.profile.architecture=Architecture::Aarch64;
    assert!(decode_initial_cie(&bytes,&mismatched).unwrap_err().to_string().contains("differs from source profile"));
    let (body,inventory)=body_fixture(Target::Riscv64UnknownNone);
    assert!(verify_source_cfi_from_original_fde(&bytes,&selected,&body,&inventory,Target::Riscv64UnknownNone).unwrap_err().to_string().contains("initial CIE restore rule is unspecified"));
}
#[test]
fn actual_target_and_cfa_register_mismatches_reach_existing_core_guards() {
    let (bytes,selected)=object_fixture(183,&[0x0c,31,8,0x08,0]);
    let (body,inventory)=body_fixture(Target::Aarch64UnknownNone);
    assert!(verify_source_cfi_from_original_fde(&bytes,&selected,&body,&inventory,Target::X86_64UnknownNone).unwrap_err().to_string().contains("selected canonical target"));
    let (bytes,selected)=object_fixture(243,&[0x0c,0,8,0x08,10]);
    let (body,inventory)=body_fixture(Target::Riscv64UnknownNone);
    assert!(verify_source_cfi_from_original_fde(&bytes,&selected,&body,&inventory,Target::Riscv64UnknownNone).unwrap_err().to_string().contains("canonical address"));
}

#[test]
fn two_functions_in_one_object_keep_distinct_selected_cie_contexts_and_reject_reuse() {
    let (first,first_inventory)=body_fixture(Target::Riscv64UnknownNone);
    let mut second=first.clone();let mut second_inventory=first_inventory.clone();
    second.symbol="second_inert_adapter".into();second_inventory.symbol=second.symbol.clone();
    second.source.unit_id="second_inert_adapter_unit".into();second_inventory.source=second.source.clone();
    second_inventory.identity=ArtifactIdentity {bytes:1024,sha256:"7".repeat(64)};second.selected_inventory=second_inventory.identity.clone();
    let (mut frame,first_fde)=frame_pair(243,&[0x0c,2,8,0x08,10],0);
    let (tail,second_fde)=frame_pair(243,&[0x0c,2,16,0x07,10],frame.len());frame.extend(tail);
    let bytes=encode_object(243,&frame);
    let selected_first=OriginalFdeSelection {frame_section_index:2,fde_section_offset:first_fde,source_scope:source_scope(&first)};
    let selected_second=OriginalFdeSelection {frame_section_index:2,fde_section_offset:second_fde,source_scope:source_scope(&second)};
    let a=verify_source_cfi_from_original_fde(&bytes,&selected_first,&first,&first_inventory,Target::Riscv64UnknownNone).unwrap();
    let b=verify_source_cfi_from_original_fde(&bytes,&selected_second,&second,&second_inventory,Target::Riscv64UnknownNone).unwrap();
    assert_ne!(a.source_program.initial_cie.cie_section_offset,b.source_program.initial_cie.cie_section_offset);
    assert_eq!(a.source_program.program.rows[1].register_rules[0].rule,CfiRegisterRule::SameValue);
    assert_eq!(b.source_program.program.rows[1].register_rules[0].rule,CfiRegisterRule::Undefined);
    assert_eq!(a.source_program.initial_cie.cfa.unwrap().offset,8);
    assert_eq!(b.source_program.initial_cie.cfa.unwrap().offset,16);
    assert!(verify_source_cfi_from_original_fde(&bytes,&selected_first,&second,&second_inventory,Target::Riscv64UnknownNone).unwrap_err().to_string().contains("source-function scope differs"));
}

fn with_frame_relocation(mut bytes:Vec<u8>,offset:u64,kind:u32,rela:bool) -> Vec<u8> {
    let old_headers=u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let original_headers=bytes[old_headers..old_headers+3*64].to_vec();
    let symbol_at=(bytes.len()+7)&!7;let relocation_at=symbol_at+24;
    let headers=relocation_at+24;bytes.resize(headers+5*64,0);
    bytes[headers..headers+3*64].copy_from_slice(&original_headers);
    put64(&mut bytes,40,headers as u64);put16(&mut bytes,60,5);
    let symbols=headers+3*64;
    put32(&mut bytes,symbols+4,2);put64(&mut bytes,symbols+24,symbol_at as u64);
    put64(&mut bytes,symbols+32,24);put64(&mut bytes,symbols+48,8);put64(&mut bytes,symbols+56,24);
    let relocations=headers+4*64;let stride=if rela {24}else{16};
    put32(&mut bytes,relocations+4,if rela {4}else{9});put64(&mut bytes,relocations+24,relocation_at as u64);
    put64(&mut bytes,relocations+32,stride);put32(&mut bytes,relocations+40,3);
    put32(&mut bytes,relocations+44,2);put64(&mut bytes,relocations+48,8);put64(&mut bytes,relocations+56,stride);
    put64(&mut bytes,relocation_at,offset);put64(&mut bytes,relocation_at+8,u64::from(kind));
    bytes
}

#[test]
fn relocated_fde_header_cannot_select_an_initial_cie_for_any_typed_architecture() {
    for &target in Target::ALL {
        let (_,machine,cfa,arg,_,_,_,_)=architecture_fixture(target);
        let (bytes,selected)=object_fixture(machine,&[0x0c,cfa,8,0x08,arg]);
        let (body,inventory)=body_fixture(target);
        verify_source_cfi_from_original_fde(&bytes,&selected,&body,&inventory,target).unwrap();
        let (word,pc)=match machine {62=>(1,2),183=>(257,261),243=>(2,57),_=>unreachable!()};
        for rela in [false,true] {
            for kind in [word,pc,0xffff] {
                for relative in [4isize,0,1,2,3,5,6,7,-1] {
                    let offset=selected.fde_section_offset.checked_add_signed(relative).unwrap();
                    let modified=with_frame_relocation(bytes.clone(),offset as u64,kind,rela);
                    let raw=cie_raw_decoder::inspect_elf64_le_rel(&modified).unwrap();
                    let fde=raw.sections[0].records.iter().find_map(|record|match record {
                        RawRecord::Fde(fde) if fde.range.section_offset==selected.fde_section_offset=>Some(fde),_=>None,
                    }).unwrap();
                    assert!(fde.error.as_deref().is_some_and(|error|error.contains("overlaps FDE length/CIE backreference")),
                        "machine={machine} rela={rela} kind={kind} relative={relative}: {:?}",fde.error);
                    assert!(fde.cie_section_offset.is_none());
                    assert!(raw.require_initial_rules_decoded().is_err());
                    assert!(decode_initial_cie(&modified,&selected).is_err());
                    assert!(verify_source_cfi_from_original_fde(&modified,&selected,&body,&inventory,target).is_err());
                }
            }
        }
    }
}

#[test]
fn initial_pc_relocation_after_fde_header_keeps_source_cfi_adapter_available() {
    for &target in Target::ALL {
        let (_,machine,cfa,arg,_,_,_,_)=architecture_fixture(target);
        let (bytes,selected)=object_fixture(machine,&[0x0c,cfa,8,0x08,arg]);
        let (body,inventory)=body_fixture(target);
        let kind=match machine {62=>2,183=>261,243=>57,_=>unreachable!()};
        for rela in [false,true] {
            let modified=with_frame_relocation(bytes.clone(),(selected.fde_section_offset+8) as u64,kind,rela);
            let output=verify_source_cfi_from_original_fde(&modified,&selected,&body,&inventory,target).unwrap();
            assert_eq!(output.source_program.initial_cie.fde_section_offset,selected.fde_section_offset as u64);
            assert_eq!(output.raw_object.sections[0].relocations.len(),1);
            assert_eq!(output.raw_object.sections[0].relocations[0].addend,rela.then_some(0));
            assert!(!output.raw_object.fde_pc_verified && !output.source_program.program.emitted_program_counter_map_verified);
        }
    }
}
