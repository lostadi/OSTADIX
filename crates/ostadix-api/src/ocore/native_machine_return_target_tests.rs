// Included inside native_machine_verify::tests: actual builder/lifters/verifier.
// Test-only graph observation is DATA, not an unchanged-IR runtime or native proof.
use super::super::native_machine_asm_reader as return_syntax;
use super::super::native_machine_lift::{BlockLifter as ReturnLifter,LiftFlow as ReturnFlow,LiftIds as ReturnIds};
fn return_register(t:Target)->RegisterView {
    register(match t {Target::Riscv64UnknownNone=>PhysicalRegister::RiscvGpr{index:1},
        Target::Aarch64UnknownNone=>PhysicalRegister::Aarch64Gpr{index:30},
        Target::X86_64UnknownNone=>panic!("x86 stack return remains unsupported")},64)
}
fn return_parts(c:&MachineControl)->(u32,usize,ReturnMechanism) {
    match c {MachineControl::ReturnTo{exit,target,mechanism}=>(*exit,*target,*mechanism),other=>panic!("not computed return: {other:?}")}
}
fn return_flow_parts(f:&ReturnFlow)->(Scalar,ReturnMechanism) {
    match f {ReturnFlow::ReturnTo{target,mechanism}=>(*target,*mechanism),other=>panic!("not computed return flow: {other:?}")}
}
fn return_unqualified(r:&StructuralReport){
    assert!(!r.source_custody_verified&&!r.inventory_authority_verified&&!r.original_unit_completeness_verified);
    assert!(!r.instruction_semantics_verified&&!r.native_realization_verified&&!r.cfi_semantics_verified);
    assert!(!r.memory_access_validity_verified&&!r.entry_state_realization_verified);
    assert!(!r.provider_qualified&&!r.runtime_qualified&&!r.isa_equivalence_qualified&&!r.ordinary_native_admission);
}
fn return_case(t:Target)->(MachineBodyContract,SelectedInstructionInventory,ReturnFlow){
    let(mut body,mut floor)=fixture(t);let link=return_register(t);
    body.format=COMPUTED_CONTROL_FORMAT.into();body.interface.entry.initialized.push(link);
    body.interface.exits[0].outputs.clear();floor.interface=body.interface.clone();
    floor.items.retain(|x|[0,1,4,5].contains(&x.id));
    let profile=body.profile.clone();let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let(flow,control,state)={let mut b=ReturnLifter::new(&profile,4,0,&mut ids,&mut code);
        let flow=match t{
            Target::Riscv64UnknownNone=>super::super::native_machine_lift_rv64::lower_rv64(return_syntax::RiscvOpcode::Return,"ret",&[],&mut b).unwrap(),
            Target::Aarch64UnknownNone=>super::super::native_machine_lift_aarch64::lower_aarch64(return_syntax::Aarch64Opcode::Return,"ret",&[],&mut b).unwrap(),
            Target::X86_64UnknownNone=>panic!("x86 stack return remains unsupported")};
        let control=b.return_control(&flow,0).unwrap();(flow,control,b.state())};
    body.blocks[0].instructions=code;body.blocks[0].terminator=MachineTerminator{source_item:4,state,control};
    (body,floor,flow)
}
// This deliberately small observer consumes actual emitted primitives. It is
// never shipped or used as original-engine/ISA execution evidence.
fn return_value(code:&[MachineInstruction],target:usize,link:RegisterView,input:u64)->u64{
    let mut values=BTreeMap::<usize,u64>::new();let mut state=0;
    for i in code{
        assert_eq!(i.source_item,4);assert_eq!(i.state_in,state);state=i.state_out;
        let result=i.result.expect("return scalar");assert_eq!(result.bits,64);
        let value=match &i.operation{
            MachineOperation::ReadRegister{view}=>{assert_eq!(*view,link);input},
            MachineOperation::Constant{little_endian}=>u64::from_le_bytes(little_endian.as_slice().try_into().unwrap()),
            MachineOperation::Binary{kind,lhs,rhs}=>{let a=values[lhs];let b=values[rhs];match kind{
                BinaryKind::WrappingAdd=>a.wrapping_add(b),BinaryKind::And=>a&b,other=>panic!("unexpected return binary {other:?}")}},
            other=>panic!("unexpected return primitive {other:?}")};
        assert!(values.insert(result.id,value).is_none());
    }values[&target]
}
#[test]
fn rv_ret_target_uses_real_graph_and_odd_link_low_bit_clearing(){
    let t=Target::Riscv64UnknownNone;let(body,floor,flow)=return_case(t);
    let(scalar,kind)=return_flow_parts(&flow);let(exit,target,mechanism)=return_parts(&body.blocks[0].terminator.control);
    assert_eq!((exit,target,mechanism),(0,scalar.id,kind));assert_eq!(kind,ReturnMechanism::Rv64Jalr);
    assert_eq!(body.blocks[0].terminator.state,body.blocks[0].instructions.last().unwrap().state_out);
    for input in [0,1,2,3,0x1234,0x1235,0x8000_0000_0000_0001,u64::MAX]{
        let independent=input-input%2;
        assert_eq!(return_value(&body.blocks[0].instructions,target,return_register(t),input),independent);
    }
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn rv_jr_and_zero_link_jalr_aliases_keep_actual_computed_target(){
    let t=Target::Riscv64UnknownNone;let p=fixture(t).0.profile;let ra=return_register(t);
    let zero=return_syntax::Expression{first:return_syntax::ExprAtom::Integer(0),rest:vec![]};
    for(op,spelling,args)in[
        (return_syntax::RiscvOpcode::JumpRegister,"jr",vec![return_syntax::Operand::Register(ra)]),
        (return_syntax::RiscvOpcode::JumpRegister,"jalr",vec![return_syntax::Operand::ZeroRegister{bits:64},return_syntax::Operand::Register(ra),return_syntax::Operand::Immediate(zero)])]{
        let mut ids=ReturnIds::new(0,1);let mut code=vec![];
        let(flow,control)={let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
            let f=super::super::native_machine_lift_rv64::lower_rv64(op,spelling,&args,&mut b).unwrap();
            let c=b.return_control(&f,0).unwrap();(f,c)};
        assert_eq!(return_parts(&control).1,return_flow_parts(&flow).0.id);
        assert_eq!(return_parts(&control).2,ReturnMechanism::Rv64Jalr);
        assert_eq!(return_value(&code,return_parts(&control).1,ra,0x1235),0x1234);
    }
}
#[test]
fn changed_return_target_is_reached_and_independent_odd_ra_oracle_distinguishes_it(){
    let t=Target::Riscv64UnknownNone;let(mut body,floor,_)=return_case(t);
    let original=return_parts(&body.blocks[0].terminator.control).1;
    let read=body.blocks[0].instructions.iter().find(|i|matches!(i.operation,MachineOperation::ReadRegister{..})).unwrap().result.unwrap().id;
    assert_ne!(read,original);
    let MachineControl::ReturnTo{target,..}=&mut body.blocks[0].terminator.control else{panic!()};*target=read;
    let reached=return_parts(&body.blocks[0].terminator.control).1;assert_eq!(reached,read);
    let input=0x1235;let observed=return_value(&body.blocks[0].instructions,reached,return_register(t),input);
    assert_eq!(observed,input);assert_ne!(observed,input-input%2);
    // A defined address-width target is structurally valid. The checker must not
    // claim it independently recovered the original instruction's intent.
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn changed_return_mask_is_reached_by_the_actual_target_graph(){
    let t=Target::Riscv64UnknownNone;let(mut body,floor,_)=return_case(t);
    let target=return_parts(&body.blocks[0].terminator.control).1;
    let mask=body.blocks[0].instructions.iter_mut().find(|i|matches!(&i.operation,MachineOperation::Constant{little_endian} if little_endian.as_slice()==(u64::MAX-1).to_le_bytes())).unwrap();
    let MachineOperation::Constant{little_endian}=&mut mask.operation else{panic!()};
    assert_eq!(little_endian.as_slice(),(u64::MAX-1).to_le_bytes());*little_endian=u64::MAX.to_le_bytes().to_vec();
    assert_eq!(little_endian.as_slice(),u64::MAX.to_le_bytes());assert_eq!(return_parts(&body.blocks[0].terminator.control).1,target);
    let input=0x35;let observed=return_value(&body.blocks[0].instructions,target,return_register(t),input);
    assert_eq!(observed,input);assert_ne!(observed,input-input%2);
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn aarch64_ret_reads_actual_lr_without_rv_mask_and_preserves_ret_class(){
    let t=Target::Aarch64UnknownNone;let(body,floor,flow)=return_case(t);
    let(target,mechanism)=return_flow_parts(&flow);assert_eq!(mechanism,ReturnMechanism::Aarch64Ret);
    assert_eq!(return_parts(&body.blocks[0].terminator.control),(0,target.id,mechanism));
    assert_eq!(body.blocks[0].instructions.len(),1);
    assert!(matches!(body.blocks[0].instructions[0].operation,MachineOperation::ReadRegister{view} if view==return_register(t)));
    assert_eq!(return_value(&body.blocks[0].instructions,target.id,return_register(t),0x1235),0x1235);
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn aarch64_non_lr_return_stays_a_reached_explicit_refusal(){
    let t=Target::Aarch64UnknownNone;let p=fixture(t).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let operand=return_syntax::Operand::Register(register(PhysicalRegister::Aarch64Gpr{index:19},64));
    let error={let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
        let e=super::super::native_machine_lift_aarch64::lower_aarch64(return_syntax::Aarch64Opcode::Return,"ret",&[operand],&mut b).unwrap_err();
        assert_eq!(b.state(),0);e};
    assert_eq!(error.source_item,4);assert_eq!(error.reason,"A64 non-LR RET target lacks selected continuation realization");assert!(code.is_empty());
}
#[test]
fn checked_return_converter_rejects_nonreturn_wrong_profile_and_absent_scalar(){
    let p=fixture(Target::Riscv64UnknownNone).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
    let e=b.return_control(&ReturnFlow::Continue,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"flow has no explicit computed return target");
    let actual=b.read_register(return_register(Target::Riscv64UnknownNone)).unwrap();
    let wrong=ReturnFlow::ReturnTo{target:actual,mechanism:ReturnMechanism::Aarch64Ret};
    assert_eq!(return_flow_parts(&wrong),(actual,ReturnMechanism::Aarch64Ret));
    let e=b.return_control(&wrong,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"return mechanism differs from machine architecture");
    let absent=Scalar{id:999_999,bits:64};let wrong=ReturnFlow::ReturnTo{target:absent,mechanism:ReturnMechanism::Rv64Jalr};
    assert_eq!(return_flow_parts(&wrong).0.id,999_999);
    let e=b.return_control(&wrong,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"scalar is absent or its declared width differs from emitted SSA");
}
#[test]
fn checked_return_converter_rejects_a_known_wrong_width_scalar(){
    let p=fixture(Target::Riscv64UnknownNone).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);let actual=b.constant(32,7).unwrap();assert_eq!(actual.bits,32);
    let flow=ReturnFlow::ReturnTo{target:actual,mechanism:ReturnMechanism::Rv64Jalr};assert_eq!(return_flow_parts(&flow).0,actual);
    let e=b.return_control(&flow,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"return target must have exact profile address width");
}
#[test]
fn computed_return_versions_reject_mixing_and_legacy_v2_stays_unqualified(){
    for &t in Target::ALL{let(mut b,i)=fixture(t);let r=verify(&b,&i,t).unwrap();assert_eq!(r.format,"ocore-machine-structure-relative-inventory-v2");return_unqualified(&r);
        b.format=COMPUTED_CONTROL_FORMAT.into();assert!(matches!(b.blocks[0].terminator.control,MachineControl::Return{..}));rejected(&b,&i,t,"legacy return marker is only a v2 structural contract");}
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let r=verify(&b,&i,t).unwrap();assert_eq!(r.format,"ocore-machine-structure-relative-inventory-v3");return_unqualified(&r);
    b.format=FORMAT.into();assert!(matches!(b.blocks[0].terminator.control,MachineControl::ReturnTo{..}));rejected(&b,&i,t,"computed return requires v3 machine contract");
    b.format="ocore-machine-body-contract-v999".into();rejected(&b,&i,t,"machine/inventory contract version differs");
}
#[test]
fn computed_return_mechanism_must_match_the_actual_profile(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);
    let MachineControl::ReturnTo{mechanism,..}=&mut b.blocks[0].terminator.control else{panic!()};*mechanism=ReturnMechanism::Aarch64Ret;
    assert_eq!(return_parts(&b.blocks[0].terminator.control).2,ReturnMechanism::Aarch64Ret);rejected(&b,&i,t,"return mechanism differs from machine architecture");
}
#[test]
fn computed_return_requires_an_available_value_in_this_block(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let absent=999_999;
    assert!(b.blocks[0].instructions.iter().all(|x|x.result.is_none_or(|r|r.id!=absent)));
    let MachineControl::ReturnTo{target,..}=&mut b.blocks[0].terminator.control else{panic!()};*target=absent;
    assert_eq!(return_parts(&b.blocks[0].terminator.control).1,absent);rejected(&b,&i,t,"SSA value is not defined earlier");
}
#[test]
fn computed_return_rejects_a_well_typed_truncated_target(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let old=return_parts(&b.blocks[0].terminator.control).1;
    let next=b.blocks[0].instructions.iter().filter_map(|x|x.result.map(|r|r.id)).max().unwrap()+1;
    let state=b.blocks[0].terminator.state;b.blocks[0].instructions.push(MachineInstruction{source_item:4,state_in:state,state_out:state+1,result:Some(Scalar{id:next,bits:32}),operation:MachineOperation::Cast{kind:ExtensionKind::Truncate,value:old}});
    b.blocks[0].terminator.state=state+1;let MachineControl::ReturnTo{target,..}=&mut b.blocks[0].terminator.control else{panic!()};*target=next;
    assert_eq!(b.blocks[0].instructions.last().unwrap().result,Some(Scalar{id:next,bits:32}));assert_eq!(return_parts(&b.blocks[0].terminator.control).1,next);
    rejected(&b,&i,t,"return target must have exact profile address width");
}
#[test]
fn computed_returns_retain_final_state_sp_and_readonly_preservation_guards(){
    let t=Target::Riscv64UnknownNone;let(base,floor,_)=return_case(t);
    let mut bad=base.clone();assert_ne!(bad.blocks[0].terminator.state,0);bad.blocks[0].terminator.state=0;rejected(&bad,&floor,t,"control transfer must consume final state SSA token");
    for protected in [false,true]{let mut b=base.clone();let mut i=floor.clone();let target=return_parts(&b.blocks[0].terminator.control).1;
        let view=if protected{return_register(t)}else{register(PhysicalRegister::RiscvGpr{index:2},64)};
        if protected{b.interface.exits[0].preserved.push(view);i.interface=b.interface.clone();}
        let state=b.blocks[0].terminator.state;b.blocks[0].instructions.push(MachineInstruction{source_item:4,state_in:state,state_out:state+1,result:None,operation:MachineOperation::WriteRegister{view,value:target,mode:WriteMode::WholeStorage}});b.blocks[0].terminator.state=state+1;
        assert!(matches!(b.blocks[0].instructions.last().unwrap().operation,MachineOperation::WriteRegister{view:v,..} if v==view));
        rejected(&b,&i,t,if protected{"write overlaps readonly exit-preserved"}else{"SP/PC/zero/flags"});
    }
}
#[test]
fn computed_return_serialization_keeps_exact_target_and_branch_class(){
    let t=Target::Riscv64UnknownNone;let(b,i,_)=return_case(t);let expected=return_parts(&b.blocks[0].terminator.control);
    let value=serde_json::to_value(&b).unwrap();assert_eq!(value["format"],COMPUTED_CONTROL_FORMAT);
    let c=&value["blocks"][0]["terminator"]["control"];assert_eq!(c["control"],"return_to");assert_eq!(c["target"],expected.1);assert_eq!(c["mechanism"],"rv64_jalr");
    let decoded:MachineBodyContract=serde_json::from_value(value).unwrap();assert_eq!(return_parts(&decoded.blocks[0].terminator.control),expected);return_unqualified(&verify(&decoded,&i,t).unwrap());
}
