//! Real BlockLifter controls; no native execution/whole-source claim.
use super::*;
use super::super::native_machine_ir::{ByteOrder,CfiPolicy,MachineInstruction,MachineOperation,MachineProfile,StateFeature};
use super::super::native_machine_lift::LiftIds;
use std::collections::BTreeMap;
fn g(index:u8)->RegisterView {RegisterView{register:PhysicalRegister::RiscvGpr{index},low_bit:0,bits:64}}
fn f(index:u8)->RegisterView {RegisterView{register:PhysicalRegister::RiscvFpr{index},low_bit:0,bits:64}}
fn r(index:u8)->Operand {Operand::Register(g(index))}
fn i(n:i128)->Operand {Operand::Immediate(Expression{first:syntax::ExprAtom::Integer(n),rest:vec![]})}
fn m(index:u8,n:i128)->Operand {Operand::Address(syntax::Address::Riscv{base:g(index),displacement:Expression{first:syntax::ExprAtom::Integer(n),rest:vec![]}})}
fn lift(op:RiscvOpcode,s:&str,args:&[Operand])->(Result<LiftFlow>,Vec<MachineInstruction>){
 let p=MachineProfile{architecture:Architecture::Rv64,abi:MachineAbi::RiscvLp64d,address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:0,features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::NoCfiDeclared};
 let mut ids=LiftIds::new(1,1);let mut out=vec![];
 let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut out);let result=lower_rv64(op,s,args,&mut b);drop(b);(result,out)
}
fn mask(bits:u16)->u128 {if bits==128{u128::MAX}else{(1u128<<bits)-1}}
fn sx(v:u128,from:u16,to:u16)->u128{let v=v&mask(from);if v&(1u128<<(from-1))==0{v}else{v|(mask(to)^mask(from))}}
struct Seen{values:BTreeMap<usize,(u16,u128)>,regs:Vec<(RegisterView,u128)>,memory:Vec<u8>,reads:Vec<RegisterView>,writes:Vec<RegisterView>,loads:usize,stores:usize}
impl Seen{
 fn v(&self,id:usize)->(u16,u128){*self.values.get(&id).expect("defined SSA")}
 fn reg(&self,v:RegisterView)->u128{if is_zero(v){0}else{self.regs.iter().rev().find(|(x,_)|*x==v).expect("initialized control register").1}}
}
// This test-only unsigned-bitvector oracle evaluates actual emitted primitives.
// It is not a production interpreter or native realization evidence.
fn observe(ops:&[MachineInstruction],regs:&[(RegisterView,u128)],memory:&[u8])->Seen{
 let mut z=Seen{values:BTreeMap::new(),regs:regs.to_vec(),memory:memory.to_vec(),reads:vec![],writes:vec![],loads:0,stores:0};let mut state=0;
 for op in ops{assert_eq!(op.source_item,1);assert_eq!(op.state_in,state);assert_ne!(op.state_in,op.state_out);state=op.state_out;
  let value=match &op.operation{
   MachineOperation::Constant{little_endian}=>{let mut raw=[0u8;16];raw[..little_endian.len()].copy_from_slice(little_endian);Some(u128::from_le_bytes(raw))},
   MachineOperation::ReadRegister{view}=>{z.reads.push(*view);Some(z.reg(*view))},
   MachineOperation::WriteRegister{view,value,mode}=>{assert_eq!(*mode,WriteMode::WholeStorage);let(bits,v)=z.v(*value);assert_eq!(bits,view.bits);z.regs.push((*view,v));z.writes.push(*view);None},
   MachineOperation::Binary{kind,lhs,rhs}=>{let(bits,a)=z.v(*lhs);let(bbits,b)=z.v(*rhs);assert_eq!(bits,bbits);Some((match kind{
    BinaryKind::WrappingAdd=>a.wrapping_add(b),BinaryKind::WrappingSub=>a.wrapping_sub(b),BinaryKind::And=>a&b,BinaryKind::Or=>a|b,BinaryKind::Xor=>a^b,
    BinaryKind::RotateRightModuloWidth=>{let n=(b%u128::from(bits))as u32;if n==0{a}else{(a>>n)|(a<<(u32::from(bits)-n))}}
   })&mask(bits))},
   MachineOperation::Compare{kind,lhs,rhs}=>{let(bits,a)=z.v(*lhs);let(bbits,b)=z.v(*rhs);assert_eq!(bits,bbits);Some(u128::from(match kind{CompareKind::Equal=>a==b,CompareKind::UnsignedLess=>a<b}))},
   MachineOperation::Cast{kind,value}=>{let(from,v)=z.v(*value);let to=op.result.unwrap().bits;Some(match kind{ExtensionKind::Truncate=>{assert!(to<from);v&mask(to)},ExtensionKind::ZeroExtend=>{assert!(to>from);v&mask(from)},ExtensionKind::SignExtend=>{assert!(to>from);sx(v,from,to)}})},
   MachineOperation::Load{address,alignment}=>{assert_eq!(*alignment,1);let(bits,a)=z.v(*address);assert_eq!(bits,64);let n=usize::from(op.result.unwrap().bits/8);let a=usize::try_from(a).unwrap();let mut raw=[0u8;16];raw[..n].copy_from_slice(z.memory.get(a..a+n).expect("bounded control load"));z.loads+=n;Some(u128::from_le_bytes(raw))},
   MachineOperation::Store{address,value,alignment}=>{assert_eq!(*alignment,1);let(bits,a)=z.v(*address);assert_eq!(bits,64);let(bits,v)=z.v(*value);let n=usize::from(bits/8);let a=usize::try_from(a).unwrap();z.memory.get_mut(a..a+n).expect("bounded control store").copy_from_slice(&v.to_le_bytes()[..n]);z.stores+=n;None},
   other=>panic!("unexpected control primitive: {other:?}"),
  };
  if let Some(v)=value{let result=op.result.expect("scalar");assert!(z.values.insert(result.id,(result.bits,v&mask(result.bits))).is_none());}else{assert!(op.result.is_none());}
 }z
}
fn run(op:RiscvOpcode,s:&str,args:&[Operand],regs:&[(RegisterView,u128)],memory:&[u8])->(LiftFlow,Seen,Vec<MachineInstruction>){let(result,ops)=lift(op,s,args);let flow=result.unwrap();let seen=observe(&ops,regs,memory);(flow,seen,ops)}
fn refusal(op:RiscvOpcode,s:&str,args:&[Operand],reason:&str){let(result,ops)=lift(op,s,args);let e=match result{Err(e)=>e,Ok(x)=>panic!("unexpected flow {x:?}")};assert!(e.reason.contains(reason),"{e}");assert_eq!(e.source_item,1);assert!(ops.is_empty());}

#[test]
fn rv_addi_wraps_and_addiw_sign_extends_the_low_word(){
 let(_,s,_)=run(RiscvOpcode::AddImmediate,"addi",&[r(10),r(11),i(1)],&[(g(11),u64::MAX.into())],&[]);assert_eq!(s.reg(g(10)),0);
 let(_,s,_)=run(RiscvOpcode::AddImmediate,"addiw",&[r(10),r(11),i(1)],&[(g(11),0x7fff_ffff)],&[]);assert_eq!(s.reg(g(10)),0xffff_ffff_8000_0000);
}
#[test]
fn rv_word_add_and_subtract_preserve_modulo32_then_sign_extension(){
 for(op,s,a,b,want)in[(RiscvOpcode::Add,"addw",0xffff_ffffu128,1,0),(RiscvOpcode::Subtract,"subw",0,1,u128::from(u64::MAX)),(RiscvOpcode::Add,"addw",0x1234_5678_7fff_ffff,1,0xffff_ffff_8000_0000)]{let(_,z,_)=run(op,s,&[r(10),r(11),r(12)],&[(g(11),a),(g(12),b)],&[]);assert_eq!(z.reg(g(10)),want);}
}
#[test]
fn rv_zero_destination_keeps_load_effect_and_never_writes_x0(){let(_,s,_)=run(RiscvOpcode::LoadDouble,"ld",&[r(0),m(11,0)],&[(g(11),0)],&[0x5a;8]);assert_eq!(s.loads,8);assert!(s.writes.is_empty());assert_eq!(s.reg(g(0)),0);}
#[test]
fn rv_lw_and_lwu_differ_at_bit31_and_load_exactly_four_bytes(){for(s,want)in[("lw",0xffff_ffff_8000_0000u128),("lwu",0x8000_0000)]{let(_,z,_)=run(RiscvOpcode::LoadWord,s,&[r(10),m(11,0)],&[(g(11),0)],&[0,0,0,0x80,0x99]);assert_eq!(z.reg(g(10)),want);assert_eq!(z.loads,4);}}
#[test]
fn rv_lw_oracle_detects_mutating_sign_extension_to_zero_extension(){
 let(result,mut ops)=lift(RiscvOpcode::LoadWord,"lw",&[r(10),m(11,0)]);assert!(result.is_ok());let good=observe(&ops,&[(g(11),0)],&[0,0,0,0x80]);assert_eq!(good.reg(g(10)),0xffff_ffff_8000_0000);
 let mut reached=0;for op in &mut ops{if let MachineOperation::Cast{kind,..}=&mut op.operation{if *kind==ExtensionKind::SignExtend{*kind=ExtensionKind::ZeroExtend;reached+=1;}}}assert_eq!(reached,1);
 let bad=observe(&ops,&[(g(11),0)],&[0,0,0,0x80]);assert_eq!(bad.reg(g(10)),0x8000_0000);assert_ne!(good.reg(g(10)),bad.reg(g(10)));
}
#[test]
fn rv_sw_truncates_and_preserves_neighboring_bytes(){let(_,s,_)=run(RiscvOpcode::StoreWord,"sw",&[r(10),m(11,1)],&[(g(10),0x1234_5678_aabb_ccdd),(g(11),0)],&[0x77;8]);assert_eq!(s.stores,4);assert_eq!(s.memory,vec![0x77,0xdd,0xcc,0xbb,0xaa,0x77,0x77,0x77]);}
#[test]
fn rv_signed_address_offset_is_wrapping64_not_a_host_pointer(){for(base,offset)in[(4u128,-4),(u128::from(u64::MAX),1)]{let(_,s,_)=run(RiscvOpcode::LoadDouble,"ld",&[r(10),m(11,offset)],&[(g(11),base)],&[1,2,3,4,5,6,7,8]);assert_eq!(s.reg(g(10)),0x0807_0605_0403_0201);assert_eq!(s.loads,8);}}
#[test]
fn rv_immediate_shift_zero_and_extreme_counts_have_defined_bits(){
 let x=0x8000_0000_0000_0001u128;for(op,s,n,want)in[(RiscvOpcode::ShiftLeftImmediate,"slli",0,x),(RiscvOpcode::ShiftLeftImmediate,"slli",63,0x8000_0000_0000_0000),(RiscvOpcode::ShiftRightImmediate,"srli",63,1),(RiscvOpcode::ShiftRightImmediate,"srai",63,u128::from(u64::MAX)),(RiscvOpcode::ShiftRightImmediate,"sraiw",31,0),(RiscvOpcode::ShiftLeftImmediate,"slliw",31,0xffff_ffff_8000_0000)]{let(_,z,_)=run(op,s,&[r(10),r(11),i(n)],&[(g(11),x)],&[]);assert_eq!(z.reg(g(10)),want,"{s}/{n}");}
 // Distinguish low-word-first arithmetic shift from shifting all 64 bits.
 let(_,z,_)=run(RiscvOpcode::ShiftRightImmediate,"sraiw",&[r(10),r(11),i(31)],&[(g(11),0x8000_0000)],&[]);
 assert_eq!(z.reg(g(10)),u128::from(u64::MAX));
 // Even shamt zero must truncate/sign-extend the word before writeback.
 let(_,z,_)=run(RiscvOpcode::ShiftLeftImmediate,"slliw",&[r(10),r(11),i(0)],&[(g(11),0x8000_0000)],&[]);
 assert_eq!(z.reg(g(10)),0xffff_ffff_8000_0000);
}

#[test]
fn rv_illegal_immediates_are_refused_before_emitting_effects(){
 assert!(lift(RiscvOpcode::AddImmediate,"addi",&[r(10),r(11),i(2047)]).0.is_ok());
 refusal(RiscvOpcode::AddImmediate,"addi",&[r(10),r(11),i(2048)],"signed 12-bit encoding");
 assert!(lift(RiscvOpcode::ShiftLeftImmediate,"slli",&[r(10),r(11),i(63)]).0.is_ok());
 refusal(RiscvOpcode::ShiftLeftImmediate,"slli",&[r(10),r(11),i(64)],"encoded operand width");
 let unbound=Operand::Immediate(Expression{first:syntax::ExprAtom::Symbol("unadmitted_address".into()),rest:vec![]});
 refusal(RiscvOpcode::AddImmediate,"addi",&[r(10),r(11),unbound],"authenticated symbol/relocation binding");
}
#[test]
fn rv_cross_architecture_register_is_refused_before_effects(){
 assert!(lift(RiscvOpcode::Move,"mv",&[r(10),r(11)]).0.is_ok());
 let foreign=Operand::Register(RegisterView{register:PhysicalRegister::Aarch64Gpr{index:0},low_bit:0,bits:64});
 refusal(RiscvOpcode::Move,"mv",&[r(10),foreign],"canonical 64-bit integer register");
 // A source read may already exist; the real shared write guard must refuse SP.
 let(result,ops)=lift(RiscvOpcode::Move,"mv",&[r(2),r(11)]);
 let e=match result{Err(e)=>e,Ok(x)=>panic!("SP write unexpectedly accepted: {x:?}")};
 assert_eq!(e.source_item,1);assert!(e.reason.contains("SP/PC/zero writes require separate state realization"),"{e}");
 assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::ReadRegister{view}if *view==g(11))));
 assert!(ops.iter().all(|op|!matches!(&op.operation,MachineOperation::WriteRegister{..})));
}
#[test]
fn rv_fld_fsd_preserve_raw_nan_payload_bits_without_host_float_math(){
 let payload=0x7ff8_1234_dead_beefu64;let memory=payload.to_le_bytes();
 let(_,s,_)=run(RiscvOpcode::LoadFloatDouble,"fld",&[Operand::Register(f(3)),m(11,0)],&[(g(11),0)],&memory);assert_eq!(s.reg(f(3)),u128::from(payload));
 let(_,s,_)=run(RiscvOpcode::StoreFloatDouble,"fsd",&[Operand::Register(f(3)),m(11,0)],&[(g(11),0),(f(3),payload.into())],&[0;8]);assert_eq!(s.memory,memory);assert_eq!(s.stores,8);
}
#[test]
fn rv_branch_condition_and_original_target_are_preserved(){
 let target=Expression{first:syntax::ExprAtom::Symbol("original_label".into()),rest:vec![]};
 let(flow,s,_)=run(RiscvOpcode::BranchNotEqual,"bne",&[r(10),r(11),Operand::Expression(target.clone())],&[(g(10),4),(g(11),5)],&[]);
 match flow{LiftFlow::Branch{condition,target:actual}=>{assert_eq!(actual,target);assert_eq!(s.v(condition.id),(1,1));},_=>panic!("missing branch")}
}
#[test]
fn rv_linked_or_indirect_calls_do_not_become_plain_jumps(){
 let target=Operand::Expression(Expression{first:syntax::ExprAtom::Symbol("callee".into()),rest:vec![]});
 assert!(matches!(lift(RiscvOpcode::JumpAndLink,"jal",&[r(0),target.clone()]).0,Ok(LiftFlow::Jump(_))));
 refusal(RiscvOpcode::JumpAndLink,"jal",&[r(1),target],"linked call requires an explicit call/PC/ABI realization");
 refusal(RiscvOpcode::JumpRegister,"jr",&[r(10)],"indirect jump requires an explicit PC/ABI realization");
}
#[test]
fn rv_ret_reads_the_original_link_register_and_has_return_flow(){
 let(flow,s,_)=run(RiscvOpcode::Return,"ret",&[],&[(g(1),0x1235)],&[]);
 let LiftFlow::ReturnTo{target,mechanism}=flow else{panic!("computed return expected")};
 assert_eq!(mechanism,ReturnMechanism::Rv64Jalr);assert_eq!(target.bits,64);assert_eq!(s.v(target.id),(64,0x1234));
 assert_eq!(s.reads,vec![g(1)]);assert!(s.writes.is_empty());
 // Actual JALR target graph is represented; native entry/return realization remains unmet.
}
#[test]
fn rv_original_ostadix_leaf_move_uses_the_actual_retained_source(){
 const ORIGINAL:&str=include_str!("../../../../ocore/boot/riscv64/entry.S");
 assert!(ORIGINAL.starts_with("/* Native RV64GC S-mode bootstrap"));assert!(ORIGINAL.contains("ecall")&&ORIGINAL.contains("sret"));
 let source=ORIGINAL.split_once("rv_arch_current_tp:").expect("original leaf").1;
 let source=source.split_once(".size rv_arch_current_tp").expect("original extent").0;
 let actual=source.lines().map(str::trim).filter(|s|!s.is_empty()).collect::<Vec<_>>();assert_eq!(actual,vec!["mv a0, tp","ret"]);
 let(_,s,_)=run(RiscvOpcode::Move,"mv",&[r(10),r(4)],&[(g(4),0x1122_3344_5566_7788)],&[]);assert_eq!(s.reg(g(10)),0x1122_3344_5566_7788);
 // Complete original retained; this leaf control is not whole-source admission.
}

// Authored ISA vectors: no claim of original GNU source or native execution.
#[test]
fn rv_byte_loads_extend_bit7_and_touch_exactly_one_byte(){
 for(raw,signed,unsigned)in[(0x7fu8,0x7fu128,0x7fu128),(0x80,0xffff_ffff_ffff_ff80,0x80),(0xff,u128::from(u64::MAX),0xff)]{
  for(op,name,want)in[(RiscvOpcode::LoadByteSigned,"lb",signed),(RiscvOpcode::LoadByteUnsigned,"lbu",unsigned)]{
   let memory=[0x31,0x32,raw,0xee,0x44];let(_,seen,ops)=run(op,name,&[r(10),m(11,2)],&[(g(11),0)],&memory);
   assert_eq!(seen.reg(g(10)),want,"{name}/{raw:#x}");assert_eq!(seen.loads,1);assert_eq!(seen.stores,0);assert_eq!(seen.memory,memory);
   let loads=ops.iter().filter(|op|matches!(&op.operation,MachineOperation::Load{..})).collect::<Vec<_>>();assert_eq!(loads.len(),1);assert_eq!(loads[0].result.unwrap().bits,8);
  }
 }
}
#[test]
fn rv_half_loads_extend_bit15_and_touch_exactly_two_bytes(){
 for(raw,signed,unsigned)in[(0x7fffu16,0x7fffu128,0x7fffu128),(0x8000,0xffff_ffff_ffff_8000,0x8000),(0xffff,u128::from(u64::MAX),0xffff)]{
  for(op,name,want)in[(RiscvOpcode::LoadHalfSigned,"lh",signed),(RiscvOpcode::LoadHalfUnsigned,"lhu",unsigned)]{
   let bytes=raw.to_le_bytes();let memory=[0x31,0x32,bytes[0],bytes[1],0xee,0x44];let(_,seen,ops)=run(op,name,&[r(10),m(11,2)],&[(g(11),0)],&memory);
   assert_eq!(seen.reg(g(10)),want,"{name}/{raw:#x}");assert_eq!(seen.loads,2);assert_eq!(seen.stores,0);assert_eq!(seen.memory,memory);
   let loads=ops.iter().filter(|op|matches!(&op.operation,MachineOperation::Load{..})).collect::<Vec<_>>();assert_eq!(loads.len(),1);assert_eq!(loads[0].result.unwrap().bits,16);
  }
 }
}
#[test]
fn rv_byte_half_actual_cast_mutant_changes_the_sign_result(){
 for(op,name,bits,memory,good_value,bad_value)in[
  (RiscvOpcode::LoadByteSigned,"lb",8u16,vec![0x31u8,0x32,0x80,0xee],0xffff_ffff_ffff_ff80u128,0x80u128),
  (RiscvOpcode::LoadHalfSigned,"lh",16u16,vec![0x31u8,0x32,0,0x80,0xee],0xffff_ffff_ffff_8000u128,0x8000u128)]{
  let(result,mut ops)=lift(op,name,&[r(10),m(11,2)]);assert!(matches!(result,Ok(LiftFlow::Continue)));
  let load=ops.iter().find(|op|matches!(&op.operation,MachineOperation::Load{..})).expect("actual load").result.unwrap();assert_eq!(load.bits,bits);
  let good=observe(&ops,&[(g(11),0)],&memory);assert_eq!(good.reg(g(10)),good_value);assert_eq!(good.loads,usize::from(bits/8));
  let mut reached=Vec::new();for(index,op)in ops.iter_mut().enumerate(){if let MachineOperation::Cast{kind,value}=&mut op.operation{if *kind==ExtensionKind::SignExtend{assert_eq!(*value,load.id);assert_eq!(op.result.unwrap().bits,64);*kind=ExtensionKind::ZeroExtend;reached.push(index);}}}
  assert_eq!(reached.len(),1,"mutant must reach exactly one actual sign cast");assert!(matches!(&ops[reached[0]].operation,MachineOperation::Cast{kind:ExtensionKind::ZeroExtend,value}if *value==load.id));
  let bad=observe(&ops,&[(g(11),0)],&memory);assert_eq!(bad.reg(g(10)),bad_value);assert_ne!(good.reg(g(10)),bad.reg(g(10)));assert_eq!(bad.loads,good.loads);assert_eq!(bad.memory,memory);
 }
}
#[test]
fn rv_byte_half_stores_truncate_and_keep_both_neighbors(){
 for(op,name,bits,want)in[(RiscvOpcode::StoreByte,"sb",8u16,vec![0x77u8,0x77,0xdd,0x77,0x77,0x77]),(RiscvOpcode::StoreHalf,"sh",16u16,vec![0x77u8,0x77,0xdd,0xcc,0x77,0x77])]{
  let(_,seen,ops)=run(op,name,&[r(10),m(11,2)],&[(g(10),0x1234_5678_aabb_ccdd),(g(11),0)],&[0x77;6]);assert_eq!(seen.memory,want);assert_eq!(seen.stores,usize::from(bits/8));assert_eq!(seen.loads,0);
  let truncations=ops.iter().filter(|op|matches!(&op.operation,MachineOperation::Cast{kind:ExtensionKind::Truncate,..})).collect::<Vec<_>>();assert_eq!(truncations.len(),1);let truncated=truncations[0].result.unwrap();assert_eq!(truncated.bits,bits);assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::Store{value,..}if *value==truncated.id)));
 }
}
#[test]
fn rv_byte_half_x0_keeps_access_and_stores_actual_zero(){
 for(op,name,n)in[(RiscvOpcode::LoadByteSigned,"lb",1usize),(RiscvOpcode::LoadByteUnsigned,"lbu",1),(RiscvOpcode::LoadHalfSigned,"lh",2),(RiscvOpcode::LoadHalfUnsigned,"lhu",2)]{
  let(_,seen,_)=run(op,name,&[r(0),m(11,2)],&[(g(11),0)],&[0x77,0x77,0x80,0xff,0x77]);assert_eq!(seen.loads,n);assert!(seen.writes.is_empty());assert_eq!(seen.reg(g(0)),0);
 }
 for(op,name,n,want)in[(RiscvOpcode::StoreByte,"sb",1usize,vec![0x77u8,0x77,0,0x77,0x77]),(RiscvOpcode::StoreHalf,"sh",2usize,vec![0x77u8,0x77,0,0,0x77])]{
  let(_,seen,_)=run(op,name,&[r(0),m(11,2)],&[(g(11),0)],&[0x77;5]);assert_eq!(seen.stores,n);assert_eq!(seen.memory,want);assert!(!seen.reads.contains(&g(0)));assert!(seen.writes.is_empty());
 }
}
#[test]
fn rv_byte_half_addresses_enforce_signed12_before_effects(){
 for(op,name)in[(RiscvOpcode::LoadByteSigned,"lb"),(RiscvOpcode::LoadByteUnsigned,"lbu"),(RiscvOpcode::LoadHalfSigned,"lh"),(RiscvOpcode::LoadHalfUnsigned,"lhu"),(RiscvOpcode::StoreByte,"sb"),(RiscvOpcode::StoreHalf,"sh")]{
  for offset in [-2048i128,2047]{let(result,ops)=lift(op,name,&[r(10),m(11,offset)]);assert!(matches!(result,Ok(LiftFlow::Continue)),"{name}/{offset}");let expected=(offset as u64).to_le_bytes().to_vec();assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::Constant{little_endian}if *little_endian==expected)));assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::Load{..}|MachineOperation::Store{..})));}
  for offset in [-2049i128,2048]{assert!(!(-2048..=2047).contains(&offset));refusal(op,name,&[r(10),m(11,offset)],"signed 12-bit encoding");}
 }
 // Wrapping64 address, not a host pointer; choose a bounded resulting address.
 let(_,seen,_)=run(RiscvOpcode::LoadByteUnsigned,"lbu",&[r(10),m(11,1)],&[(g(11),u128::from(u64::MAX))],&[0x9a]);assert_eq!(seen.reg(g(10)),0x9a);assert_eq!(seen.loads,1);
}
#[test]
fn rv_byte_half_typed_opcode_and_raw_spelling_must_agree(){
 for(op,name)in[(RiscvOpcode::LoadByteSigned,"lb"),(RiscvOpcode::LoadByteUnsigned,"lbu"),(RiscvOpcode::LoadHalfSigned,"lh"),(RiscvOpcode::LoadHalfUnsigned,"lhu"),(RiscvOpcode::StoreByte,"sb"),(RiscvOpcode::StoreHalf,"sh")]{
  let(result,ops)=lift(op,name,&[r(10),m(11,0)]);assert!(matches!(result,Ok(LiftFlow::Continue)));assert!(ops.iter().any(|op|matches!(&op.operation,MachineOperation::Load{..}|MachineOperation::Store{..})));
  let wrong="lw";assert_ne!(name,wrong);refusal(op,wrong,&[r(10),m(11,0)],"unsupported RV64 memory operation spelling");
 }
}
#[test]
fn rv_byte_half_unadmitted_symbol_displacement_is_not_an_offset(){
 for(op,name)in[(RiscvOpcode::LoadByteSigned,"lb"),(RiscvOpcode::StoreHalf,"sh")]{
  assert!(lift(op,name,&[r(10),m(11,0)]).0.is_ok());
  let symbol=Operand::Address(syntax::Address::Riscv{base:g(11),displacement:Expression{first:syntax::ExprAtom::Symbol("unadmitted_provider_slot".into()),rest:vec![]}});
  assert!(matches!(&symbol,Operand::Address(syntax::Address::Riscv{displacement:Expression{first:syntax::ExprAtom::Symbol(s),..},..})if s=="unadmitted_provider_slot"));refusal(op,name,&[r(10),symbol],"authenticated symbol/relocation binding");
 }
}
