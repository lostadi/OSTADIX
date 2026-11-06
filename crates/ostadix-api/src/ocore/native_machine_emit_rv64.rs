//! Static RV64 instruction selection from the typed machine graph.
//! No interpreter, raw source instruction forwarding, implicit frame or scratch.
use std::collections::{BTreeMap, BTreeSet};
use super::{common::Target, native_ir::{BlockId, ValueId}, native_machine_ir::*, native_machine_verify};
type Result<T> = std::result::Result<T, String>;
fn need(ok: bool, text: &str) -> Result<()> { if ok { Ok(()) } else { Err(text.into()) } }
fn mask(bits: u16) -> u64 { if bits == 64 { u64::MAX } else { (1u64 << bits)-1 } }
fn signed(value: u64, bits: u16) -> i64 { if bits == 64 { value as i64 } else { ((value << (64-bits)) as i64) >> (64-bits) } }
fn immediate(value: u64, bits: u16) -> Option<i64> { let n=signed(value,bits); (-2048..=2047).contains(&n).then_some(n) }
#[derive(Debug)]
pub(super) struct BodyEmission { blocks: Vec<SelectedBlock>, pub instruction_count: u64 }
#[derive(Debug)]
struct SelectedBlock { id: BlockId, label: String, code: Vec<SelectedInstruction> }
#[derive(Debug)]
struct SelectedInstruction { source: SourceItemId, text: String, edge: Option<(BlockId,bool)> }
impl BodyEmission {
    pub(super) fn assembly(&self) -> String {
        let mut text=String::from(".option push\n.option norvc\n.option norelax\n");
        for block in &self.blocks { text.push_str(&format!("{}:\n",block.label)); for inst in &block.code { text.push_str(&format!("\t{} # machine-source-item {}\n",inst.text,inst.source)); } }
        text.push_str(".option pop\n"); text
    }
    pub(super) fn byte_size(&self) -> u64 { self.instruction_count*4 }
}
#[derive(Clone)]
struct Node<'a> { bits: u16, instruction: &'a MachineInstruction, epoch: Option<u64> }
struct Graph<'a> { nodes: BTreeMap<ValueId,Node<'a>>, uses: BTreeMap<ValueId,Vec<usize>>, write_epochs: BTreeMap<usize,u64> }
fn inputs(op: &MachineOperation) -> Vec<ValueId> {
    match op { MachineOperation::WriteRegister{value,..}|MachineOperation::WriteFlags{value,..}|MachineOperation::Cast{value,..}=>vec![*value],
        MachineOperation::Binary{lhs,rhs,..}|MachineOperation::Compare{lhs,rhs,..}=>vec![*lhs,*rhs],
        MachineOperation::Load{address,..}=>vec![*address],MachineOperation::Store{address,value,..}=>vec![*address,*value],_=>vec![] }
}
fn canonical(view: RegisterView) -> Result<()> {
    need(view.low_bit==0&&view.bits==64,"native RV selection requires a whole 64-bit architectural register")?;
    need(matches!(view.register,PhysicalRegister::RiscvGpr{index:0..=31}|PhysicalRegister::RiscvFpr{index:0..=31}),"non-RV register or PC/flags requires another realization")
}
impl<'a> Graph<'a> {
    fn new(block: &'a MachineBlock) -> Result<Self> {
        let mut g=Self{nodes:BTreeMap::new(),uses:BTreeMap::new(),write_epochs:BTreeMap::new()}; let mut epochs=BTreeMap::<PhysicalRegister,u64>::new();
        for (at,i) in block.instructions.iter().enumerate() {
            for value in inputs(&i.operation) { g.uses.entry(value).or_default().push(at); }
            let mut epoch=None;
            match &i.operation {
                MachineOperation::ReadRegister{view}=>{canonical(*view)?;epoch=Some(*epochs.get(&view.register).unwrap_or(&0));},
                MachineOperation::WriteRegister{view,mode,..}=>{canonical(*view)?;need(*mode==WriteMode::WholeStorage,"partial/zero-extending architectural write needs explicit selection")?;need(!matches!(view.register,PhysicalRegister::RiscvGpr{index:0|1|2|3|4}),"protected x0/RA/SP/gp/tp write is not realized")?;let n=epochs.entry(view.register).or_default();*n=n.checked_add(1).ok_or("register epoch overflow")?;g.write_epochs.insert(at,*n);},
                MachineOperation::ReadFlags{..}|MachineOperation::WriteFlags{..}|MachineOperation::InvalidateRegister{..}=>return Err("flags or register definedness change is not realized".into()),_=>{}
            }
            if let Some(value)=i.result { need(matches!(value.bits,1|8|16|32|64),"scalar width needs a native allocation/operation realization")?;g.nodes.insert(value.id,Node{bits:value.bits,instruction:i,epoch}); }
        }
        let mut control=Vec::new(); match &block.terminator.control {
            MachineControl::Jump{edge}=>control.extend(&edge.arguments),MachineControl::Branch{condition,on_true,on_false}=>{control.push(*condition);control.extend(&on_true.arguments);control.extend(&on_false.arguments);},
            MachineControl::ReturnTo{target,..}=>control.push(*target),MachineControl::RestoreContext{stack_pointer,program_counter}=>control.extend([*stack_pointer,*program_counter]),_=>{}
        }
        for value in control { g.uses.entry(value).or_default().push(block.instructions.len()); } Ok(g)
    }
    fn node(&self,id: ValueId)->Result<&Node<'a>> { self.nodes.get(&id).ok_or_else(||format!("scalar {id} needs cross-block/parameter allocation")) }
    fn constant(&self,id: ValueId)->Option<(u64,u16)> { let n=self.nodes.get(&id)?;if let MachineOperation::Constant{little_endian}=&n.instruction.operation { if little_endian.len()>8{return None;}let mut bytes=[0u8;8];bytes[..little_endian.len()].copy_from_slice(little_endian);Some((u64::from_le_bytes(bytes),n.bits)) }else{None} }
    fn binary(&self,id: ValueId,kind: BinaryKind)->Option<(ValueId,ValueId)> { match &self.nodes.get(&id)?.instruction.operation {MachineOperation::Binary{kind:k,lhs,rhs}if *k==kind=>Some((*lhs,*rhs)),_=>None} }
    fn gpr(&self,id: ValueId,bits: u16,physical: &BTreeMap<PhysicalRegister,u64>)->Result<u8> {
        let n=self.node(id)?;need(n.bits==bits,"scalar operand width differs")?;
        if self.constant(id)==Some((0,bits)){return Ok(0);}
        if bits<64 { if let MachineOperation::Cast{kind:ExtensionKind::Truncate,value}=&n.instruction.operation {return self.gpr(*value,64,physical);}return Err("narrow scalar needs explicit temporary allocation".into()); }
        if let MachineOperation::ReadRegister{view}=&n.instruction.operation {if let PhysicalRegister::RiscvGpr{index}=view.register { need(n.epoch==Some(*physical.get(&view.register).unwrap_or(&0)),"captured scalar requires preserved temporary allocation after register overwrite")?;return Ok(index);} }
        Err("scalar is not an available physical GPR".into())
    }
    fn fpr(&self,id: ValueId,physical: &BTreeMap<PhysicalRegister,u64>)->Result<u8> {let n=self.node(id)?;if let MachineOperation::ReadRegister{view}=&n.instruction.operation {if let PhysicalRegister::RiscvFpr{index}=view.register {need(n.bits==64&&n.epoch==Some(*physical.get(&view.register).unwrap_or(&0)),"FPR scalar was overwritten")?;return Ok(index);}}Err("scalar is not an available raw FPR".into())}
    fn address(&self,id: ValueId,physical: &BTreeMap<PhysicalRegister,u64>)->Result<(u8,i64)> {
        if let Ok(reg)=self.gpr(id,64,physical){return Ok((reg,0));}
        if let Some((value,64))=self.constant(id){return immediate(value,64).map(|n|(0,n)).ok_or_else(||"absolute address needs explicit scratch/relocation realization".into());}
        if let Some((a,b))=self.binary(id,BinaryKind::WrappingAdd){for (base,offset) in [(a,b),(b,a)]{if let Some((value,64))=self.constant(offset){if let Some(n)=immediate(value,64){if let Ok(reg)=self.gpr(base,64,physical){return Ok((reg,n));}}}}}
        Err("memory address is not an available base plus signed 12-bit displacement".into())
    }
}
fn append(code: &mut Vec<SelectedInstruction>,source: SourceItemId,text: String){code.push(SelectedInstruction{source,text,edge:None});}
fn materialize(rd:u8,value:u64)->Vec<String> {
    let mut value=value as i64 as i128;let mut digits=Vec::new();while !(-2048..=2047).contains(&value){let digit=(value+2048).rem_euclid(4096)-2048;digits.push(digit);value=(value-digit)/4096;}
    let mut code=vec![format!("addi x{rd}, x0, {value}")];for digit in digits.into_iter().rev(){code.push(format!("slli x{rd}, x{rd}, 12"));if digit!=0{code.push(format!("addi x{rd}, x{rd}, {digit}"));}}code
}
fn arithmetic(g:&Graph<'_>,id:ValueId,bits:u16,rd:u8,physical:&BTreeMap<PhysicalRegister,u64>)->Result<Vec<String>> {
    if let Some((value,width))=g.constant(id){need(width==bits,"constant arithmetic width differs")?;return Ok(materialize(rd,if bits==32{signed(value,32) as u64}else{value}));}
    if let Ok(rs)=g.gpr(id,bits,physical){return Ok(vec![format!("{} x{rd}, x{rs}, 0",if bits==32{"addiw"}else{"addi"})]);}
    let mut current=id;let mut shift=0u16;while let Some((a,b))=g.binary(current,BinaryKind::WrappingAdd){if a!=b{break;}shift+=1;current=a;if shift>=bits{return Ok(materialize(rd,0));}}
    if shift>0 {let rs=g.gpr(current,bits,physical)?;return Ok(vec![format!("{} x{rd}, x{rs}, {shift}",if bits==32{"slliw"}else{"slli"})]);}
    if let Some((a,b))=g.binary(id,BinaryKind::And){for (rot,mask_id) in [(a,b),(b,a)]{if let (Some((src,count_id)),Some((m,w)))=(g.binary(rot,BinaryKind::RotateRightModuloWidth),g.constant(mask_id)){if let Some((k,kw))=g.constant(count_id){if w==bits&&kw==bits&&k>0&&k<u64::from(bits)&&m==mask(bits)>>(k as u32){let rs=g.gpr(src,bits,physical)?;return Ok(vec![format!("{} x{rd}, x{rs}, {k}",if bits==32{"srliw"}else{"srli"})]);}}}}}
    let n=g.node(id)?;if let MachineOperation::Binary{kind,lhs,rhs}=&n.instruction.operation {
        let name=match kind{BinaryKind::WrappingAdd=>"add",BinaryKind::WrappingSub=>"sub",BinaryKind::And=>"and",BinaryKind::Or=>"or",BinaryKind::Xor=>"xor",BinaryKind::RotateRightModuloWidth=>return Err("live rotate needs explicit RV64GC expansion; Zbb/RORI is not implied".into())};
        if let (Ok(a),Ok(b))=(g.gpr(*lhs,bits,physical),g.gpr(*rhs,bits,physical)){let word=bits==32&&matches!(kind,BinaryKind::WrappingAdd|BinaryKind::WrappingSub);let mut code=vec![format!("{name}{} x{rd}, x{a}, x{b}",if word{"w"}else{""})];if bits==32&&!word{code.push(format!("addiw x{rd}, x{rd}, 0"));}return Ok(code);}
        let orders=if matches!(kind,BinaryKind::WrappingSub){vec![(*lhs,*rhs)]}else{vec![(*lhs,*rhs),(*rhs,*lhs)]};
        for (reg,c) in orders{if let (Ok(rs),Some((v,w)))=(g.gpr(reg,bits,physical),g.constant(c)){if w!=bits{continue;}if let Some(mut imm)=immediate(v,bits){if *kind==BinaryKind::WrappingSub{imm=-imm;if !(-2048..=2047).contains(&imm){continue;}}let op=if matches!(kind,BinaryKind::WrappingAdd|BinaryKind::WrappingSub){if bits==32{"addiw"}else{"addi"}}else{match kind{BinaryKind::And=>"andi",BinaryKind::Or=>"ori",BinaryKind::Xor=>"xori",_=>unreachable!()}};let mut code=vec![format!("{op} x{rd}, x{rs}, {imm}")];if bits==32&&!matches!(kind,BinaryKind::WrappingAdd|BinaryKind::WrappingSub){code.push(format!("addiw x{rd}, x{rd}, 0"));}return Ok(code);}}}
    }
    Err("live expression needs another static instruction selection or explicit allocation".into())
}
fn write_value(g:&Graph<'_>,value:ValueId,rd:u8,physical:&BTreeMap<PhysicalRegister,u64>)->Result<Vec<String>> {
    let n=g.node(value)?;need(n.bits==64,"architectural GPR result must have 64 bits")?;
    if let MachineOperation::Cast{kind,value:inner}=&n.instruction.operation {let bits=g.node(*inner)?.bits;if *kind==ExtensionKind::SignExtend&&bits==32{return arithmetic(g,*inner,32,rd,physical);}if matches!(kind,ExtensionKind::SignExtend|ExtensionKind::ZeroExtend)&&matches!(bits,8|16|32){let rs=g.gpr(*inner,bits,physical)?;let k=64-bits;return Ok(vec![format!("slli x{rd}, x{rs}, {k}"),format!("{} x{rd}, x{rd}, {k}",if *kind==ExtensionKind::SignExtend{"srai"}else{"srli"})]);}}
    arithmetic(g,value,64,rd,physical)
}
// A physically early load may not destroy an older captured register
// scalar, including a derived pre-load address reused after the load.
fn captured_before_load_is_used_later(g:&Graph<'_>,block:&MachineBlock,at:usize,register:PhysicalRegister)->bool {
    for instruction in &block.instructions[..at] {
        if !matches!(&instruction.operation,MachineOperation::ReadRegister{view}if view.register==register){continue;}
        let Some(value)=instruction.result else{continue;};let mut pending=vec![value.id];let mut seen=BTreeSet::new();
        while let Some(id)=pending.pop(){if !seen.insert(id){continue;}for &use_at in g.uses.get(&id).map(Vec::as_slice).unwrap_or(&[]){
            if use_at>at{return true;}
            if use_at<at{if let Some(next)=block.instructions.get(use_at){if matches!(next.operation,MachineOperation::Cast{..}|MachineOperation::Binary{..}|MachineOperation::Compare{..}){if let Some(result)=next.result{pending.push(result.id);}}}}
        }}
    }false
}
struct LoadSink { register:PhysicalRegister, write_at:Option<usize>, signed:bool }
fn load_sink(g:&Graph<'_>,block:&MachineBlock,at:usize,value:Scalar)->Result<LoadSink> {
    let mut id=value.id;let mut sign=false;let mut widened=value.bits==64;
    loop {let uses=g.uses.get(&id).map(Vec::as_slice).unwrap_or(&[]);if uses.is_empty(){return Ok(LoadSink{register:PhysicalRegister::RiscvGpr{index:0},write_at:None,signed:false});}need(uses.len()==1,"load result retention/fanout requires explicit register allocation")?;let next=uses[0];let i=block.instructions.get(next).ok_or("load result used by control needs explicit allocation")?;
        match &i.operation {
            MachineOperation::Cast{kind,value:source}if *source==id&&!widened&&matches!(kind,ExtensionKind::SignExtend|ExtensionKind::ZeroExtend)=>{let result=i.result.ok_or("load cast result absent")?;need(result.bits==64,"load extension must reach whole-register width")?;id=result.id;sign=*kind==ExtensionKind::SignExtend;widened=true;},
            MachineOperation::WriteRegister{view,value:source,mode}if *source==id=>{canonical(*view)?;need(*mode==WriteMode::WholeStorage&&widened,"load sink requires exact whole-register extension")?;need(next>at,"load sink is not after load")?;
                for between in &block.instructions[at+1..next]{match &between.operation{MachineOperation::Constant{..}|MachineOperation::Cast{..}|MachineOperation::Binary{..}|MachineOperation::Compare{..}=>{},MachineOperation::ReadRegister{view:read}if read.register!=view.register=>{},_=>return Err("load sink crosses a fault/state effect or old destination read".into())}}
                need(!captured_before_load_is_used_later(g,block,at,view.register),"captured pre-load destination scalar crosses a physical load clobber; explicit temporary allocation is required")?;
                return Ok(LoadSink{register:view.register,write_at:Some(next),signed:sign});},_=>return Err("load use requires another static selection/allocation".into())
        }
    }
}
fn coverage(views:&[RegisterView],reg:PhysicalRegister)->u64 {views.iter().filter(|v|v.register==reg).fold(0,|m,v|m|(mask(v.bits)<<v.low_bit))}
fn abi(body:&MachineBodyContract)->Result<()> {
    need(body.profile.architecture==Architecture::Rv64&&matches!(body.profile.abi,MachineAbi::RiscvLp64|MachineAbi::RiscvLp64d),"only the explicit RV64 LP64/LP64D leaf ABI is selected")?;
    need(body.profile.cfi==CfiPolicy::NoCfiDeclared&&body.directives.is_empty(),"CFI/directive realization is not implemented by this selector")?;
    need(body.interface.entry.policy==EntryPolicy::NoImplicitFrameOrScratch,"implicit entry frame/scratch is forbidden")?;
    let mut saved=vec![1,2,3,4,8,9];saved.extend(18..=27);
    for exit in &body.interface.exits {need(exit.kind==ExitKind::OrdinaryReturn,"restored continuation is not realized")?;need(!exit.preserved.iter().any(|v|v.register==PhysicalRegister::RiscvPc),"return PC cannot be declared readonly-preserved")?;
        for &index in &saved{let reg=PhysicalRegister::RiscvGpr{index};need(coverage(&body.interface.entry.initialized,reg)==u64::MAX&&coverage(&exit.preserved,reg)==u64::MAX,"leaf ABI requires initialized readonly SP/RA/gp/tp/callee-saved registers")?;}
        if body.profile.abi==MachineAbi::RiscvLp64d{for index in [8,9,18,19,20,21,22,23,24,25,26,27]{let reg=PhysicalRegister::RiscvFpr{index};need(coverage(&body.interface.entry.initialized,reg)==u64::MAX&&coverage(&exit.preserved,reg)==u64::MAX,"LP64D requires readonly callee-saved FPR bits")?;}}
    }Ok(())
}
fn return_target(g:&Graph<'_>,id:ValueId,physical:&BTreeMap<PhysicalRegister,u64>)->Result<()> {
    if let Some((a,b))=g.binary(id,BinaryKind::And){for (sum,mask_id) in [(a,b),(b,a)]{if g.constant(mask_id)!=Some((u64::MAX-1,64)){continue;}if let Some((x,y))=g.binary(sum,BinaryKind::WrappingAdd){for (reg,zero) in [(x,y),(y,x)]{if g.constant(zero)==Some((0,64))&&g.gpr(reg,64,physical)==Ok(1){return Ok(());}}}}}
    Err("ReturnTo target is not the preserved RA plus zero with exact JALR low-bit clearing".into())
}
fn branch(g:&Graph<'_>,mut id:ValueId,physical:&BTreeMap<PhysicalRegister,u64>)->Result<(&'static str,u8,u8)> {
    let mut inverted=false;loop{if let Some((a,b))=g.binary(id,BinaryKind::Xor){if g.constant(a)==Some((1,1)){id=b;inverted=!inverted;continue;}if g.constant(b)==Some((1,1)){id=a;inverted=!inverted;continue;}}break;}
    if let Some((value,1))=g.constant(id){need(value<=1,"branch boolean constant differs")?;return Ok((if (value==1)^inverted{"beq"}else{"bne"},0,0));}
    if let MachineOperation::Compare{kind,lhs,rhs}=&g.node(id)?.instruction.operation{let a=g.gpr(*lhs,64,physical)?;let b=g.gpr(*rhs,64,physical)?;return Ok((match(kind,inverted){(CompareKind::Equal,false)=>"beq",(CompareKind::Equal,true)=>"bne",(CompareKind::UnsignedLess,false)=>"bltu",(CompareKind::UnsignedLess,true)=>"bgeu"},a,b));}
    Err("branch predicate requires explicit static compare selection".into())
}
pub(super) fn select_body(body:&MachineBodyContract,inventory:&SelectedInstructionInventory,target:Target,prefix:&str)->Result<BodyEmission> {
    native_machine_verify::verify(body,inventory,target).map_err(|e|format!("machine structural verification: {e:?}"))?;
    need(body.format==COMPUTED_CONTROL_FORMAT,"native selection rejects legacy return-marker format")?;abi(body)?;
    need(!prefix.is_empty()&&prefix.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'.'),"unsafe private label prefix")?;
    let labels:BTreeMap<_,_>=body.blocks.iter().map(|b|(b.id,format!("{prefix}_{}",b.id))).collect();let mut ordered:Vec<_>=body.blocks.iter().filter(|b|b.id==body.entry).collect();ordered.extend(body.blocks.iter().filter(|b|b.id!=body.entry));let mut blocks=Vec::new();
    for block in ordered {need(block.parameters.is_empty(),"block parameters need explicit parallel-copy/allocation realization")?;let g=Graph::new(block)?;let mut physical=BTreeMap::new();let mut skipped=BTreeSet::new();let mut code=Vec::new();
        for (at,i) in block.instructions.iter().enumerate(){match &i.operation {
            MachineOperation::WriteRegister{view,value,..}=>{if skipped.contains(&at){continue;}let rd=if let PhysicalRegister::RiscvGpr{index}=view.register{index}else{return Err("non-load FPR write has no raw-bit selection".into())};for text in write_value(&g,*value,rd,&physical)?{append(&mut code,i.source_item,text);}physical.insert(view.register,g.write_epochs[&at]);},
            MachineOperation::Load{address,..}=>{need(body.interface.entry.memory==MemoryInterface::OrderedProcessData,"load requires explicit process-memory interface")?;let value=i.result.ok_or("load scalar absent")?;let sink=load_sink(&g,block,at,value)?;let (base,offset)=g.address(*address,&physical)?;
                let (op,dest)=match sink.register {PhysicalRegister::RiscvGpr{index}=>(match(value.bits,sink.signed){(64,_)=>"ld",(32,true)=>"lw",(32,false)=>"lwu",(16,true)=>"lh",(16,false)=>"lhu",(8,true)=>"lb",(8,false)=>"lbu",_=>return Err("load footprint is not realized".into())},format!("x{index}")),PhysicalRegister::RiscvFpr{index}=>{need(value.bits==64&&body.profile.abi==MachineAbi::RiscvLp64d,"FPR load needs LP64D raw 64-bit memory contract")?;("fld",format!("f{index}"))},_=>return Err("load sink register is not RV".into())};append(&mut code,i.source_item,format!("{op} {dest}, {offset}(x{base})"));if let Some(write)=sink.write_at{skipped.insert(write);physical.insert(sink.register,g.write_epochs[&write]);}},
            MachineOperation::Store{address,value,..}=>{need(body.interface.entry.memory==MemoryInterface::OrderedProcessData,"store requires explicit process-memory interface")?;let (base,offset)=g.address(*address,&physical)?;let n=g.node(*value)?;let mut input=*value;if let MachineOperation::Cast{kind:ExtensionKind::Truncate,value}=&n.instruction.operation{input=*value;}let (op,src)=if let Ok(reg)=g.gpr(input,64,&physical){(match n.bits{8=>"sb",16=>"sh",32=>"sw",64=>"sd",_=>return Err("store footprint is not realized".into())},format!("x{reg}"))}else{need(n.bits==64&&body.profile.abi==MachineAbi::RiscvLp64d,"FPR store needs LP64D raw 64-bit contract")?;("fsd",format!("f{}",g.fpr(input,&physical)?))};append(&mut code,i.source_item,format!("{op} {src}, {offset}(x{base})"));},
            MachineOperation::Constant{..}|MachineOperation::ReadRegister{..}|MachineOperation::Cast{..}|MachineOperation::Binary{..}|MachineOperation::Compare{..}=>{},_=>return Err("machine state operation has no native selection".into())
        }}
        let source=block.terminator.source_item;match &block.terminator.control {
            MachineControl::Jump{edge}=>{need(edge.arguments.is_empty(),"edge arguments need parallel copies")?;let label=labels.get(&edge.target).ok_or("jump label absent")?;code.push(SelectedInstruction{source,text:format!("jal x0, {label}"),edge:Some((edge.target,false))});},
            MachineControl::Branch{condition,on_true,on_false}=>{need(on_true.arguments.is_empty()&&on_false.arguments.is_empty(),"conditional edge arguments need parallel copies")?;let (op,a,b)=branch(&g,*condition,&physical)?;let yes=labels.get(&on_true.target).ok_or("true label absent")?;let no=labels.get(&on_false.target).ok_or("false label absent")?;code.push(SelectedInstruction{source,text:format!("{op} x{a}, x{b}, {yes}"),edge:Some((on_true.target,true))});code.push(SelectedInstruction{source,text:format!("jal x0, {no}"),edge:Some((on_false.target,false))});},
            MachineControl::ReturnTo{target,mechanism,..}=>{need(*mechanism==ReturnMechanism::Rv64Jalr,"return branch class is not RV JALR")?;return_target(&g,*target,&physical)?;append(&mut code,source,"jalr x0, x1, 0".into());},
            MachineControl::Return{..}=>return Err("legacy return marker has no native target".into()),MachineControl::RestoreContext{..}=>return Err("restored SP/PC protocol is not realized".into())
        }blocks.push(SelectedBlock{id:block.id,label:labels[&block.id].clone(),code});
    }
    let mut offsets=BTreeMap::new();let mut cursor=0u64;for b in &blocks{offsets.insert(b.id,cursor);cursor=cursor.checked_add(u64::try_from(b.code.len()).map_err(|_|"instruction count overflow")?.checked_mul(4).ok_or("code extent overflow")?).ok_or("code extent overflow")?;}
    let mut pc=0u64;for b in &blocks{for i in &b.code{if let Some((target,conditional))=i.edge{let delta=i128::from(offsets[&target])-i128::from(pc);let (lo,hi)=if conditional{(-4096,4094)}else{(-1048576,1048574)};need(delta%2==0&&delta>=lo&&delta<=hi,"edge encoding range requires an explicit long-transfer realization; no hidden scratch is allowed")?;}pc+=4;}}
    Ok(BodyEmission{blocks,instruction_count:cursor/4})
}
