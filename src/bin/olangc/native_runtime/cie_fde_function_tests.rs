//! Authored byte fixtures only. UNRUN: no assembled/original-object authority.
use super::*;
use sha2::{Digest, Sha256};
fn put16(b: &mut [u8], p: usize, v: u16) { b[p..p+2].copy_from_slice(&v.to_le_bytes()); }
fn put32(b: &mut [u8], p: usize, v: u32) { b[p..p+4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], p: usize, v: u64) { b[p..p+8].copy_from_slice(&v.to_le_bytes()); }
struct Fixture { bytes: Vec<u8>, headers: usize, frame_at: usize, fde_offsets: Vec<usize> }
fn fixture(machine: u16, functions: &[(u16, u64, u64)], paired: bool, range: i32, fde_count: usize, implicit: bool) -> Fixture {
    fixture_with_profile(machine, functions, paired, range, fde_count, implicit, 16, false)
}
fn fixture_with_profile(machine: u16, functions: &[(u16, u64, u64)], paired: bool, range: i32, fde_count: usize, implicit: bool, code_size: usize, personality: bool) -> Fixture {
    let mut cie = if personality {
        vec![0,0,0,0,1,b'z',b'P',b'R',0,1,0x78,1,6,0x1b,0,0,0,0,0x1b]
    } else {
        vec![0,0,0,0,1,b'z',b'R',0,1,0x78,1,1,0x1b]
    };
    cie.extend_from_slice(&[0x0c,2,16,0x81,1]);
    while !cie.len().is_multiple_of(4) { cie.push(0); }
    let mut frame = (cie.len() as u32).to_le_bytes().to_vec(); frame.extend(cie);
    let mut fde_offsets = Vec::new(); let mut relocations = Vec::new();
    for _ in 0..fde_count {
        let start = frame.len(); fde_offsets.push(start);
        let mut payload = ((start + 4) as u32).to_le_bytes().to_vec();
        payload.extend(0i32.to_le_bytes()); payload.extend(range.to_le_bytes()); payload.push(0);
        while !payload.len().is_multiple_of(4) { payload.push(0); }
        frame.extend((payload.len() as u32).to_le_bytes()); frame.extend(payload);
        let label_start = functions.len() as u32 + 1;
        relocations.push(((start+8) as u64, label_start, 57u32));
        if paired {
            relocations.push(((start+12) as u64, label_start+1, 35));
            relocations.push(((start+12) as u64, label_start, 39));
        }
    }
    let mut strings = vec![0]; let mut symbols = vec![0;24];
    for (i, &(section, value, size)) in functions.iter().enumerate() {
        let name = strings.len() as u32; strings.extend(format!("function{i}\0").as_bytes());
        let mut row = vec![0;24]; put32(&mut row,0,name); row[4]=0x12; put16(&mut row,6,section);
        put64(&mut row,8,value); put64(&mut row,16,size); symbols.extend(row);
    }
    for value in [0,16] {
        let mut row = vec![0;24]; put16(&mut row,6,2); put64(&mut row,8,value); symbols.extend(row);
    }
    let mut rela = Vec::new();
    for (offset, symbol, kind) in relocations {
        rela.extend(offset.to_le_bytes()); rela.extend(((u64::from(symbol)<<32)|u64::from(kind)).to_le_bytes());
        if !implicit { rela.extend(0i64.to_le_bytes()); }
    }
    let mut names=vec![0]; let mut name_offsets=Vec::new();
    for name in [".shstrtab", ".text", ".eh_frame", ".strtab", ".symtab", ".rela.eh_frame"] {
        name_offsets.push(names.len() as u32); names.extend(name.as_bytes()); names.push(0);
    }
    let payloads = [names, vec![0;code_size], frame, strings, symbols, rela];
    let mut bytes = vec![0;64]; let mut offsets=Vec::new();
    for payload in &payloads { while !bytes.len().is_multiple_of(8) {bytes.push(0);} offsets.push(bytes.len()); bytes.extend(payload); }
    while !bytes.len().is_multiple_of(8) { bytes.push(0); }
    let headers=bytes.len();bytes.resize(headers+7*64,0);
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");put16(&mut bytes,16,1);put16(&mut bytes,18,machine);put32(&mut bytes,20,1);
    put64(&mut bytes,40,headers as u64);put16(&mut bytes,52,64);put16(&mut bytes,58,64);put16(&mut bytes,60,7);put16(&mut bytes,62,1);
    for i in 0..6 {
        let at=headers+(i+1)*64;put32(&mut bytes,at,name_offsets[i]);
        put32(&mut bytes,at+4,match i {0|3=>3,4=>2,5=>if implicit {9}else{4},_=>1});
        put64(&mut bytes,at+24,offsets[i] as u64);put64(&mut bytes,at+32,payloads[i].len() as u64);put64(&mut bytes,at+48,1);
        if i==1 {put64(&mut bytes,at+8,6);}
        if i==4 {put32(&mut bytes,at+40,4);put64(&mut bytes,at+56,24);}
        if i==5 {put32(&mut bytes,at+40,5);put32(&mut bytes,at+44,3);put64(&mut bytes,at+56,if implicit {16}else{24});}
    }
    Fixture {bytes,headers,frame_at:offsets[2],fde_offsets}
}
fn pin(f: &Fixture) -> ArtifactIdentity { ArtifactIdentity { sha256:hex::encode(Sha256::digest(&f.bytes)), bytes:u64::try_from(f.bytes.len()).unwrap() } }
fn key() -> SymbolKey { SymbolKey {symbol_table:5,symbol_index:1} }
#[test]
fn rv_pcrel_and_unrelocated_range_match_exact_whole_function() {
    let f=fixture(243,&[(2,0,16)],false,16,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(object.symbol_tables()[0].symbols.len(),4);assert_eq!(object.functions().len(),1);assert_eq!(object.fdes().len(),1);
    assert_eq!(object.selected_fde(&pin(&f),key()).unwrap().fde_section_offset,f.fde_offsets[0]);
    object.require_all_defined_functions_matched().unwrap();
    assert!(!object.raw_object().fde_pc_verified && !object.raw_object().object_provenance_verified);
}
#[test]
fn notype_labels_and_zero_raw_ordered_range_pair_are_preserved() {
    let f=fixture(243,&[(2,0,16)],true,0,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    let frame=&object.raw_object().sections[0];assert_eq!(frame.relocations.iter().map(|r|r.kind).collect::<Vec<_>>(),vec![57,35,39]);
    assert_eq!(frame.relocations[0].symbol_index,2);assert_eq!(object.symbol_tables()[0].symbols[2].kind,0);
    assert_eq!(object.fdes()[0].extent.unwrap().size,16);assert_eq!(object.fdes()[0].relocation_rows.len(),3);
    let range=f.frame_at+f.fde_offsets[0]+12;assert_eq!(&f.bytes[range..range+4],&[0;4]);
    object.require_all_defined_functions_matched().unwrap();
}
#[test]
fn aliases_and_partial_overlaps_keep_all_functions_and_refuse_selection() {
    for extra in [(2,0,16),(2,8,8)] {
        let f=fixture(243,&[(2,0,16),extra],false,16,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
        assert_eq!(object.functions().len(),2);assert_eq!(object.symbol_tables()[0].symbols.len(),5);
        assert!(object.functions().iter().all(|f|f.error.as_deref().unwrap().contains("overlapping or aliased")));
        assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains("overlapping or aliased"));
        assert!(object.fdes()[0].error.is_some());assert!(object.require_all_defined_functions_matched().is_err());
    }
}
#[test]
fn duplicate_fdes_do_not_choose_first() {
    let f=fixture(243,&[(2,0,16)],false,16,2,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(object.fdes().len(),2);assert_eq!(object.extent_groups()[object.functions()[0].extent_group.unwrap()].fdes.len(),2);
    assert!(object.functions()[0].error.as_deref().unwrap().contains("multiple exact FDEs"));
    assert!(object.fdes().iter().all(|f|f.error.is_some()));
    assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains("multiple exact FDEs"));
}
#[test]
fn missing_extent_and_outside_extent_remain_unmet_without_guessing() {
    for (function, expected) in [((2,0,0),"size is zero"),((2,8,16),"outside its code section")] {
        let f=fixture(243,&[function],false,16,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
        assert_eq!(object.functions().len(),1);assert_eq!(object.fdes().len(),1);
        assert!(object.functions()[0].error.as_deref().unwrap().contains(expected));
        assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains(expected));
    }
}
#[test]
fn external_function_declaration_is_not_invented_local_body() {
    let f=fixture(243,&[(0,0,0)],false,16,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(object.functions()[0].disposition,"external_declaration");assert!(object.functions()[0].extent.is_none());
    assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains("not a uniquely associated defined function"));
    assert!(object.fdes()[0].error.as_deref().unwrap().contains("no unique exact"));
}
#[test]
fn zero_unrelocated_range_cannot_stand_for_unresolved_relocation() {
    let f=fixture(243,&[(2,0,16)],false,0,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(object.raw_object().sections[0].relocations.len(),1);
    assert!(object.fdes()[0].error.as_deref().unwrap().contains("range is zero"));
}
#[test]
fn nonzero_add_sub_raw_range_is_explicitly_unimplemented() {
    let f=fixture(243,&[(2,0,16)],true,1,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    let range=f.frame_at+f.fde_offsets[0]+12;assert_eq!(&f.bytes[range..range+4],&1i32.to_le_bytes());
    assert_eq!(object.raw_object().sections[0].relocations.len(),3);
    assert!(object.fdes()[0].error.as_deref().unwrap().contains("nonzero raw ADD32/SUB32"));
}
#[test]
fn implicit_addend_and_other_machine_fail_with_raw_rows_retained() {
    for (machine,implicit,expected) in [(243,true,"explicit-addend RELA"),(62,false,"unsupported for this ELF machine"),(183,false,"unsupported for this ELF machine")] {
        let f=fixture(machine,&[(2,0,16)],false,16,1,implicit);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
        assert_eq!(object.raw_object().sections[0].relocations.len(),1);
        assert_eq!(object.raw_object().sections[0].relocations[0].addend.is_none(),implicit);
        assert_eq!(object.functions().len(),1);assert!(object.fdes()[0].error.as_deref().unwrap().contains(expected));
    }
}
#[test]
fn changed_object_pin_and_unknown_symbol_are_rejected_before_selection() {
    let f=fixture(243,&[(2,0,16)],false,16,1,false);let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    let mut wrong=pin(&f);wrong.sha256="00".repeat(32);
    assert!(object.selected_fde(&wrong,key()).unwrap_err().to_string().contains("object pin differs"));
    assert!(object.selected_fde(&pin(&f),SymbolKey{symbol_table:5,symbol_index:99}).unwrap_err().to_string().contains("STT_FUNC symbol absent"));
    assert!(object.selected_fde(&pin(&f),key()).is_ok());
}
#[test]
fn changed_name_index_is_observed_and_refuses_partial_symbol_inventory() {
    let mut f=fixture(243,&[(2,0,16)],false,16,1,false);
    let sym_header=f.headers+5*64;let sym_at=u64::from_le_bytes(f.bytes[sym_header+24..sym_header+32].try_into().unwrap()) as usize;
    put32(&mut f.bytes,sym_at+24,u32::MAX);assert_eq!(&f.bytes[sym_at+24..sym_at+28],&u32::MAX.to_le_bytes());
    let object=inspect_elf64_le_rel(&f.bytes).unwrap();assert_eq!(object.symbol_tables()[0].symbols.len(),4);
    assert!(object.symbol_tables()[0].symbols[1].error.as_deref().unwrap().contains("outside retained strings"));
    assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains("symbol inventory incomplete"));
}

// Mutations operate on actual retained RELA rows; each oracle inspects the
// resulting row identity/state before asserting its intended success/refusal.
fn rewrite_rela(f: &mut Fixture, row: usize, offset: Option<u64>, symbol: Option<u32>, addend: i64) {
    let header=f.headers+6*64;
    assert_eq!(u32::from_le_bytes(f.bytes[header+4..header+8].try_into().unwrap()),4);
    assert_eq!(u64::from_le_bytes(f.bytes[header+56..header+64].try_into().unwrap()),24);
    let table=u64::from_le_bytes(f.bytes[header+24..header+32].try_into().unwrap()) as usize;
    let at=table+row*24;
    if let Some(offset)=offset {put64(&mut f.bytes,at,offset);}
    if let Some(symbol)=symbol {
        let info=u64::from_le_bytes(f.bytes[at+8..at+16].try_into().unwrap());
        put64(&mut f.bytes,at+8,(u64::from(symbol)<<32)|(info & 0xffff_ffff));
    }
    f.bytes[at+16..at+24].copy_from_slice(&addend.to_le_bytes());
}
fn distinct_pair_fixture() -> Fixture {
    let mut f=fixture_with_profile(243,&[(2,0,16),(2,16,16)],true,0,2,false,32,false);
    rewrite_rela(&mut f,3,None,Some(2),0); // second PC: function2 at16
    rewrite_rela(&mut f,4,None,Some(2),16); // second end: function2+16
    rewrite_rela(&mut f,5,None,Some(2),0); // second base: function2
    f
}
#[test]
fn ambiguity_relations_use_one_shared_complete_extent_group() {
    let f=fixture(243,&vec![(2,0,16);64],false,16,64,false);
    let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(object.functions().len(),64);assert_eq!(object.fdes().len(),64);
    assert_eq!(object.extent_groups().len(),1);
    let group=&object.extent_groups()[0];assert_eq!(group.functions.len()+group.fdes.len(),128);
    assert!(object.functions().iter().all(|row|row.extent_group==Some(0) && row.error.is_some()));
    assert!(object.fdes().iter().all(|row|row.extent_group==Some(0) && row.error.is_some()));
    let value=serde_json::to_value(&object).unwrap();
    assert!(value["functions"].as_array().unwrap().iter().all(|row|row.get("fdes").is_none()));
    assert!(value["fdes"].as_array().unwrap().iter().all(|row|row.get("candidates").is_none()));
    assert_eq!(value["extent_groups"][0]["functions"].as_array().unwrap().len(),64);
    assert_eq!(value["extent_groups"][0]["fdes"].as_array().unwrap().len(),64);
    assert!(object.selected_fde(&pin(&f),key()).unwrap_err().to_string().contains("overlapping or aliased"));
}
#[test]
fn earlier_pair_does_not_poison_later_distinct_fde_header() {
    let f=distinct_pair_fixture();let object=inspect_elf64_le_rel(&f.bytes).unwrap();
    let raw=object.raw_object();assert_eq!(raw.sections[0].relocations.len(),6);
    assert_eq!(raw.sections[0].relocations[3].symbol_index,2);
    assert_eq!(raw.sections[0].relocations[4].addend,Some(16));
    assert_eq!(raw.sections[0].relocations[5].addend,Some(0));
    assert_eq!(raw.sections[0].relocations[1].kind,35);assert_eq!(raw.sections[0].relocations[2].kind,39);
    assert!(raw.sections[0].relocations[1].offset < f.fde_offsets[1] as u64);
    let fdes=raw.sections[0].records.iter().filter_map(|r|if let RawRecord::Fde(fde)=r {Some(fde)}else{None}).collect::<Vec<_>>();
    assert_eq!(fdes.len(),2);assert!(fdes.iter().all(|fde|fde.error.is_none() && fde.cie_section_offset==Some(0)));
    object.require_initial_rules_decoded().unwrap();object.require_all_defined_functions_matched().unwrap();
    assert_eq!(object.extent_groups().len(),2);
    assert_eq!(object.selected_fde(&pin(&f),key()).unwrap().fde_section_offset,f.fde_offsets[0]);
    assert_eq!(object.selected_fde(&pin(&f),SymbolKey{symbol_table:5,symbol_index:2}).unwrap().fde_section_offset,f.fde_offsets[1]);
}
#[test]
fn known_pair_width_does_not_authorize_initial_program_or_fde_header_overlap() {
    for header in [false,true] {
        let mut f=distinct_pair_fixture();let before=inspect_elf64_le_rel(&f.bytes).unwrap();
        before.require_all_defined_functions_matched().unwrap();
        let initial=before.raw_object().sections[0].records.iter().find_map(|r|if let RawRecord::Cie(cie)=r {cie.initial_instructions.as_ref().map(|span|span.section_offset)}else{None}).unwrap();
        let offset=if header {f.fde_offsets[1]+4}else{initial};
        rewrite_rela(&mut f,1,Some(offset as u64),None,0);rewrite_rela(&mut f,2,Some(offset as u64),None,0);
        let after=inspect_elf64_le_rel(&f.bytes).unwrap();let raw=after.raw_object();
        assert_eq!(raw.sections[0].relocations.len(),6);
        assert_eq!(raw.sections[0].relocations[1].offset,offset as u64);assert_eq!(raw.sections[0].relocations[2].offset,offset as u64);
        if header {
            let fde=raw.sections[0].records.iter().find_map(|r|if let RawRecord::Fde(fde)=r {if fde.range.section_offset==f.fde_offsets[1] {Some(fde)}else{None}}else{None}).unwrap();
            assert!(fde.cie_section_offset.is_none());
            assert!(fde.error.as_deref().unwrap().contains("overlaps FDE length/CIE backreference"));
        } else {
            let cie=raw.sections[0].records.iter().find_map(|r|if let RawRecord::Cie(cie)=r {Some(cie)}else{None}).unwrap();
            assert!(cie.initial_rules.is_none());assert!(cie.error.as_deref().unwrap().contains("overlaps CIE header/initial rules"));
        }
        assert!(after.require_initial_rules_decoded().is_err());
    }
}
#[test]
fn known_pair_width_does_not_widen_personality_expression_policy() {
    let mut f=fixture_with_profile(243,&[(2,0,16)],true,0,1,false,16,true);
    let before=inspect_elf64_le_rel(&f.bytes).unwrap();before.require_all_defined_functions_matched().unwrap();
    let pointer=before.raw_object().sections[0].records.iter().find_map(|r|if let RawRecord::Cie(cie)=r {cie.personality.as_ref().map(|p|p.range.section_offset)}else{None}).unwrap();
    rewrite_rela(&mut f,1,Some(pointer as u64),None,0);rewrite_rela(&mut f,2,Some(pointer as u64),None,0);
    let after=inspect_elf64_le_rel(&f.bytes).unwrap();let raw=after.raw_object();assert_eq!(raw.sections[0].relocations.len(),3);
    let cie=raw.sections[0].records.iter().find_map(|r|if let RawRecord::Cie(cie)=r {Some(cie)}else{None}).unwrap();
    let slot=cie.personality.as_ref().unwrap();assert_eq!(slot.range.section_offset,pointer);
    assert_eq!(raw.sections[0].relocations[1].offset,pointer as u64);assert_eq!(raw.sections[0].relocations[2].offset,pointer as u64);
    assert_eq!(raw.sections[0].relocations[1].kind,35);assert_eq!(raw.sections[0].relocations[2].kind,39);
    assert!(slot.range.bytes.iter().all(|b|*b==0));assert!(cie.initial_rules.is_none());
    assert!(cie.error.as_deref().unwrap().contains("overlaps CIE header/initial rules"));
    assert!(after.require_initial_rules_decoded().is_err());
}
