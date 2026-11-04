//! Authored inert DATA; no genuine original compiler/capture or native execution.
use super::*;
use serde_json::json;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Item { recipe: Vec<u8>, dependencies: BTreeMap<String, String>, compound: CompoundBindings }
struct Fixture { directory: PathBuf, items: BTreeMap<String, Item>, policy: Value }
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("membership-DATA-{}-{}-{}",std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),NEXT.fetch_add(1,Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let mut items = BTreeMap::new();
        let members = BTreeMap::from([("zlib".into(),"provider-zlib".into()),
            ("bzip2".into(),"provider-bzip2".into()),("xz".into(),"provider-xz".into())]);
        items.insert("engine".into(),Item { recipe:serde_json::to_vec(&json!({"schema":source_recipe::RECIPE_FORMAT,
            "source":{"fixture_original":"engine"},"dependencies":[{"name":"compression","source_pin":null,"fixture_role":"unchanged"}]})).unwrap(),
            dependencies:BTreeMap::new(),compound:BTreeMap::from([("compression".into(),members)]) });
        for member in ["zlib","bzip2","xz"] {
            items.insert(format!("provider-{member}"),Item {recipe:serde_json::to_vec(&json!({"schema":source_recipe::RECIPE_FORMAT,
                "source":{"fixture_original":member,"version":"DATA-only"},"dependencies":[]})).unwrap(),
                dependencies:BTreeMap::new(),compound:BTreeMap::new()});
        }
        let mut f=Self {directory,items,policy:Value::Null}; f.reset();f.write();f
    }
    fn inputs(&self)->Vec<Input<'_>> { self.items.iter().map(|(name,x)|Input{name,recipe:&x.recipe,
        dependencies:&x.dependencies,compound:&x.compound}).collect() }
    fn reset(&mut self) {
        let rows:Vec<Value>=self.items.iter().map(|(name,x)| {
            let recipe:Value=serde_json::from_slice(&x.recipe).unwrap();let mut labels=serde_json::Map::new();
            for(label,bindings)in &x.compound {
                let declaration=recipe["dependencies"].as_array().unwrap().iter().find(|v|v["name"].as_str()==Some(label.as_str())).unwrap();
                let sources:BTreeMap<String,Value>=bindings.iter().map(|(member,provider)| {
                    let r:Value=serde_json::from_slice(&self.items[provider].recipe).unwrap();(member.clone(),r["source"].clone())
                }).collect();labels.insert(label.clone(),json!({"declaration":declaration,"members":sources}));
            }
            json!({"component":name,"recipe":{"bytes":x.recipe.len(),"sha256":digest(&x.recipe)},"compound_dependencies":labels})
        }).collect();self.policy=json!({"schema":POLICY_SCHEMA,"components":rows});
    }
    fn component(&mut self,name:&str)->&mut Value {self.policy["components"].as_array_mut().unwrap().iter_mut().find(|x|x["component"]==name).unwrap()}
    fn members(&mut self)->&mut serde_json::Map<String,Value> {self.component("engine")["compound_dependencies"]["compression"]["members"].as_object_mut().unwrap()}
    fn path(&self)->PathBuf{self.directory.join("policy.json")}
    fn write_raw(&self,raw:&[u8]){fs::write(self.path(),raw).unwrap();assert_eq!(fs::read(self.path()).unwrap(),raw,"mutation must reach actual selected file");}
    fn write(&self){self.write_raw(&serde_json::to_vec(&self.policy).unwrap());}
    fn pin(&self)->provider_order::OrderPin {let raw=fs::read(self.path()).unwrap();provider_order::OrderPin{path:self.path(),bytes:raw.len()as u64,sha256:digest(&raw)}}
    fn select(&self)->Result<SelectedMembership>{SelectedMembership::read(&self.pin(),&self.inputs())}
    fn refuses(&self,reason:&str){reject(self.select(),reason);}
}
fn reject<T>(result:Result<T>,reason:&str){let e=match result{Ok(_)=>panic!("unexpected acceptance; expected {reason}"),Err(e)=>e};
    assert!(format!("{e:#}").contains(reason),"wrong refusal: {e:#}; expected {reason}");}

#[test]
fn three_original_members_and_detached_external_roundtrip(){
    let f=Fixture::new();assert_eq!(f.items["engine"].compound["compression"].len(),3);
    let selected=f.select().unwrap();selected.check_unchanged().unwrap();let package=selected.package();package.check(&f.inputs()).unwrap();
    let detached:PackagedMembership=serde_json::from_slice(&serde_json::to_vec(&package).unwrap()).unwrap();
    detached.require_external(Some(&selected),&f.inputs()).unwrap();
}
#[test]
fn maps_are_membership_not_link_order(){
    let mut f=Fixture::new();let old=f.items["engine"].compound["compression"].clone();
    let reversed=old.iter().rev().map(|(k,v)|(k.clone(),v.clone())).collect();
    f.items.get_mut("engine").unwrap().compound.insert("compression".into(),reversed);
    assert_eq!(f.items["engine"].compound["compression"],old);
    f.policy["components"].as_array_mut().unwrap().reverse();assert_eq!(f.policy["components"][0]["component"],"provider-zlib");
    let members=f.members().clone();let forward=serde_json::to_string(&members).unwrap();
    let reversed=format!("{{{}}}",members.iter().rev().map(|(k,v)|format!("{}:{}",serde_json::to_string(k).unwrap(),serde_json::to_string(v).unwrap())).collect::<Vec<_>>().join(","));
    assert_ne!(forward,reversed,"actual raw member order must change");
    let original=serde_json::to_string(&f.policy).unwrap();assert_eq!(original.matches(&forward).count(),1);
    let reordered=original.replacen(&forward,&reversed,1);assert_ne!(original,reordered);
    assert_eq!(serde_json::from_str::<Value>(&reordered).unwrap(),f.policy,"member order changes raw bytes, not membership");
    f.write_raw(reordered.as_bytes());f.select().unwrap().package().check(&f.inputs()).unwrap();
}
#[test]
fn missing_each_member_and_extra_member_are_rejected(){
    for member in ["zlib","bzip2","xz"]{let mut f=Fixture::new();assert!(f.members().remove(member).is_some());assert!(!f.members().contains_key(member));assert_eq!(f.members().len(),2);
        f.write();f.refuses("compound member set differs");}
    let mut f=Fixture::new();f.members().insert("extra".into(),json!({"fixture_original":"extra"}));assert_eq!(f.members().len(),4);assert!(f.members().contains_key("extra"));
    f.write();f.refuses("compound member set differs");
}
#[test]
fn wrong_source_and_empty_source_are_rejected(){
    let mut f=Fixture::new();f.members().insert("zlib".into(),json!({"fixture_original":"substitute"}));assert_eq!(f.members()["zlib"]["fixture_original"],"substitute");
    f.write();f.refuses("compound member source differs: engine/compression/zlib");
    let mut f=Fixture::new();let item=f.items.get_mut("provider-xz").unwrap();let mut r:Value=serde_json::from_slice(&item.recipe).unwrap();r["source"]=json!({});assert_eq!(r["source"],json!({}));
    item.recipe=serde_json::to_vec(&r).unwrap();f.reset();f.write();f.refuses("membership recipe source must be a nonempty object");
}
#[test]
fn ambiguous_and_unknown_provider_components_are_rejected(){
    let mut f=Fixture::new();f.items.get_mut("engine").unwrap().compound.get_mut("compression").unwrap().insert("xz".into(),"provider-zlib".into());
    assert_eq!(f.items["engine"].compound["compression"]["xz"],f.items["engine"].compound["compression"]["zlib"]);f.refuses("ambiguous compound members share one provider component");
    let mut f=Fixture::new();f.items.get_mut("engine").unwrap().compound.get_mut("compression").unwrap().insert("xz".into(),"unknown".into());
    assert!(!f.items.contains_key("unknown"));f.refuses("membership binding names unknown provider component");
}
#[test]
fn singular_source_pin_cannot_be_erased_by_compound_binding(){
    let mut f=Fixture::new();let item=f.items.get_mut("engine").unwrap();let mut r:Value=serde_json::from_slice(&item.recipe).unwrap();
    r["dependencies"][0]["source_pin"]=json!({"retained":"singular-original-pin"});assert!(!r["dependencies"][0]["source_pin"].is_null());item.recipe=serde_json::to_vec(&r).unwrap();
    f.reset();f.write();f.refuses("compound dependency retains non-null singular source_pin");
}
#[test]
fn duplicate_raw_keys_are_rejected_recursively(){
    let f=Fixture::new();let raw=serde_json::to_string(&f.policy).unwrap();assert_eq!(raw.matches("\"name\":\"compression\"").count(),1);
    let raw=raw.replace("\"name\":\"compression\"","\"name\":\"compression\",\"name\":\"compression\"");
    assert_eq!(raw.matches("\"name\":\"compression\"").count(),2);assert!(serde_json::from_str::<Value>(&raw).is_ok());f.write_raw(raw.as_bytes());
    f.refuses("membership policy raw JSON must have unique keys");
}
#[test]
fn actual_declaration_and_raw_recipe_fingerprint_are_retained(){
    let mut f=Fixture::new();f.component("engine")["compound_dependencies"]["compression"]["declaration"]["fixture_role"]=json!("forged");
    assert_eq!(f.component("engine")["compound_dependencies"]["compression"]["declaration"]["fixture_role"],"forged");f.write();f.refuses("compound declaration differs");
    let mut f=Fixture::new();let old=digest(&f.items["provider-zlib"].recipe);f.items.get_mut("provider-zlib").unwrap().recipe.push(b' ');
    assert_ne!(old,digest(&f.items["provider-zlib"].recipe));assert!(serde_json::from_slice::<Value>(&f.items["provider-zlib"].recipe).is_ok());f.refuses("membership policy recipe pin differs: provider-zlib");
}

#[test]
fn missing_extra_and_duplicate_components_are_rejected(){
    for extra in [false,true]{let mut f=Fixture::new();let rows=f.policy["components"].as_array_mut().unwrap();
        if extra{let mut x=rows[0].clone();x["component"]=json!("extra-component");rows.push(x);assert_eq!(rows.len(),5);}
        else{rows.pop().unwrap();assert_eq!(rows.len(),3);}f.write();f.refuses("membership policy component set differs");}
    let mut f=Fixture::new();let rows=f.policy["components"].as_array_mut().unwrap();let x=rows[0].clone();rows.push(x);assert_eq!(rows[0]["component"],rows[4]["component"]);
    f.write();f.refuses("duplicate membership policy component");
    let f=Fixture::new();let mut inputs=f.inputs();let x=&f.items["engine"];inputs.push(Input{name:"engine",recipe:&x.recipe,dependencies:&x.dependencies,compound:&x.compound});
    assert_eq!(inputs.iter().filter(|x|x.name=="engine").count(),2);reject(SelectedMembership::read(&f.pin(),&inputs),"duplicate membership input component");
}
#[test]
fn exact_compound_labels_and_legacy_overlap_are_enforced(){
    for extra in [false,true]{let mut f=Fixture::new();let labels=f.component("engine")["compound_dependencies"].as_object_mut().unwrap();
        if extra{let x=labels["compression"].clone();labels.insert("extra-label".into(),x);assert_eq!(labels.len(),2);}
        else{assert!(labels.remove("compression").is_some());assert!(labels.is_empty());}f.write();f.refuses("membership compound label set differs");}
    let mut f=Fixture::new();f.items.get_mut("engine").unwrap().dependencies.insert("compression".into(),"provider-zlib".into());
    assert!(f.items["engine"].compound.contains_key("compression"));assert!(f.items["engine"].dependencies.contains_key("compression"));f.refuses("legacy/compound dependency label overlap");
}
#[test]
fn malformed_or_empty_member_floor_and_absent_compound_are_rejected(){
    for bad in [""," spaced","line\nidentity"]{let mut f=Fixture::new();let m=f.items.get_mut("engine").unwrap().compound.get_mut("compression").unwrap();
        let provider=m.remove("xz").unwrap();m.insert(bad.into(),provider);assert!(m.contains_key(bad));assert!(!m.contains_key("xz"));f.refuses("malformed compound member identity");}
    let mut f=Fixture::new();f.items.get_mut("engine").unwrap().compound.get_mut("compression").unwrap().clear();assert!(f.items["engine"].compound["compression"].is_empty());f.refuses("compound member bindings empty");
    let mut f=Fixture::new();let x=f.items.get_mut("engine").unwrap();x.compound.clear();let mut r:Value=serde_json::from_slice(&x.recipe).unwrap();r["dependencies"]=json!([]);x.recipe=serde_json::to_vec(&r).unwrap();
    assert!(f.items.values().all(|x|x.compound.is_empty()));f.reset();f.write();f.refuses("membership V5 requires at least one compound dependency");
}
#[test]
fn legacy_dependency_map_is_preserved_without_becoming_compound(){
    let mut f=Fixture::new();let x=f.items.get_mut("engine").unwrap();x.dependencies.insert("legacy-zlib".into(),"provider-zlib".into());
    let mut r:Value=serde_json::from_slice(&x.recipe).unwrap();r["dependencies"].as_array_mut().unwrap().push(json!({"name":"legacy-zlib","source_pin":null}));x.recipe=serde_json::to_vec(&r).unwrap();
    f.reset();f.write();assert_eq!(f.items["engine"].dependencies.len(),1);assert!(!f.items["engine"].compound.contains_key("legacy-zlib"));
    f.select().unwrap().package().check(&f.inputs()).unwrap();
}
#[test]
fn same_bytes_atomic_policy_replacement_invalidates_capability(){
    let f=Fixture::new();let selected=f.select().unwrap();let old=fs::metadata(f.path()).unwrap();let raw=fs::read(f.path()).unwrap();
    let replacement=f.directory.join("replacement.json");fs::write(&replacement,&raw).unwrap();fs::set_permissions(&replacement,fs::Permissions::from_mode(old.mode()&0o7777)).unwrap();
    fs::rename(&replacement,f.path()).unwrap();let current=fs::metadata(f.path()).unwrap();
    assert_ne!(old.ino(),current.ino(),"actual atomic replacement must occur");assert_eq!(digest(&fs::read(f.path()).unwrap()),digest(&raw));assert_eq!(old.mode(),current.mode());
    reject(selected.check_unchanged(),"membership policy physical identity changed");
}
#[test]
fn detached_internal_consistency_never_authorizes_external_floor(){
    let f=Fixture::new();let selected=f.select().unwrap();let mut package=selected.package();package.check(&f.inputs()).unwrap();
    reject(package.require_external(None,&f.inputs()),"separately selected membership policy required");
    package.policy_pin.path=f.directory.join("deliberately-absent.json");assert!(!package.policy_pin.path.exists());
    package.check(&f.inputs()).unwrap();reject(package.require_external(Some(&selected),&f.inputs()),"external membership policy pin/raw differs");
}
#[test]
fn recomputed_detached_source_forgery_cannot_replace_held_floor(){
    let mut f=Fixture::new();let selected=f.select().unwrap();let original=selected.raw.clone();let mut forged=selected.package();
    let x=f.items.get_mut("provider-xz").unwrap();let mut r:Value=serde_json::from_slice(&x.recipe).unwrap();r["source"]=json!({"fixture_original":"substitute-xz"});
    x.recipe=serde_json::to_vec(&r).unwrap();f.reset();forged.policy_raw=serde_json::to_string(&f.policy).unwrap();
    forged.policy_sha256=digest(forged.policy_raw.as_bytes());forged.policy_pin.sha256=forged.policy_sha256.clone();forged.policy_pin.bytes=forged.policy_raw.len()as u64;
    assert_ne!(forged.policy_raw,original);assert_eq!(fs::read(f.path()).unwrap(),original.as_bytes(),"external floor must remain fixed");
    forged.check(&f.inputs()).unwrap();reject(forged.require_external(Some(&selected),&f.inputs()),"external membership policy pin/raw differs");selected.check_unchanged().unwrap();
}
#[test]
fn package_and_policy_typed_schemas_fail_closed(){
    let f=Fixture::new();let package=f.select().unwrap().package();let mut raw=serde_json::to_value(&package).unwrap();raw["extra_authority"]=json!(true);assert_eq!(raw["extra_authority"],true);
    let error=serde_json::from_value::<PackagedMembership>(raw).unwrap_err();assert!(error.to_string().contains("unknown field"));
    let mut f=Fixture::new();f.policy["schema"]=json!("unselected-schema");assert_eq!(f.policy["schema"],"unselected-schema");f.write();f.refuses("unsupported membership policy schema");
    let mut package=package;package.policy_pin.path=PathBuf::from("relative-policy.json");assert!(!package.policy_pin.path.is_absolute());
    reject(package.check(&f.inputs()),"membership policy path must be absolute and lexical-normal");
}
