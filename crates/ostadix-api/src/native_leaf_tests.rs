//! Independent boundary tests using verified modules, owned emission and real
//! sealed host executables. No supplied ELF or mocked compiler stands in for
//! the native leaf under test.

use super::*;
use serde_json::{json, Value as Json};

fn descriptor(arity: usize) -> Json {
    serde_json::from_str(&test_descriptor(arity, false)).unwrap()
}

fn verified(value: &Json) {
    NativeModule::from_json(&serde_json::to_vec(&value["module"]).unwrap())
        .unwrap_or_else(|error| panic!("invalid boundary fixture: {}", error.message));
}

fn rejects_valid_module(value: &Json, arity: usize) {
    verified(value);
    assert!(validate_descriptor(&value.to_string(), arity).is_err());
}

fn constant_return(ty: usize, bits: &str) -> Json {
    json!({"op":"return","value":{"kind":"int","ty":ty,"bits":bits}})
}

#[test]
fn unused_inventory_cannot_hide_external_storage_aliases_groups_or_effects() {
    let base = descriptor(1);
    verified(&base);
    for case in 0..5 {
        let mut value = base.clone();
        match case {
            0 => {
                value["module"]["globals"] = json!([{
                    "name":"unused_storage","ty":1,"linkage":"external","alignment":8,
                    "constant":false,"thread_local":false,
                    "initializer":{"bytes":[0,0,0,0,0,0,0,0],"relocations":[]}
                }]);
                value["module"]["provenance"]["source_global_count"] = json!(1);
            }
            1 => {
                let signature = value["module"]["functions"][0]["signature"].clone();
                value["module"]["types"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"kind":"function","signature":signature}));
                value["module"]["aliases"] = json!([{
                    "name":"unused_alias","ty":3,"aliasee":"native_add","linkage":"external"
                }]);
                value["module"]["provenance"]["source_alias_count"] = json!(1);
            }
            2 => {
                value["module"]["comdats"] = json!([{"name":"unused_group","selection":"any"}]);
                value["module"]["provenance"]["referenced_comdat_count"] = json!(1);
                value["module"]["functions"][0]["comdat"] = json!("unused_group");
                value["module"]["functions"][0]["linkage"] = json!("linkonce_odr");
            }
            3 | 4 => {
                let mut function = value["module"]["functions"][0].clone();
                function["name"] = json!("unused_function");
                if case == 3 {
                    function["entry"] = Json::Null;
                    function["blocks"] = json!([]);
                } else {
                    value["module"]["types"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"kind":"pointer","address_space":0}));
                    function["blocks"][0]["instructions"] = json!([{
                        "result":{"id":1,"ty":3},
                        "operation":{"op":"alloca","size":8,"alignment":8}
                    }]);
                    function["blocks"][0]["terminator"] = constant_return(1, "0");
                }
                value["module"]["functions"]
                    .as_array_mut()
                    .unwrap()
                    .push(function);
                value["module"]["provenance"]["source_function_count"] = json!(2);
            }
            _ => unreachable!(),
        }
        rejects_valid_module(&value, 1);
    }
}

#[test]
fn unreachable_effects_and_cycles_reject_but_duplicate_dag_edges_remain_legal() {
    let mut cycle = descriptor(1);
    cycle["module"]["functions"][0]["blocks"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":99,"instructions":[],"terminator":{"op":"jump","target":99}
        }));
    verified(&cycle);
    let error = validate_descriptor(&cycle.to_string(), 1).unwrap_err();
    assert!(format!("{error:#}").contains("acyclic"));

    let mut effects = descriptor(1);
    effects["module"]["types"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"pointer","address_space":0}));
    effects["module"]["functions"][0]["blocks"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":99,"instructions":[{"result":{"id":2,"ty":3},
                "operation":{"op":"alloca","size":8,"alignment":8}}],
            "terminator":constant_return(1,"0")
        }));
    rejects_valid_module(&effects, 1);

    let mut dag = descriptor(1);
    dag["module"]["functions"][0]["blocks"][0]["terminator"] = json!({
        "op":"switch","condition":{"kind":"value","id":0},"default":7,
        "cases":[{"value":{"kind":"int","ty":1,"bits":"0"},"target":7}]
    });
    dag["module"]["functions"][0]["blocks"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":7,"instructions":[],"terminator":constant_return(1,"9")
        }));
    verified(&dag);
    validate_descriptor(&dag.to_string(), 1).unwrap();
}

#[test]
fn entry_identity_and_every_original_signature_require_the_exact_scalar_contract() {
    let base = descriptor(1);
    assert!(validate_descriptor(&base.to_string(), 0).is_err());
    for case in 0..7 {
        let mut value = base.clone();
        match case {
            0 => value["entry"] = json!("absent_entry"),
            1 | 2 => {
                let name = if case == 1 {
                    "_start"
                } else {
                    "__ostadix_leaf_reserved"
                };
                value["entry"] = json!(name);
                value["module"]["functions"][0]["name"] = json!(name);
            }
            3 => {
                value["module"]["functions"][0]["signature"]["params"] = json!([2]);
                value["module"]["functions"][0]["params"][0]["ty"] = json!(2);
                value["module"]["functions"][0]["blocks"][0]["instructions"] = json!([]);
                value["module"]["functions"][0]["blocks"][0]["terminator"] =
                    constant_return(1, "0");
            }
            4 => {
                value["module"]["functions"][0]["signature"]["result"] = json!(2);
                value["module"]["functions"][0]["blocks"][0]["instructions"] = json!([]);
                value["module"]["functions"][0]["blocks"][0]["terminator"] =
                    constant_return(2, "1");
            }
            5 => value["module"]["functions"][0]["signature"]["abi"] = json!("fastcc"),
            6 => value["module"]["functions"][0]["signature"]["variadic"] = json!(true),
            _ => unreachable!(),
        }
        rejects_valid_module(&value, 1);
    }
    let mut trap: Json = serde_json::from_str(&test_descriptor(1, true)).unwrap();
    trap["entry"] = json!("llvm.trap");
    rejects_valid_module(&trap, 0);
}

#[test]
fn scalar_crossing_rejects_rounding_overflow_and_noncanonical_signed_text() {
    for value in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX] {
        assert_eq!(argument(&OValue::big_int(value)).unwrap(), value);
        assert_eq!(argument(&OValue::str_(value.to_string())).unwrap(), value);
    }
    for value in [
        num_bigint::BigInt::from(i64::MIN) - 1u8,
        num_bigint::BigInt::from(i64::MAX) + 1u8,
    ] {
        assert!(argument(&OValue::big_int(value)).is_err());
    }
    for text in [
        "-0",
        "00",
        "+0",
        " 0",
        "0\n",
        "1e0",
        "1.0",
        "-9223372036854775809",
        "9223372036854775808",
    ] {
        assert!(argument(&OValue::str_(text)).is_err(), "{text:?}");
    }
    assert!(argument(&OValue::Bool { v: false }).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn environment_binding_distinguishes_absence_empty_sentinel_and_raw_unix_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let absent = tool_environment_sha256(None);
    for value in [
        OsStr::new(""),
        OsStr::new("LC_ALL=C;LD_LIBRARY_PATH=absent"),
    ] {
        assert_ne!(absent, tool_environment_sha256(Some(value)));
    }
    assert_ne!(
        tool_environment_sha256(Some(OsStr::from_bytes(&[0xff]))),
        tool_environment_sha256(Some(OsStr::from_bytes(&[0xfe])))
    );
    assert_eq!(
        tool_environment_sha256(Some(OsStr::new("/a:/b"))),
        tool_environment_sha256(Some(OsStr::new("/a:/b")))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn actual_owned_kernel_preserves_signed_word_boundaries_and_zero_argument_frames() {
    let zero = prepare(&test_descriptor(0, false)).unwrap();
    assert_eq!(argument(&zero.execute(&[]).unwrap()).unwrap(), 1);
    assert!(zero.execute(&[0]).is_err());
    let leaf = prepare(&test_descriptor(1, false)).unwrap();
    for value in [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX] {
        assert_eq!(
            argument(&leaf.execute(&[value]).unwrap()).unwrap(),
            value.wrapping_add(1)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_protocol_refuses_short_extra_and_wrong_magic_frames() {
    fn exchange(leaf: &PreparedLeaf, bytes: &[u8]) -> std::process::Output {
        let mut child = leaf
            .image
            .command()
            .unwrap()
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    }
    let leaf = prepare(&test_descriptor(1, false)).unwrap();
    let mut correct = MAGIC.to_le_bytes().to_vec();
    correct.extend_from_slice(&41i64.to_le_bytes());
    let mut wrong = correct.clone();
    wrong[0] ^= 0xff;
    let mut extra = correct.clone();
    extra.push(0);
    for frame in [Vec::new(), correct[..8].to_vec(), wrong, extra] {
        let output = exchange(&leaf, &frame);
        assert!(
            !output.status.success(),
            "malformed frame accepted: {frame:?}"
        );
        assert!(output.stdout.is_empty());
    }
    let output = exchange(&leaf, &correct);
    assert!(output.status.success());
    assert_eq!(output.stdout[..8], MAGIC.to_le_bytes());
    assert_eq!(output.stdout.len(), 16);
    assert_eq!(
        i64::from_le_bytes(output.stdout[8..].try_into().unwrap()),
        42
    );
}

#[cfg(target_os = "linux")]
#[test]
fn manifest_and_lease_metadata_tampering_cannot_launch_a_prepared_kernel() {
    let mut leaf = prepare(&test_descriptor(1, false)).unwrap();
    let original = leaf.manifest.clone();
    assert!(original.tool_working_directory.is_absolute());
    assert_eq!(
        original.tool_working_directory,
        std::env::current_dir().unwrap()
    );
    Arc::get_mut(&mut leaf)
        .unwrap()
        .manifest
        .tool_working_directory
        .push("changed-working-directory");
    assert!(leaf.verify().is_err());
    Arc::get_mut(&mut leaf).unwrap().manifest = original.clone();
    for case in 0..3 {
        let mutable = Arc::get_mut(&mut leaf).unwrap();
        match case {
            0 => mutable.manifest.entry = "different_valid_symbol".into(),
            1 => mutable.manifest.parameter_count += 1,
            2 => mutable.manifest.executable_sha256 = "0".repeat(64),
            _ => unreachable!(),
        }
        assert!(leaf.verify().is_err());
        let count = leaf.manifest.parameter_count;
        assert!(leaf.execute(&vec![0; count]).is_err());
        Arc::get_mut(&mut leaf).unwrap().manifest = original.clone();
        leaf.verify().unwrap();
    }
    let original_bytes = leaf.image.bytes;
    Arc::get_mut(&mut leaf).unwrap().image.bytes += 1;
    assert!(leaf.verify().is_err());
    assert!(leaf.execute(&[0]).is_err());
    Arc::get_mut(&mut leaf).unwrap().image.bytes = original_bytes;
    assert_eq!(argument(&leaf.execute(&[41]).unwrap()).unwrap(), 42);
}

// ############################################################################
// division parity: owned native code against the reference interpreter
// ############################################################################

/// One divisor or dividend: a runtime parameter or a literal folded into the
/// module, so the emitter sees a known constant.
#[derive(Clone, Copy, Debug)]
enum Side {
    Runtime(i64),
    Constant(i64),
}

impl Side {
    fn value(self) -> i64 {
        match self {
            Side::Runtime(value) | Side::Constant(value) => value,
        }
    }
}

/// A two-parameter leaf computing `kind` at `width` (1 or 64). an i1 leaf
/// truncates its i64 inputs, divides at i1 and sign-extends the answer, so
/// the guards under test run at i1 while the leaf keeps the i64 interface.
fn division_leaf(kind: &str, width: u16, lhs: Side, rhs: Side) -> Json {
    let ty = if width == 1 { 2 } else { 1 };
    let mut instructions = Vec::new();
    let mut next = 2;
    let mut operand = |side: Side, param: usize, instructions: &mut Vec<Json>| match side {
        Side::Constant(value) => {
            let bits = if width == 1 {
                (value & 1) as u64
            } else {
                value as u64
            };
            json!({"kind":"int","ty":ty,"bits":bits.to_string()})
        }
        Side::Runtime(_) if width == 1 => {
            let id = next;
            next += 1;
            instructions.push(json!({"result":{"id":id,"ty":2},"operation":{"op":"cast","kind":"trunc","value":{"kind":"value","id":param}}}));
            json!({"kind":"value","id":id})
        }
        Side::Runtime(_) => json!({"kind":"value","id":param}),
    };
    let lhs = operand(lhs, 0, &mut instructions);
    let rhs = operand(rhs, 1, &mut instructions);
    let quotient = next;
    instructions.push(json!({"result":{"id":quotient,"ty":ty},"operation":{"op":"binary","kind":kind,"lhs":lhs,"rhs":rhs,"flags":[]}}));
    let mut result = json!({"kind":"value","id":quotient});
    if width == 1 {
        instructions.push(json!({"result":{"id":quotient + 1,"ty":1},"operation":{"op":"cast","kind":"s_ext","value":result}}));
        result = json!({"kind":"value","id":quotient + 1});
    }
    let mut leaf = descriptor(2);
    let function = &mut leaf["module"]["functions"][0];
    function["blocks"][0]["instructions"] = Json::Array(instructions);
    function["blocks"][0]["terminator"] = json!({"op":"return","value":result});
    leaf
}

#[cfg(target_os = "linux")]
#[test]
fn division_matches_the_interpreter_at_i1_and_i64_through_owned_native_code() {
    use crate::ocore::native_interpret::evaluate;
    use num_bigint::BigUint;
    use Side::{Constant, Runtime};
    let mut cases = Vec::new();
    for (width, minimum) in [(1_u16, -1_i64), (64, i64::MIN)] {
        for kind in ["s_div", "s_rem", "u_div", "u_rem"] {
            for (lhs, rhs) in [
                // division by zero traps whether the zero is known or not.
                (Runtime(7), Constant(0)),
                (Runtime(7), Runtime(0)),
                (Constant(minimum), Runtime(0)),
                // MIN / -1: sdiv gives MIN, srem gives 0; nothing traps.
                (Runtime(minimum), Constant(-1)),
                (Runtime(minimum), Runtime(-1)),
                (Constant(minimum), Constant(-1)),
                (Constant(minimum), Runtime(-1)),
                // a known non-zero, non -1 divisor needs no guard.
                (Runtime(minimum), Constant(7)),
                (Runtime(-7), Runtime(2)),
                (Runtime(-1), Runtime(-1)),
            ] {
                cases.push((kind, width, lhs, rhs));
            }
        }
    }
    for (kind, width, lhs, rhs) in cases {
        let leaf = division_leaf(kind, width, lhs, rhs);
        verified(&leaf);
        let module = NativeModule::from_json(&serde_json::to_vec(&leaf["module"]).unwrap())
            .unwrap_or_else(|error| panic!("{}", error.message));
        let arguments = [lhs.value(), rhs.value()];
        let expected = evaluate(
            &module,
            "native_add",
            &arguments.map(|value| BigUint::from(value as u64)),
        );
        let native = prepare(&leaf.to_string())
            .unwrap_or_else(|error| panic!("{kind} i{width} {lhs:?} {rhs:?}: {error:#}"))
            .execute(&arguments);
        let case = format!("{kind} i{width} {lhs:?} {rhs:?}");
        match expected {
            Ok(Some(bits)) => {
                let value =
                    argument(&native.unwrap_or_else(|error| panic!("{case}: {error:#}"))).unwrap();
                assert_eq!(BigUint::from(value as u64), bits, "{case}");
            }
            Ok(None) => panic!("{case}: no result"),
            Err(error) => {
                assert!(
                    error.message.contains("by zero trapped"),
                    "{case}: {}",
                    error.message
                );
                assert_eq!(
                    rhs.value() & if width == 1 { 1 } else { -1 },
                    0,
                    "{case} trapped"
                );
                let failure = format!("{:#}", native.expect_err(&case));
                assert!(failure.contains("failed"), "{case}: {failure}");
            }
        }
    }
    // the documented answers, independent of either implementation.
    let at = |kind, width, lhs, rhs| {
        argument(
            &prepare(&division_leaf(kind, width, lhs, rhs).to_string())
                .unwrap()
                .execute(&[lhs.value(), rhs.value()])
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(at("s_div", 1, Runtime(-1), Runtime(-1)), -1);
    assert_eq!(at("s_rem", 1, Runtime(-1), Runtime(-1)), 0);
    assert_eq!(at("s_div", 64, Runtime(i64::MIN), Runtime(-1)), i64::MIN);
    assert_eq!(at("s_rem", 64, Runtime(i64::MIN), Constant(-1)), 0);
}
