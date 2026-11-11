#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use proptest::prelude::*;
use tempfile::TempDir;

fn relative_path_strategy() -> impl Strategy<Value = String> {
    (
        prop::collection::vec("[a-z]{1,5}", 0..3),
        "[a-z]{1,7}",
        prop_oneof![
            Just(Some("py")),
            Just(Some("sh")),
            Just(Some("rs")),
            Just(Some("js")),
            Just(Some("rb")),
            Just(Some("java")),
            Just(Some("ml")),
            Just(Some("md")),
            Just(Some("txt")),
            Just(Some("c")),
            Just(Some("hs")),
            Just(Some("rkt")),
            Just(Some("sql")),
            Just(Some("ts")),
            Just(Some("svelte")),
            Just(Some("toml")),
            Just(None),
        ],
    )
        .prop_map(|(directories, name, extension)| {
            let mut path = directories.join("/");
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&name);
            if let Some(extension) = extension {
                path.push('.');
                path.push_str(extension);
            }
            path
        })
}

fn content_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            "[a-zA-Z0-9 _=+*/.,;:{}'\"-]{0,30}",
            Just("\n".to_string()),
            Just("\r\n".to_string()),
            Just("#".to_string()),
            Just("# ── embedded/file.O ──\n# o-link-section-bytes: 999\n".to_string()),
            Just("$HOME".to_string()),
            Just("$value".to_string()),
            Just("python^(".to_string()),
            Just(")_python".to_string()),
            Just(")_python[0]".to_string()),
            Just(")_python[*]{defer}".to_string()),
            Just(")_python_suffix".to_string()),
            Just("bash[3]^(".to_string()),
            Just(")_bash[3]".to_string()),
            Just("\\python^(".to_string()),
            Just("lambda λ and snowman ☃".to_string()),
        ],
        0..10,
    )
    .prop_map(|parts| parts.concat())
}

fn o_document_strategy() -> impl Strategy<Value = String> {
    (
        any::<bool>(),
        prop::collection::vec(
            prop_oneof![
                "[a-zA-Z0-9 _#=-]{0,30}",
                Just("lambda λ and snowman ☃".to_string()),
                Just("── embedded/file.O ──".to_string()),
                Just("o-link-section-bytes: 999".to_string()),
            ],
            0..6,
        ),
        prop_oneof![Just("\n"), Just("\r\n")],
        any::<bool>(),
    )
        .prop_map(|(inner_shebang, comments, newline, final_newline)| {
            // Generate valid .O documents: literal mode still parses the bundle.
            // Comment data includes marker-like text; the nested O stays intentional.
            let mut source = String::new();
            if inner_shebang {
                source.push_str("#!/usr/bin/env o");
                source.push_str(newline);
            }
            for comment in comments {
                source.push_str("# ");
                source.push_str(&comment);
                source.push_str(newline);
            }
            source.push_str("python[0]^(print('literal λ'))_python[0]");
            if final_newline {
                source.push_str(newline);
            }
            source
        })
}

fn write_tree(root: &Path, files: &BTreeMap<String, String>) {
    for (relative, content) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content.as_bytes()).unwrap();
    }
}

fn is_valid_file_tree(files: &BTreeMap<String, String>) -> bool {
    let file_paths = files.keys().map(PathBuf::from).collect::<BTreeSet<_>>();
    for relative in &file_paths {
        let mut current = relative.as_path();
        while let Some(parent) = current.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            if file_paths.contains(&parent.to_path_buf()) {
                return false;
            }
            current = parent;
        }
    }
    true
}

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn setup(files: &BTreeMap<String, String>, symlink_mode: u8) -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let expected = temp.path().join("expected");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&expected).unwrap();
    write_tree(&source, files);
    write_tree(&expected, files);
    if symlink_mode & 1 != 0 {
        std::os::unix::fs::symlink(&source, source.join("zz-loop")).unwrap();
    }
    if symlink_mode & 2 != 0 {
        let target = files.keys().next().unwrap();
        let alias = Path::new(target)
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("zzzzzzzzzzzz-alias.{extension}"))
            .unwrap_or_else(|| "zzzzzzzzzzzz-alias".to_string());
        std::os::unix::fs::symlink(source.join(target), source.join(alias)).unwrap();
    }
    (temp, source, expected)
}

fn assert_exact_literal_round_trip(
    files: &BTreeMap<String, String>,
    symlink_mode: u8,
    outer_shebang: bool,
) {
    let (temp, source, expected) = setup(files, symlink_mode);
    let combined = temp.path().join("combined.O");
    let restored = temp.path().join("restored");
    let mut command = Command::new(env!("CARGO_BIN_EXE_o-link"));
    command
        .arg("--literal")
        .arg(&source)
        .arg("-o")
        .arg(&combined);
    if outer_shebang {
        command.arg("--shebang");
    }
    run(&mut command);
    let linked = fs::read(&combined).unwrap();
    assert_eq!(linked.starts_with(b"#!/usr/bin/env o\n"), outer_shebang);

    run(Command::new(env!("CARGO_BIN_EXE_o-unlink"))
        .arg(&combined)
        .arg("-o")
        .arg(&restored));
    for (relative, original) in files {
        assert_eq!(
            fs::read(restored.join(relative)).unwrap(),
            original.as_bytes(),
            "literal bytes changed for {relative}, outer shebang={outer_shebang}"
        );
    }
    let diff = Command::new("diff")
        .arg("-r")
        .arg(&expected)
        .arg(&restored)
        .output()
        .unwrap();
    assert!(
        diff.status.success(),
        "round-trip file inventory or bytes changed:\n{}",
        String::from_utf8_lossy(&diff.stdout)
    );
}

#[test]
fn literal_o_shebang_only_round_trips_without_final_newline() {
    let files = BTreeMap::from([("only.O".to_string(), "#!/usr/bin/env o".to_string())]);
    for outer_shebang in [false, true] {
        assert_exact_literal_round_trip(&files, 0, outer_shebang);
    }
}

#[test]
fn literal_o_inner_shebang_round_trips_with_and_without_outer_shebang() {
    let files = BTreeMap::from([(
        "inner.O".to_string(),
        "#!/usr/bin/env o\npython[0]^(print('nested O'))_python[0]".to_string(),
    )]);
    for outer_shebang in [false, true] {
        assert_exact_literal_round_trip(&files, 0, outer_shebang);
    }
}

#[test]
fn literal_o_crlf_unicode_and_embedded_markers_round_trip_exactly() {
    let files = BTreeMap::from([(
        "nested/λ_program.O".to_string(),
        concat!(
            "#!/usr/bin/env o\r\n",
            "# λ and snowman ☃\r\n",
            "# ── embedded/file.O ──\r\n",
            "# o-link-section-bytes: 999\r\n",
            "python[0]^(print('no final newline'))_python[0]"
        )
        .to_string(),
    )]);
    for outer_shebang in [false, true] {
        assert_exact_literal_round_trip(&files, 0, outer_shebang);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn generated_o_documents_round_trip_with_optional_outer_shebang(
        relative in relative_path_strategy(),
        source in o_document_strategy(),
        outer_shebang in any::<bool>(),
        symlink_mode in 0u8..4,
    ) {
        let relative = PathBuf::from(relative).with_extension("O");
        let files = BTreeMap::from([(relative.to_str().unwrap().to_string(), source)]);
        assert_exact_literal_round_trip(&files, symlink_mode, outer_shebang);
    }

    #[test]
    fn generated_file_trees_round_trip_with_empty_recursive_diff(
        files in prop::collection::btree_map(relative_path_strategy(), content_strategy(), 1..9),
        symlink_mode in 0u8..4,
    ) {
        prop_assume!(is_valid_file_tree(&files));
        let (temp, source, expected) = setup(&files, symlink_mode);
        let combined = temp.path().join("combined.O");
        let restored = temp.path().join("restored");

        let link = run(
            Command::new(env!("CARGO_BIN_EXE_o-link"))
                .arg("--literal")
                .arg(&source)
                .arg("-o")
                .arg(&combined),
        );
        let link_stderr = String::from_utf8_lossy(&link.stderr);
        prop_assert!(link_stderr.contains("o-link scan:"));

        let combined_source = fs::read_to_string(&combined).unwrap();
        prop_assert!(!combined_source.contains(&source.display().to_string()));

        run(
            Command::new(env!("CARGO_BIN_EXE_o-unlink"))
                .arg(&combined)
                .arg("-o")
                .arg(&restored),
        );

        let diff = Command::new("diff")
            .arg("-r")
            .arg(&expected)
            .arg(&restored)
            .output()
            .unwrap();
        prop_assert!(
            diff.status.success(),
            "round-trip diff was not empty:\n{}",
            String::from_utf8_lossy(&diff.stdout)
        );
    }
}
