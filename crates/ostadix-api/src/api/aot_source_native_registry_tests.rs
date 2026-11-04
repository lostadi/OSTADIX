#[cfg(test)]
mod native_root_registry_tests {
    use super::RUNTIME_OCORE_NATIVE_SOURCES;
    use std::collections::{BTreeMap, BTreeSet};

    const ROOT: &str = include_str!("../ocore/native_core.rs");

    #[derive(Debug, PartialEq, Eq)]
    enum GuardError {
        DuplicateTuple(String),
        MissingRoot,
        RootBytesDiffer,
        EmptyRoot,
        UnsupportedRootDeclaration(usize),
        DuplicateRootModule(String),
        DuplicateRootPath(String),
        MissingModule { path: String, module: String },
    }

    fn identifier(s: &str) -> bool {
        let mut bytes = s.bytes();
        matches!(bytes.next(), Some(b'_') | Some(b'a'..=b'z') | Some(b'A'..=b'Z'))
            && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
    }

    fn module_line(line: &str) -> Option<&str> {
        let rest = line.strip_prefix("pub mod ").or_else(|| line.strip_prefix("mod "))?;
        let name = rest.strip_suffix(';')?;
        identifier(name).then_some(name)
    }

    // This guard covers this selected unconditional root layout, not arbitrary
    // Rust dependencies, cfg evaluation, descendant modules or asset closure.
    fn root_modules(root: &str) -> Result<BTreeMap<String, String>, GuardError> {
        let mut paths = BTreeMap::new();
        let mut names = BTreeSet::new();
        let mut pending: Option<(String, usize)> = None;
        for (index, raw) in root.lines().enumerate() {
            let line_number = index + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with("//") { continue; }
            if line.starts_with("#[path") {
                if pending.is_some() { return Err(GuardError::UnsupportedRootDeclaration(line_number)); }
                let path = line.strip_prefix("#[path = \"")
                    .and_then(|s| s.strip_suffix("\"]"))
                    .filter(|s| s.strip_suffix(".rs").is_some_and(identifier))
                    .ok_or(GuardError::UnsupportedRootDeclaration(line_number))?;
                pending = Some((path.to_owned(), line_number));
                continue;
            }
            if line.starts_with("#[") || line.starts_with("#!")
                || line.starts_with("/*") || line.starts_with('*')
            {
                return Err(GuardError::UnsupportedRootDeclaration(line_number));
            }
            let declaration = module_line(line);
            if let Some((path, _)) = pending.take() {
                let name = declaration.ok_or(GuardError::UnsupportedRootDeclaration(line_number))?;
                if !names.insert(name.to_owned()) {
                    return Err(GuardError::DuplicateRootModule(name.to_owned()));
                }
                if paths.insert(path.clone(), name.to_owned()).is_some() {
                    return Err(GuardError::DuplicateRootPath(path));
                }
            } else if declaration.is_some() || line.split_whitespace().any(|word| word == "mod") {
                return Err(GuardError::UnsupportedRootDeclaration(line_number));
            }
        }
        if let Some((_, line)) = pending {
            return Err(GuardError::UnsupportedRootDeclaration(line));
        }
        if paths.is_empty() { return Err(GuardError::EmptyRoot); }
        Ok(paths)
    }

    fn check(root: &str, rows: &[(&str, &str)]) -> Result<BTreeMap<String, String>, GuardError> {
        let mut table = BTreeMap::new();
        for &(path, contents) in rows {
            if table.insert(path, contents).is_some() {
                return Err(GuardError::DuplicateTuple(path.to_owned()));
            }
        }
        match table.get("mod.rs") {
            None => return Err(GuardError::MissingRoot),
            Some(&actual) if actual != root => return Err(GuardError::RootBytesDiffer),
            Some(_) => {}
        }
        let required = root_modules(root)?;
        for (path, module) in &required {
            if !table.contains_key(path.as_str()) {
                return Err(GuardError::MissingModule { path: path.clone(), module: module.clone() });
            }
        }
        Ok(required)
    }

    fn rows_with_root(root: &str) -> Vec<(&str, &str)> {
        RUNTIME_OCORE_NATIVE_SOURCES.iter().map(|&(path, contents)| {
            (path, if path == "mod.rs" { root } else { contents })
        }).collect()
    }

    #[test]
    fn generated_native_root_registry_closes_actual_declared_modules() {
        let required = check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).expect("actual generated native root closure");
        assert!(!required.is_empty());
        assert_eq!(RUNTIME_OCORE_NATIVE_SOURCES.iter().filter(|row| row.0 == "mod.rs").count(), 1);
        assert_eq!(RUNTIME_OCORE_NATIVE_SOURCES.iter().find(|row| row.0 == "mod.rs").unwrap().1, ROOT);
        for path in required.keys() {
            assert_eq!(RUNTIME_OCORE_NATIVE_SOURCES.iter().filter(|row| row.0 == path.as_str()).count(), 1);
        }
    }

    #[test]
    fn removing_each_actual_root_module_reaches_its_missing_path() {
        let required = check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).unwrap();
        for (path, module) in required {
            let mut mutant = RUNTIME_OCORE_NATIVE_SOURCES.to_vec();
            assert_eq!(mutant.iter().filter(|row| row.0 == path.as_str()).count(), 1);
            let before = mutant.len();
            mutant.retain(|row| row.0 != path.as_str());
            assert_eq!(mutant.len() + 1, before);
            assert!(mutant.iter().all(|row| row.0 != path.as_str()));
            assert_eq!(check(ROOT, &mutant), Err(GuardError::MissingModule { path, module }));
        }
    }

    #[test]
    fn added_root_module_cannot_be_omitted_from_the_registry() {
        const PATH: &str = "native_source_registry_new_module_probe.rs";
        const NAME: &str = "native_source_registry_new_module_probe";
        let baseline = check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).unwrap();
        assert!(!baseline.contains_key(PATH));
        assert!(baseline.values().all(|name| name != NAME));
        assert!(RUNTIME_OCORE_NATIVE_SOURCES.iter().all(|row| row.0 != PATH));
        let mutant_root = format!("{ROOT}\n#[path = \"{PATH}\"]\npub mod {NAME};\n");
        let selected = root_modules(&mutant_root).unwrap();
        assert_eq!(selected.len(), baseline.len() + 1);
        assert_eq!(selected.get(PATH).map(String::as_str), Some(NAME));
        for (path, module) in &baseline { assert_eq!(selected.get(path), Some(module)); }
        let mutant_rows = rows_with_root(&mutant_root);
        assert_eq!(mutant_rows.iter().find(|row| row.0 == "mod.rs").unwrap().1, mutant_root.as_str());
        assert!(mutant_rows.iter().all(|row| row.0 != PATH));
        assert_eq!(check(&mutant_root, &mutant_rows), Err(GuardError::MissingModule {
            path: PATH.to_owned(), module: NAME.to_owned()
        }));
        assert_eq!(check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).unwrap(), baseline);
    }

    #[test]
    fn duplicate_root_and_registry_keys_are_rejected() {
        let baseline = check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).unwrap();
        let (path, name) = baseline.iter().next().unwrap();
        let original = *RUNTIME_OCORE_NATIVE_SOURCES.iter().find(|row| row.0 == path.as_str()).unwrap();
        let mut duplicate_rows = RUNTIME_OCORE_NATIVE_SOURCES.to_vec();
        duplicate_rows.push(original);
        assert_eq!(duplicate_rows.iter().filter(|row| row.0 == path.as_str()).count(), 2);
        assert_eq!(check(ROOT, &duplicate_rows), Err(GuardError::DuplicateTuple(path.clone())));

        const FRESH_NAME: &str = "native_source_registry_duplicate_path_probe";
        const FRESH_PATH: &str = "native_source_registry_duplicate_name_probe.rs";
        assert!(baseline.values().all(|value| value != FRESH_NAME));
        assert!(!baseline.contains_key(FRESH_PATH));
        let duplicate_path = format!("{ROOT}\n#[path = \"{path}\"]\npub mod {FRESH_NAME};\n");
        assert_eq!(check(&duplicate_path, &rows_with_root(&duplicate_path)),
            Err(GuardError::DuplicateRootPath(path.clone())));
        let duplicate_name = format!("{ROOT}\n#[path = \"{FRESH_PATH}\"]\npub mod {name};\n");
        assert_eq!(check(&duplicate_name, &rows_with_root(&duplicate_name)),
            Err(GuardError::DuplicateRootModule(name.clone())));
    }

    #[test]
    fn unsupported_root_module_layout_refuses_instead_of_disappearing() {
        check(ROOT, RUNTIME_OCORE_NATIVE_SOURCES).unwrap();
        let mut mutant_root = ROOT.to_owned();
        if !mutant_root.ends_with('\n') { mutant_root.push('\n'); }
        let line = mutant_root.lines().count() + 1;
        mutant_root.push_str("pub(crate) mod native_source_registry_unparsed_probe;\n");
        assert!(mutant_root.ends_with("pub(crate) mod native_source_registry_unparsed_probe;\n"));
        assert_eq!(check(&mutant_root, &rows_with_root(&mutant_root)),
            Err(GuardError::UnsupportedRootDeclaration(line)));
    }
}
