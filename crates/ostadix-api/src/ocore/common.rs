// The compiler, artifact driver and generated runtime share this declaration.
// Catalog membership describes implemented target dispatch, not runtime health,
// complete language support, or executable semantic qualification.
macro_rules! define_targets {
    ($($variant:ident {
        id: $id:literal,
        architecture: $architecture:literal,
        name: $name:literal,
        triple: $triple:literal,
        aliases: [$($alias:literal),* $(,)?]
    }),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Target { $($variant),+ }

        impl Target {
            /// Every canonical target, derived together with the enum variants.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub fn parse(value: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|target| target.aliases().contains(&value))
            }

            /// Architecture names are accepted only by callers that request
            /// this interface; Target::parse keeps its existing CLI aliases.
            pub fn from_architecture(value: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|target| target.architecture() == value)
            }

            pub const fn id(self) -> &'static str {
                match self { $(Self::$variant => $id),+ }
            }

            pub const fn architecture(self) -> &'static str {
                match self { $(Self::$variant => $architecture),+ }
            }

            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            pub const fn triple(self) -> &'static str {
                match self { $(Self::$variant => $triple),+ }
            }

            pub const fn aliases(self) -> &'static [&'static str] {
                match self { $(Self::$variant => &[$name, $triple, $($alias),*]),+ }
            }
        }
    };
}

define_targets! {
    X86_64UnknownNone {
        id: "x86_64",
        architecture: "x86_64",
        name: "x86_64-unknown-none",
        triple: "x86_64-unknown-none-elf",
        aliases: []
    },
    Aarch64UnknownNone {
        id: "aarch64",
        architecture: "aarch64",
        name: "aarch64-unknown-none",
        triple: "aarch64-unknown-none-elf",
        aliases: []
    },
    Riscv64UnknownNone {
        id: "rv64gc",
        architecture: "riscv64",
        name: "riscv64-unknown-none",
        triple: "riscv64-unknown-none-elf",
        aliases: ["riscv64gc-unknown-none-elf"]
    }
}

/// Byte range and source location attached to syntax and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl Span {
    pub fn join(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            line: self.line,
            column: self.column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub file: String,
    pub span: Span,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.file, self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for Diagnostic {}

#[cfg(test)]
mod target_catalog_tests {
    use super::Target;
    use std::collections::BTreeSet;

    #[test]
    fn canonical_target_registry_is_complete_unique_and_round_trips() {
        assert!(!Target::ALL.is_empty());
        let mut ids = BTreeSet::new();
        let mut architectures = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        for &target in Target::ALL {
            assert!(ids.insert(target.id()));
            assert!(architectures.insert(target.architecture()));
            assert_eq!(
                Target::from_architecture(target.architecture()),
                Some(target)
            );
            assert!(target.aliases().contains(&target.name()));
            assert!(target.aliases().contains(&target.triple()));
            for &alias in target.aliases() {
                assert!(aliases.insert(alias), "duplicate target alias {alias}");
                assert_eq!(Target::parse(alias), Some(target));
            }
            assert_eq!(Target::parse(target.architecture()), None);
        }
        assert_eq!(Target::parse("not-a-canonical-target"), None);
        assert_eq!(
            Target::from_architecture("not-a-canonical-architecture"),
            None
        );
    }
}
