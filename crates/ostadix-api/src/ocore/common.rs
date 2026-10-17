#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    X86_64UnknownNone,
    Aarch64UnknownNone,
    Riscv64UnknownNone,
}

impl Target {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "x86_64-unknown-none" | "x86_64-unknown-none-elf" => Some(Target::X86_64UnknownNone),
            "aarch64-unknown-none" | "aarch64-unknown-none-elf" => Some(Target::Aarch64UnknownNone),
            "riscv64-unknown-none" | "riscv64-unknown-none-elf" | "riscv64gc-unknown-none-elf" => {
                Some(Target::Riscv64UnknownNone)
            }
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Target::X86_64UnknownNone => "x86_64-unknown-none",
            Target::Aarch64UnknownNone => "aarch64-unknown-none",
            Target::Riscv64UnknownNone => "riscv64-unknown-none",
        }
    }

    pub fn triple(self) -> &'static str {
        match self {
            Target::X86_64UnknownNone => "x86_64-unknown-none-elf",
            Target::Aarch64UnknownNone => "aarch64-unknown-none-elf",
            Target::Riscv64UnknownNone => "riscv64-unknown-none-elf",
        }
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
