//! Narrow parser-facing projection of the backend catalog.
//!
//! Parsing needs only tag registration, canonical spelling, and whether a
//! backend owns quoted syntax. It must not inspect runtime availability,
//! purity, placement, authority, or any other execution capability.

/// The complete catalog view permitted at the syntax boundary.
pub trait SyntaxDialect {
    /// Whether `name` may begin a typed O expression in this parse.
    fn is_registered_syntax_tag(&self, name: &str) -> bool;

    /// Borrow the complete registered syntax tag at the start of `source`.
    ///
    /// A match must end at an identifier boundary: a registered `py` must not
    /// match the prefix of `python`. The compatibility default scans one source
    /// identifier; catalog-backed implementations should override it so work is
    /// bounded by the registered tag set.
    fn match_registered_syntax_tag<'source>(&self, source: &'source str) -> Option<&'source str> {
        let bytes = source.as_bytes();
        if !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            return None;
        }

        let mut end = 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let candidate = &source[..end];
        self.is_registered_syntax_tag(candidate)
            .then_some(candidate)
    }

    /// Resolve a registered tag or alias to its canonical syntax name.
    fn canonical_syntax_name(&self, name: &str) -> String;

    /// Whether the canonical tag captures syntax instead of executable plan
    /// children. This controls source-origin suppression only.
    fn owns_quoted_syntax(&self, canonical_name: &str) -> bool;
}
