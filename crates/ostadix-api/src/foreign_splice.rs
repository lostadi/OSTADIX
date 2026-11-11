//! Bounded lexical checks for value holes in declared guest literal profiles.
//!
//! This is not a guest parser or an effect sandbox. Guest source remains code.
//! Unsupported lexical forms fail closed around ordinary holes; explicit code
//! splices deliberately opt into reinterpretation under the existing authority.

pub(crate) const CODE_SPLICE_BUILTIN: &str = "code";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Python,
    Sql,
    Shell,
    JavaScript,
    Nix,
    Presentation,
    Unsupported,
}

fn profile(lang: &str) -> Profile {
    match lang {
        "python" | "py" => Profile::Python,
        "sql" => Profile::Sql,
        "bash" | "shell" => Profile::Shell,
        "javascript" => Profile::JavaScript,
        "nix" | "nix_expr" | "nix_store" | "nixos_test" => Profile::Nix,
        "text" | "plain" | "html" | "latex" | "tex" | "markdown" | "md" | "O" | "o" | "quote" => {
            Profile::Presentation
        }
        _ => Profile::Unsupported,
    }
}

pub(crate) enum Segment<'a> {
    Text(&'a str),
    Value,
    Code,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Code,
    LineComment,
    BlockComment,
    Quote {
        end: char,
        triple: bool,
        escape: bool,
        doubled: bool,
    },
    Unsupported,
}

fn identifier(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '_' | '$') || !ch.is_ascii() && !ch.is_whitespace()
}

pub(crate) fn validate_body<'a>(
    lang: &str,
    segments: impl Iterator<Item = Segment<'a>>,
) -> Result<(), String> {
    let profile = profile(lang);
    if profile == Profile::Presentation {
        return Ok(());
    }
    let mut source = Vec::new();
    let mut holes = Vec::new();
    for segment in segments {
        match segment {
            Segment::Text(text) => source.extend(text.chars()),
            Segment::Value => {
                holes.push((source.len(), false));
                source.push(' ');
            }
            Segment::Code => {
                holes.push((source.len(), true));
                source.push(' ');
            }
        }
    }
    if holes.is_empty() {
        return Ok(());
    }
    let mut state = State::Code;
    let mut cursor = 0;
    let mut hole = 0;
    let mut dynamic_code_seen = false;
    while cursor < source.len() {
        if hole < holes.len() && holes[hole].0 == cursor {
            let explicit_code = holes[hole].1;
            if explicit_code {
                // Code may change the lexical context of following text. It
                // never makes a later ordinary value hole implicitly raw.
                dynamic_code_seen = true;
            } else {
                let reason = if profile == Profile::Unsupported {
                    Some("backend has no declared literal/lexical value-hole profile")
                } else if dynamic_code_seen {
                    Some("a preceding dynamic code splice makes the lexical context unknown")
                } else if state != State::Code {
                    Some("value hole is inside a guest string/comment or unsupported lexical form")
                } else if cursor.checked_sub(1).is_some_and(|p| identifier(source[p]))
                    || source.get(cursor + 1).copied().is_some_and(identifier)
                {
                    Some("value hole is adjacent to a guest identifier token")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    return Err(format!(
                        "foreign value splice in `{lang}` rejected: {reason}; use an unquoted standalone value hole, guest-native bindings (Bash ${{name}}), or deliberate `$!name` code syntax"
                    ));
                }
            }
            hole += 1;
            cursor += 1;
            continue;
        }
        let ch = source[cursor];
        let next = source.get(cursor + 1).copied();
        match state {
            State::LineComment => {
                if ch == '\n' {
                    state = State::Code;
                }
            }
            State::BlockComment => {
                if ch == '*' && next == Some('/') {
                    state = State::Code;
                    cursor += 1;
                }
            }
            State::Quote {
                end,
                triple,
                escape,
                doubled,
            } => {
                if matches!(profile, Profile::Nix | Profile::JavaScript)
                    && ch == '$'
                    && next == Some('{')
                    || profile == Profile::Shell && (ch == '`' || ch == '$' && next == Some('('))
                {
                    // Nested expression grammars can contain their own
                    // strings. A flat quote tracker must never guess that
                    // their quotes close the outer guest string.
                    state = State::Unsupported;
                } else if profile == Profile::Shell && ch == '$' && next == Some('{') {
                    if let Some(end) = simple_shell_parameter_end(&source, cursor) {
                        cursor = end;
                    } else {
                        state = State::Unsupported;
                    }
                } else if escape && ch == '\\' {
                    // Never skip an O hole: a backslash before it is not a
                    // context escape and cannot suppress its validation.
                    if !holes.get(hole).is_some_and(|(p, _)| *p == cursor + 1) {
                        cursor += usize::from(next.is_some());
                    }
                } else if ch == end {
                    if triple {
                        if next == Some(end) && source.get(cursor + 2) == Some(&end) {
                            state = State::Code;
                            cursor += 2;
                        }
                    } else if doubled && next == Some(end) {
                        cursor += 1;
                    } else {
                        state = State::Code;
                    }
                }
            }
            State::Unsupported => {}
            State::Code => {
                if profile == Profile::JavaScript
                    && (source[cursor..].starts_with(&['<', '!', '-', '-'])
                        || source[cursor..].starts_with(&['-', '-', '>'])
                        || ch == '#' && next == Some('!'))
                {
                    state = State::LineComment;
                } else if matches!(profile, Profile::Python | Profile::JavaScript) && ch == '\\' {
                    // Escaped identifiers and explicit line joining change
                    // token boundaries without visible adjacent characters.
                    state = State::Unsupported;
                } else if profile == Profile::Nix && (ch == '/' && next != Some('*') || ch == '<') {
                    // Unquoted path/search-path lexemes are not standalone
                    // expression holes. Their interpolation grammar is not
                    // part of this bounded literal profile.
                    state = State::Unsupported;
                } else if profile == Profile::Shell && ch == '$' && next == Some('{') {
                    if let Some(end) = simple_shell_parameter_end(&source, cursor) {
                        cursor = end;
                    } else {
                        state = State::Unsupported;
                    }
                } else if profile == Profile::Shell
                    && (ch == '$' && next == Some('(')
                        || ch == '(' && next == Some('(')
                        || ch == '[' && next == Some('[')
                        || ch == '[' && cursor > 0 && identifier(source[cursor - 1]))
                {
                    // Bash numeric [[ tests recursively interpret operand
                    // strings as arithmetic, even when shell-word quoted.
                    state = State::Unsupported;
                } else if matches!(profile, Profile::Python | Profile::Shell | Profile::Nix)
                    && ch == '#'
                {
                    state = State::LineComment;
                } else if profile == Profile::Sql && ch == '-' && next == Some('-')
                    || profile == Profile::JavaScript && ch == '/' && next == Some('/')
                {
                    state = State::LineComment;
                    cursor += 1;
                } else if matches!(profile, Profile::Sql | Profile::JavaScript | Profile::Nix)
                    && ch == '/'
                    && next == Some('*')
                {
                    state = State::BlockComment;
                    cursor += 1;
                } else if profile == Profile::JavaScript && ch == '/'
                    || profile == Profile::Shell && ch == '<' && next == Some('<')
                    || profile == Profile::Nix && ch == '\'' && next == Some('\'')
                {
                    // Regex/division ambiguity, shell here-documents and Nix
                    // indented strings need a fuller guest parser. Reject
                    // following value holes rather than guess their context.
                    state = State::Unsupported;
                } else if matches!(ch, '\'' | '"')
                    || profile == Profile::JavaScript && ch == '`'
                    || profile == Profile::Shell && ch == '`'
                    || profile == Profile::Sql && matches!(ch, '`' | '[')
                {
                    if profile == Profile::Python
                        && cursor > 0
                        && matches!(source[cursor - 1], 'f' | 'F' | 't' | 'T')
                        || profile == Profile::Python
                            && cursor > 1
                            && matches!(source[cursor - 1], 'r' | 'R')
                            && matches!(source[cursor - 2], 'f' | 'F' | 't' | 'T')
                    {
                        state = State::Unsupported;
                        cursor += 1;
                        continue;
                    }
                    let triple = profile == Profile::Python
                        && next == Some(ch)
                        && source.get(cursor + 2) == Some(&ch);
                    let escape = match profile {
                        Profile::Sql => false,
                        Profile::Shell if ch == '\'' => cursor > 0 && source[cursor - 1] == '$',
                        _ => true,
                    };
                    state = State::Quote {
                        end: if ch == '[' { ']' } else { ch },
                        triple,
                        escape,
                        doubled: profile == Profile::Sql && ch != '[',
                    };
                    if triple {
                        cursor += 2;
                    }
                } else if profile == Profile::Shell && ch == '\\' {
                    if holes.get(hole).is_some_and(|(p, _)| *p == cursor + 1) {
                        // Otherwise this backslash would escape the opening
                        // quote emitted by the value's shell-word renderer.
                        state = State::Unsupported;
                    } else {
                        cursor += usize::from(next.is_some());
                    }
                }
            }
        }
        cursor += 1;
    }
    Ok(())
}

/// Only the simple `${name}` binding form is understood here. Shell default
/// expressions, substitutions and array subscripts have nested grammars.
fn simple_shell_parameter_end(source: &[char], start: usize) -> Option<usize> {
    let mut cursor = start + 2;
    let first = *source.get(cursor)?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    cursor += 1;
    while source
        .get(cursor)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        cursor += 1;
    }
    (source.get(cursor) == Some(&'}')).then_some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_profiles_reject_strings_comments_and_identifier_adjacency() {
        for (lang, before, after) in [
            ("python", "\"", "\""),
            ("python", "'''", "'''"),
            ("python", "# ", "\n"),
            ("sql", "'", "'"),
            ("sql", "-- ", "\n"),
            ("sql", "/* ", " */"),
            ("bash", "\"", "\""),
            ("bash", "'", "'"),
            ("bash", "# ", "\n"),
            ("javascript", "`", "`"),
            ("javascript", "// ", "\n"),
            ("nix", "\"", "\""),
            ("nix", "/* ", " */"),
            ("python", "prefix", ""),
            ("sql", "", "suffix"),
        ] {
            assert!(
                validate_body(
                    lang,
                    [Segment::Text(before), Segment::Value, Segment::Text(after)].into_iter()
                )
                .is_err(),
                "{lang}: {before}..{after}"
            );
        }
        for lang in [
            "python",
            "sql",
            "bash",
            "shell",
            "javascript",
            "nix",
            "nix_expr",
        ] {
            assert!(
                validate_body(
                    lang,
                    [Segment::Text("( "), Segment::Value, Segment::Text(" )")].into_iter()
                )
                .is_ok(),
                "{lang}"
            );
        }
    }

    #[test]
    fn unsupported_profiles_fail_closed_but_code_is_explicit_and_not_sticky() {
        assert!(validate_body("c", [Segment::Value].into_iter()).is_err());
        assert!(validate_body("c", [Segment::Code].into_iter()).is_ok());
        assert!(validate_body(
            "python",
            [Segment::Code, Segment::Text(" + "), Segment::Value].into_iter()
        )
        .is_err());
        assert!(validate_body(
            "markdown",
            [Segment::Text("\""), Segment::Value].into_iter()
        )
        .is_ok());
    }

    #[test]
    fn nested_guest_grammars_fail_closed_instead_of_toggling_outer_quotes() {
        for (lang, before, after) in [
            ("python", "f\"{ \"prefix ", " suffix\" }\""),
            ("nix", "\"${ \"prefix ", " suffix\" }\""),
            ("javascript", "`outer${`inner ", " suffix`}`"),
            ("bash", "\"$(printf \"", "\")\""),
            ("bash", "$(( ", " ))"),
            ("bash", "[[ ", " -gt 0 ]]"),
            ("bash", "array[", "]"),
            ("bash", "\"${array[", "]}\""),
            ("javascript", "<!-- ", "\n"),
            ("javascript", "--> ", "\n"),
            ("javascript", "#! interpreter ", "\n"),
            ("javascript", "\\u{61}", ""),
            ("python", "prefix\\\n", ""),
            ("nix", "/tmp/", ""),
            ("nix", "<", ">"),
        ] {
            assert!(
                validate_body(
                    lang,
                    [Segment::Text(before), Segment::Value, Segment::Text(after)].into_iter()
                )
                .is_err(),
                "{lang}: {before}..{after}"
            );
        }
        assert!(validate_body(
            "bash",
            [Segment::Text("\"${native}\" "), Segment::Value].into_iter()
        )
        .is_ok());
        assert!(
            validate_body("bash", [Segment::Text("[[ ${native} -gt 0 ]]")].into_iter()).is_ok(),
            "guest-native code without O holes retains its existing path"
        );
    }

    #[test]
    fn python_templates_and_shell_escaped_holes_fail_closed() {
        for prefix in ["t", "T", "tr", "tR", "Tr", "TR", "rt", "rT", "Rt", "RT"] {
            let before = format!("{prefix}\"{{ \"prefix ");
            assert!(
                validate_body(
                    "python",
                    [
                        Segment::Text(&before),
                        Segment::Value,
                        Segment::Text(" suffix\" }\"")
                    ]
                    .into_iter()
                )
                .is_err(),
                "{prefix}"
            );
        }
        assert!(validate_body(
            "bash",
            [
                Segment::Text("printf '%s' \\"),
                Segment::Value,
                Segment::Text("\n")
            ]
            .into_iter()
        )
        .is_err());
        assert!(
            validate_body(
                "shell",
                [
                    Segment::Text("printf '%s' \\\\"),
                    Segment::Value,
                    Segment::Text("\n")
                ]
                .into_iter()
            )
            .is_ok(),
            "a complete escaped backslash must preserve the next literal quote"
        );
    }
}
