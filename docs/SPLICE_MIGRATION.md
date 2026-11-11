# Migrating source splices

An ordinary O hole supplies data to a declared receiving renderer. Keep it
outside the guest language's strings and comments:

```O
let name = python^("O'Brien")_python
sql^(SELECT $name AS who;)_sql
python^([len($name), $name])_python
javascript^(console.log($name))_javascript
```

The receiver adds its own literal spelling. Adding SQL or Python quotes around
`$name` now fails at parse/check time. This is an intentional language change.
Existing no-hole guest programs continue to use their own language syntax.

Bash and shell already receive O let bindings through the variable injection
path. Use the shell's quoted parameter expansion for interpolation into a
string, or an unquoted O hole where a complete literal word belongs:

```O
let greeting = python^("world")_python
bash^(printf 'hello %s\n' "${greeting}")_bash
bash^(printf '%s\n' $greeting)_bash
```

The second form is rendered as one shell word. In the first form `${greeting}`
is native shell syntax; it is not an O source hole. Shell substitution inside
more complex quoted expressions, including `[[` conditions, remains outside
the bounded O-hole lexer. Authored `eval`, `let`, `declare -i` and existing
integer-variable attributes can reinterpret data during execution; quoting is
not a general effect-safety guarantee for such code-consuming operations.
See the [supported profiles and edition limits](CURRENT_CONTRACT.md).

Use `$!name` only for deliberate source generation. It inserts the supplied
text as code and retains the backend's existing authority. The Rust runtime
records reinterpretation in its preparation trace; Python and C17 do not
inherit that trace guarantee. It does not confer a grant, sanitize the code, or establish
syntactic confinement. Converting a value to code requires this visible intent
at its immediate insertion; storing `code($name)` does not make later ordinary
holes raw. Unsupported executable data profiles fail closed instead of
silently inserting raw text.

The greeting example now uses Python, Bash and JavaScript, all of which have
declared literal profiles. The complete former README remains in the
[preserved reference](REFERENCE.md); its Common Lisp greeting and older quoted
hole examples describe that historical source. This guide and the current
contract govern the revised language. The original Common Lisp adapter is
retained; a literal-confinement profile for it is not claimed here.

The SQLite adapter reads each request from its own file. Open quotes can no
longer consume the completion command. A malformed SQL request reports its
SQL error, and the persistent session can accept a later request. The Python
SQLite shim uses SQLite's complete-statement recognition, including trigger
bodies and quoted semicolons.

Rust backend steps have a 120-second default deadline. Set
`O_BACKEND_STEP_TIMEOUT_MS` to an integer from 1 through 604800000 milliseconds
for a different limit, or
the exact word `disabled` to opt into an unbounded step. Operation and
heartbeat deadlines are separate controls.

Alternate editions have separate execution limits. The Python reference uses
its in-process Python evaluator and stateless external shim adapters; C17
retains its own process protocol. The Rust admission and general step-deadline
guarantees do not automatically apply to those editions.

The [seven original witnesses](../tests/fixtures/foreign-splice-witnesses.json)
remain unchanged. The [reproduction runner](../scripts/reproduce_splice_contract.py)
tests both their revised outcomes and corrected data-splice forms. See the
[evidence guide](../evidence/public-contract-20261111/README.md) for commands
and the distinction between historical and fresh results.
