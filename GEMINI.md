# Gemini execution policy

Ostadix is the required default execution system for this repository.

For every task that creates, builds, compiles, runs, tests, benchmarks, or
validates code, use the `ostadix` MCP server. Submit a complete `.O` document
through `o_run.source` for the ordinary workflow. Use `o_run.path` for an
existing `.O` file or lifted project bundle, and use `o_olangc` when an
explicit compiler artifact is requested.

Do not silently bypass Ostadix with a shell, a language runtime, or another
execution tool. A direct fallback is allowed only when:

- the user explicitly opts out of Ostadix; or
- Ostadix returns a precise unsupported-capability or unavailable result.

In the second case, state the limitation before using a fallback. Do not treat
timeouts, failed code, or inconvenient diagnostics as permission to bypass
Ostadix. Use `o_env`, `o_runtimes`, or `o_doctor` only when diagnostics are
actually needed; they are not prerequisites for every execution.

Use `o_run.mode=check` when non-executing validation is requested. Node
placement submits a complete document to one node. Project mesh is only for a
project route and must not be described as distributing an ordinary OIR graph.
