"""
Evaluator: walks the AST produced by parser.py and evaluates each
ExpressionNode via its language backend, threading a registry of persistent
per-(language, env_id) environments.

Evaluation order: LEAVES UP (applicative order, like standard Lisp).
A node's children are evaluated first; their OValues are then rendered
into the parent's language via the parent backend's render_child(); the
parent backend then runs its evaluate() on the fully-spliced body string.

Persistent environments: every numeric (canonical_language, env_id) pair gets
its own env object created exactly once. Bare and [*] blocks bypass that map
and receive a fresh backend environment on every evaluation attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union

from .backends import default_registry
from .backends.base import Backend
from .ovalue import OStr, OValue
from .parser import (
    EPHEMERAL_ENV_ID,
    LINKER_ISOLATED_ENV_ID,
    Document,
    ExpressionNode,
    LetBinding,
    TextPart,
    VarRef,
    validate_tree,
)


# (canonical_language, env_id) -> persistent env object
EnvRegistry = Dict[Tuple[str, int], object]


@dataclass
class EvalContext:
    backends: Dict[str, Backend] = field(default_factory=default_registry)
    envs: EnvRegistry = field(default_factory=dict)
    _scope: Dict[str, OValue] = field(default_factory=dict, init=False, repr=False)

    def backend_for(self, canonical_language: str) -> Backend:
        if canonical_language not in self.backends:
            raise KeyError(
                f"No backend registered for language {canonical_language!r}. "
                f"Known: {sorted(self.backends)}"
            )
        return self.backends[canonical_language]

    def env_for(self, canonical_language: str, env_id: int) -> object:
        if env_id in (EPHEMERAL_ENV_ID, LINKER_ISOLATED_ENV_ID):
            return self.backend_for(canonical_language).make_env()
        key = (canonical_language, env_id)
        if key not in self.envs:
            self.envs[key] = self.backend_for(canonical_language).make_env()
        return self.envs[key]


def evaluate_document(doc: Document, ctx: EvalContext = None) -> OValue:
    """Evaluate a parsed .O document and return the root OValue.

    If the document contains a single top-level expression, its OValue is
    the result. If it contains multiple top-level expressions (or mixed
    text/expressions), they are concatenated as a Text root -- we synthesize
    an implicit text[0] wrapper so that every document has a single root.
    """
    ctx = ctx or EvalContext()
    validate_tree(doc)
    scope: Dict[str, OValue] = {}

    top_body = doc.body

    # Evaluate let bindings first (they may appear before the main expr).
    # Collect non-let nodes for the synthesized root.
    non_let = []
    for node in top_body:
        if isinstance(node, LetBinding):
            val = _eval_expression(node.expr, ctx, scope)
            scope[node.name] = val
        else:
            non_let.append(node)

    # Ignore formatting whitespace when selecting a single expression root.
    meaningful_non_let = [
        c for c in non_let
        if not (isinstance(c, TextPart) and not c.text.strip())
    ]

    # If the document is exactly one ExpressionNode (ignoring stray
    # whitespace and let bindings), that expression IS the root.
    if len(meaningful_non_let) == 1 and isinstance(meaningful_non_let[0], ExpressionNode):
        return _eval_expression(meaningful_non_let[0], ctx, scope)

    # Otherwise synthesize an implicit text root so we always return a single
    # OValue. The text backend renders children using render_plain.
    synthetic_root = ExpressionNode(
        language="text",
        env_id=EPHEMERAL_ENV_ID,
        env_explicit=False,
        body=non_let,
    )
    return _eval_expression(synthetic_root, ctx, scope)


def _eval_expression(
    node: ExpressionNode,
    ctx: EvalContext,
    scope: Dict[str, OValue] = None,
) -> OValue:
    """Evaluate one ExpressionNode.

    If the backend implements `eval_ast(node, ctx)`, the backend takes
    full control of child evaluation (used by O^, which sequences
    children, and quote^, which captures the AST without evaluating).

    Otherwise we use the default flow:
      1. Evaluate every child ExpressionNode recursively.
      2. Build the final body string by concatenating TextParts verbatim
         with child render_child() results.
      3. Call the backend's evaluate() with the spliced body.
    """
    if scope is None:
        scope = ctx._scope

    # Structural backends and O.eval access the active lexical scope through
    # ctx. Every recursive evaluation restores its caller, including failures.
    previous_scope = ctx._scope
    ctx._scope = scope
    try:
        return _eval_expression_scoped(node, ctx, scope)
    finally:
        ctx._scope = previous_scope


def _eval_expression_scoped(
    node: ExpressionNode,
    ctx: EvalContext,
    scope: Dict[str, OValue],
) -> OValue:
    validate_tree(node)
    backend = ctx.backend_for(node.canonical_language)
    from .foreign_splice import PRESENTATION, render_literal, render_explicit_code

    eval_ast = getattr(backend, "eval_ast", None)
    if callable(eval_ast):
        return eval_ast(node, ctx)

    env = ctx.env_for(node.canonical_language, node.env_id)

    buf: List[str] = []
    for child in node.body:
        if isinstance(child, TextPart):
            buf.append(child.text)
        elif isinstance(child, VarRef):
            # Substitute variable reference from scope.
            val = scope.get(child.name)
            if val is None:
                if node.canonical_language in PRESENTATION and not child.explicit_code:
                    buf.append(f"${child.name}")
                    continue
                raise ValueError(f"undefined O variable ${child.name}; guest-native bindings use ${{name}}")
            else:
                buf.append(render_explicit_code(val) if child.explicit_code else render_literal(node.canonical_language, val, backend.render_child))
        elif isinstance(child, ExpressionNode):
            child_value = _eval_expression(child, ctx, scope)
            buf.append(render_literal(node.canonical_language, child_value, backend.render_child))
        else:
            raise TypeError(f"Unknown AST child node: {child!r}")

    body_str = "".join(buf)
    # Pass ctx to evaluate when the backend accepts it (Python uses this
    # for O.eval; others don't care).
    try:
        return backend.evaluate(body_str, env, ctx)
    except TypeError:
        # Backward compat with backends that still have 2-arg evaluate.
        return backend.evaluate(body_str, env)


# ---------------------------------------------------------------------------
# Convenience top-level driver
# ---------------------------------------------------------------------------

def run(src: str, ctx: EvalContext = None) -> OValue:
    """Parse + evaluate a .O source string. Returns the root OValue."""
    from .parser import parse
    return evaluate_document(parse(src), ctx)
