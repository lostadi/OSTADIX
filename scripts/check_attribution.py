#!/usr/bin/env python3
"""Require Lee-only commit authorship and reject additional attribution credit.

Tooling references are allowed. This guard is deliberately limited to fields
that Git, GitHub, Cargo, or CFF interpret as authorship or contribution credit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "scripts/check_attribution.py"
PROJECT_AUTHOR = "Lee Daghlar Ostadi"
PROJECT_ORCID = "0009-0001-6380-9558"
OWNED_AUTHOR_MANIFESTS = frozenset({"Cargo.toml", "crates/ostadix-api/Cargo.toml"})
LEGACY_POLICY_BASELINE = "9754a94b9cf5d1312049ba493536d86d083c5c55"
CODEX_IDENTITY = re.compile(r"(?i)(?<![a-z0-9])codex(?![a-z0-9])")
CLAUDE_PRODUCT_IDENTITY = re.compile(
    r"(?i)(?<![a-z0-9])claude[- ]+(?:code|haiku|opus|sonnet)(?![a-z0-9])"
)
CLAUDE_ACCOUNT_IDENTITY = re.compile(
    r"(?i)^\s*@?claude(?:\s*<[^>]+>)?\s*$"
)
CLAUDE_NOREPLY_IDENTITY = re.compile(r"(?i)\bnoreply@anthropic\.com\b")
VENDOR_TOOL_IDENTITY = re.compile(
    r"(?i)^\s*(?:anthropic|openai)(?:\s*<[^>]+>)?\s*$"
)
COPILOT_IDENTITY = re.compile(
    r"(?i)(?<![a-z0-9])(?:github[- ]+)?copilot(?:\[bot\])?(?![a-z0-9])"
)
ATTRIBUTION_TRAILER = re.compile(
    r"(?im)^(?P<key>[a-z][a-z0-9-]*):[ \t]*(?P<value>[^\n]+)$"
)
ATTRIBUTION_TRAILER_KEYS = frozenset(
    {
        "author",
        "authored-by",
        "co-author",
        "co-authored-by",
        "contributed-by",
        "contributor",
        "contributors",
        "assisted-by",
        "helped-by",
        "pair-programmed-by",
        "reviewed-by",
        "signed-off-by",
        "tested-by",
        "generated-by",
        "coded-by",
        "developed-by",
        "implemented-by",
    }
)
SUPPLEMENTAL_TRAILER = re.compile(
    r"(?:^|[-_])(?:co-?author(?:ed)?|contributors?|assisted|assistance|"
    r"generated|credits?|session|transcript)(?:$|[-_])"
)
AI_CREDIT = re.compile(
    r"(?im)^[^\w\n]*(?:(?:this\s+)?(?:commit|change|code|patch)\s+"
    r"(?:was\s+|is\s+)?)?(?:generated|written|authored|coauthored|co-authored|created|"
    r"developed|implemented|coded|produced|assisted|reviewed)\s+(?:by|with|using)\s+"
    r"(?:the\s+)?(?:help\s+of\s+)?(?:an?\s+)?[^\w\n]*(?:AI\b|artificial intelligence\b|"
    r"LLM\b|ChatGPT\b|Codex\b|Claude\b|Copilot\b|Gemini\b|Grok\b|"
    r"OpenAI\b|Anthropic\b)"
)
AI_CREDIT_LABEL = re.compile(
    r"(?im)^[^\w\n]*(?:AI|LLM)[ -](?:generated|assisted|authored)"
    r"(?:[.! \t]*$|[ \t]+(?:commit|change|patch|code)[.! \t]*$)"
)
OBJECT_ID = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
ZERO_OBJECT_ID = re.compile(r"^0+$")
AUTHOR_SURFACES = (
    "NOTICE",
    "ORIGIN.md",
    "crates/ostadix-api/NOTICE",
)
AUTHOR_LINE_PATTERNS = {
    "README.md": (re.compile(r"(?m)^\*By .+\*$"),),
    "SPEC.md": (re.compile(r"(?m)^Author:\s*.+$"),),
    "ostadix-lang-info.md": (re.compile(r"(?m)^- \*\*Author:\*\*\s*.+$"),),
}


@dataclass(frozen=True)
class CommitMetadata:
    oid: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    message: str


@dataclass(frozen=True)
class Violation:
    location: str
    field: str
    value: str


@dataclass(frozen=True)
class PushUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str


def contains_forbidden_identity(value: str) -> bool:
    return any(
        pattern.search(value) is not None
        for pattern in (
            CODEX_IDENTITY,
            CLAUDE_PRODUCT_IDENTITY,
            CLAUDE_ACCOUNT_IDENTITY,
            CLAUDE_NOREPLY_IDENTITY,
            VENDOR_TOOL_IDENTITY,
            COPILOT_IDENTITY,
        )
    )


def commit_violations(commit: CommitMetadata) -> list[Violation]:
    violations: list[Violation] = []
    identity_fields = (
        ("author name", commit.author_name),
        ("author email", commit.author_email),
        ("committer name", commit.committer_name),
        ("committer email", commit.committer_email),
    )
    for field, value in identity_fields:
        if (
            field in ("author name", "committer name") and value != PROJECT_AUTHOR
        ) or contains_forbidden_identity(value):
            violations.append(Violation(commit.oid, field, value))

    for match in ATTRIBUTION_TRAILER.finditer(commit.message):
        key = match.group("key").lower()
        value = match.group("value").strip()
        if (
            key in ATTRIBUTION_TRAILER_KEYS
            or key == "agent-logs-url"
            or SUPPLEMENTAL_TRAILER.search(key)
        ):
            violations.append(Violation(commit.oid, f"{key} trailer", value))
    for pattern in (AI_CREDIT, AI_CREDIT_LABEL):
        for match in pattern.finditer(commit.message):
            violations.append(Violation(commit.oid, "AI contribution credit", match.group(0)))
    return violations


def cff_author_values(text: str) -> list[tuple[int, str]]:
    authors: list[tuple[int, str]] = []
    author_indent: int | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if stripped.startswith("authors:"):
            author_indent = indent
            inline_value = stripped.partition(":")[2].strip()
            if inline_value:
                authors.append((line_number, inline_value))
            continue
        if author_indent is not None and indent <= author_indent:
            author_indent = None
        if author_indent is not None:
            authors.append((line_number, stripped))
    return authors


def metadata_text(path: Path, revision: str | None = None) -> str:
    if revision is None:
        return path.read_text(encoding="utf-8")
    result = subprocess.run(
        ["git", "show", f"{revision}:{path.relative_to(ROOT).as_posix()}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout.decode("utf-8")


def cff_author_violations(path: Path, revision: str | None = None) -> list[Violation]:
    violations: list[Violation] = []
    text = metadata_text(path, revision)
    for line_number, value in cff_author_values(text):
        if contains_forbidden_identity(value):
            violations.append(
                Violation(
                    str(path.relative_to(ROOT)),
                    f"authors line {line_number}",
                    value,
                )
            )
    if path.relative_to(ROOT).as_posix() == "CITATION.cff":
        violations.extend(cff_project_author_violations(text))
    return violations


def cff_project_author_violations(text: str) -> list[Violation]:
    """Validate the project's existing block-style CFF author declarations.

    This deliberately does not parse unrelated cited works or upstream notices.
    Unsupported author encodings are rejected rather than guessed as Lee.
    """
    violations: list[Violation] = []
    lines = text.splitlines()
    in_preferred = False
    seen_software = False
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if indent == 0 and stripped and not stripped.startswith("#"):
            in_preferred = stripped.startswith("preferred-citation:")
        if not stripped.startswith("authors:") or not (
            indent == 0 or (in_preferred and indent == 2)
        ):
            continue
        field = "software authors" if indent == 0 else "preferred-citation authors"
        seen_software |= indent == 0
        if stripped.partition(":")[2].strip():
            violations.append(Violation("CITATION.cff", field, "expected one block-style Lee author"))
            continue
        authors: list[dict[str, str]] = []
        for child in lines[index + 1:]:
            value = child.lstrip()
            if not value or value.startswith("#"):
                continue
            if len(child) - len(value) <= indent:
                break
            if value.startswith("- "):
                authors.append({})
                value = value[2:]
            key, separator, scalar = value.partition(":")
            if not authors or not separator or key in authors[-1]:
                authors = []
                break
            authors[-1][key] = scalar.strip().strip("\"'")
        valid = len(authors) == 1
        if valid:
            author = authors[0]
            name = author.get("name")
            if name is None:
                name = f"{author.get('given-names', '')} {author.get('family-names', '')}"
            valid = name == PROJECT_AUTHOR
            if "given-names" in author or "family-names" in author:
                valid &= (author.get("given-names"), author.get("family-names")) == ("Lee Daghlar", "Ostadi")
            if "orcid" in author:
                valid &= author["orcid"] in (PROJECT_ORCID, f"https://orcid.org/{PROJECT_ORCID}")
        if not valid:
            violations.append(Violation("CITATION.cff", field, "expected only Lee Daghlar Ostadi and his declared ORCID"))
    if not seen_software:
        violations.append(Violation("CITATION.cff", "software authors", "missing Lee author"))
    return violations


def owned_cargo_author_violations(
    relative: str, manifest: dict[str, object]
) -> list[Violation]:
    if relative not in OWNED_AUTHOR_MANIFESTS:
        return []
    groups: dict[str, list[str]] = {}
    for field, author in cargo_author_values(manifest):
        groups.setdefault(field, []).append(author)
    if not groups:
        return [Violation(relative, "authors", "missing Lee author")]
    violations = []
    for field, authors in groups.items():
        if len(authors) != 1 or not re.fullmatch(
            re.escape(PROJECT_AUTHOR) + r"(?: <[^<>\n]+>)?", authors[0]
        ):
            violations.append(Violation(relative, field, repr(authors)))
    return violations


def string_leaves(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for nested in value for item in string_leaves(nested)]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in string_leaves(nested)]
    return []


def cargo_author_values(manifest: dict[str, object]) -> list[tuple[str, str]]:
    authors: list[tuple[str, str]] = []
    package = manifest.get("package")
    if isinstance(package, dict):
        authors.extend(
            ("package.authors", value)
            for value in string_leaves(package.get("authors"))
        )
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        workspace_package = workspace.get("package")
        if isinstance(workspace_package, dict):
            authors.extend(
                ("workspace.package.authors", value)
                for value in string_leaves(workspace_package.get("authors"))
            )
    return authors


def forbidden_lines(path: Path, text: str, *, line_offset: int = 0) -> list[Violation]:
    violations: list[Violation] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if contains_forbidden_identity(line):
            violations.append(
                Violation(
                    str(path.relative_to(ROOT)),
                    f"line {line_number + line_offset}",
                    line.strip(),
                )
            )
    return violations


def codeowner_violations(path: Path, revision: str | None = None) -> list[Violation]:
    violations: list[Violation] = []
    for line_number, line in enumerate(metadata_text(path, revision).splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for owner in stripped.split()[1:]:
            if contains_forbidden_identity(owner):
                violations.append(
                    Violation(
                        str(path.relative_to(ROOT)),
                        f"owner line {line_number}",
                        owner,
                    )
                )
    return violations


def markdown_section(
    path: Path, heading: str, revision: str | None = None
) -> tuple[str, int]:
    lines = metadata_text(path, revision).splitlines()
    try:
        heading_index = lines.index(heading)
    except ValueError:
        raise RuntimeError(f"missing authorship section {heading!r} in {path.relative_to(ROOT)}")
    start = heading_index + 1
    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    return "\n".join(lines[start:end]), start


@lru_cache(maxsize=32)
def revision_files(revision: str) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", revision],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return tuple(entry.decode() for entry in result.stdout.split(b"\0") if entry)


def tracked_files(pattern: str, revision: str | None = None) -> list[Path]:
    if revision is not None:
        return [
            ROOT / path
            for path in revision_files(revision)
            if fnmatch(path, pattern) or fnmatch(Path(path).name, pattern)
        ]
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", pattern],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / entry.decode() for entry in result.stdout.split(b"\0") if entry]


def project_metadata_violations(revision: str | None = None) -> list[Violation]:
    violations: list[Violation] = []
    for path in tracked_files("*Cargo.toml", revision):
        manifest = tomllib.loads(metadata_text(path, revision))
        violations.extend(owned_cargo_author_violations(path.relative_to(ROOT).as_posix(), manifest))
        for field, author in cargo_author_values(manifest):
            if contains_forbidden_identity(author):
                violations.append(
                    Violation(str(path.relative_to(ROOT)), field, author)
                )
    for path in tracked_files("*.cff", revision):
        violations.extend(cff_author_violations(path, revision))
    for relative in AUTHOR_SURFACES:
        path = ROOT / relative
        violations.extend(forbidden_lines(path, metadata_text(path, revision)))
    violations.extend(codeowner_violations(ROOT / ".github/CODEOWNERS", revision))
    readme = ROOT / "README.md"
    authorship_section, line_offset = markdown_section(
        readme, "## Citation and authorship", revision
    )
    violations.extend(
        forbidden_lines(readme, authorship_section, line_offset=line_offset)
    )
    for relative, patterns in AUTHOR_LINE_PATTERNS.items():
        path = ROOT / relative
        text = metadata_text(path, revision)
        for pattern in patterns:
            for match in pattern.finditer(text):
                if contains_forbidden_identity(match.group(0)):
                    line_number = text.count("\n", 0, match.start()) + 1
                    violations.append(
                        Violation(relative, f"author line {line_number}", match.group(0))
                    )
    for name in ("AUTHORS", "AUTHORS.md", "CONTRIBUTORS", "CONTRIBUTORS.md"):
        for path in tracked_files(name, revision):
            violations.extend(forbidden_lines(path, metadata_text(path, revision)))
    return violations


def policy_boundary(head: str) -> tuple[str | None, str]:
    """Return the policy-introduction commit and its exclusive scan base.

    Discovering this boundary from Git history keeps the guard valid when all
    descendant commit IDs change during a provenance-only history rewrite.
    Before the policy is committed, use the audited legacy tip so the working
    tree implementation remains testable.
    """
    result = subprocess.run(
        [
            "git",
            "log",
            "--diff-filter=A",
            "--reverse",
            "--format=%H",
            head,
            "--",
            POLICY_PATH,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    introductions = result.stdout.split()
    if not introductions:
        return None, LEGACY_POLICY_BASELINE
    if len(introductions) != 1:
        raise RuntimeError(
            f"expected one attribution-policy introduction, found {len(introductions)}"
        )
    policy_commit = introductions[0]
    parent_result = subprocess.run(
        ["git", "show", "-s", "--format=%P", policy_commit],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    parents = parent_result.stdout.split()
    if len(parents) != 1:
        raise RuntimeError(
            "the attribution policy must be introduced by a single-parent commit"
        )
    return policy_commit, parents[0]


def revision_spec(
    base: str | None,
    head: str,
    *,
    fallback_base: str | None = None,
) -> str:
    if fallback_base is None:
        _, fallback_base = policy_boundary(head)
    effective_base = (
        base if base and not ZERO_OBJECT_ID.fullmatch(base) else fallback_base
    )
    return f"{effective_base}..{head}"


def select_scan_base(
    base: str | None,
    fallback_base: str,
    *,
    base_is_ancestor: bool,
) -> str:
    if not base or ZERO_OBJECT_ID.fullmatch(base) or not base_is_ancestor:
        return fallback_base
    return base


def is_ancestor(base: str, head: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, head],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"could not compare attribution base {base} with {head}")
    return result.returncode == 0


def commit_exists(revision: str) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode not in (0, 1, 128):
        raise RuntimeError(f"could not resolve attribution revision {revision}")
    return result.returncode == 0


def commits_in(
    base: str | None,
    head: str,
    *,
    fallback_base: str | None = None,
) -> list[str]:
    if fallback_base is None:
        _, fallback_base = policy_boundary(head)
    base_is_ancestor = bool(
        base
        and not ZERO_OBJECT_ID.fullmatch(base)
        and commit_exists(base)
        and is_ancestor(base, head)
    )
    effective_base = select_scan_base(
        base,
        fallback_base,
        base_is_ancestor=base_is_ancestor,
    )
    result = subprocess.run(
        [
            "git",
            "rev-list",
            "--reverse",
            revision_spec(effective_base, head, fallback_base=fallback_base),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()


def read_commit(oid: str) -> CommitMetadata:
    result = subprocess.run(
        [
            "git",
            "show",
            "-s",
            "--format=%an%x00%ae%x00%cn%x00%ce%x00%B",
            oid,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    fields = result.stdout.decode("utf-8", errors="replace").split("\0", 4)
    if len(fields) != 5:
        raise RuntimeError(f"could not parse attribution fields for commit {oid}")
    return CommitMetadata(oid, *fields)


def parse_push_updates(text: str) -> list[PushUpdate]:
    """Read Git's pre-push protocol without treating ref text as shell code."""
    updates = []
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if len(fields) != 4:
            raise RuntimeError(f"invalid pre-push input on line {line_number}")
        update = PushUpdate(*fields)
        if not all(OBJECT_ID.fullmatch(oid) for oid in (update.local_oid, update.remote_oid)):
            raise RuntimeError(f"invalid pre-push object ID on line {line_number}")
        if not update.remote_ref.startswith("refs/"):
            raise RuntimeError(f"invalid pre-push remote ref on line {line_number}")
        updates.append(update)
    return updates


def commit_tip(oid: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{oid}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def tag_violations(oid: str) -> list[Violation]:
    violations: list[Violation] = []
    while True:
        kind = subprocess.run(
            ["git", "cat-file", "-t", oid], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        if kind != "tag":
            return violations
        body = subprocess.run(
            ["git", "cat-file", "-p", oid], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout
        header, _, message = body.partition("\n\n")
        tagger = re.search(r"(?m)^tagger (.+) <([^>]*)> \d+ [+-]\d{4}$", header)
        target = re.search(r"(?m)^object ([0-9a-f]+)$", header)
        if tagger is None or target is None or not OBJECT_ID.fullmatch(target.group(1)):
            raise RuntimeError(f"annotated tag {oid} has invalid tagger or target metadata")
        name, email = tagger.groups()
        # Follow nested annotated tags as well as the directly pushed tag.
        metadata = CommitMetadata(oid, name, email, name, email, message)
        violations.extend(commit_violations(metadata))
        oid = target.group(1)


def pre_push_violations(text: str) -> list[Violation]:
    """Inspect exact outgoing tips; never read another branch's working files."""
    violations: list[Violation] = []
    checked_commits: set[str] = set()
    checked_tips: set[str] = set()
    for update in parse_push_updates(text):
        if ZERO_OBJECT_ID.fullmatch(update.local_oid):
            continue  # Deletion publishes no commit or tag.
        head = commit_tip(update.local_oid)
        policy_commit, policy_base = policy_boundary(head)
        if policy_commit is None:
            raise RuntimeError(
                f"{update.remote_ref} does not contain the attribution-policy introduction"
            )
        violations.extend(tag_violations(update.local_oid))
        if head not in checked_tips:
            violations.extend(project_metadata_violations(head))
            checked_tips.add(head)
        # A new branch, missing old object, or rewritten lineage uses the
        # established policy boundary. Legacy history is never rewritten here.
        commits = commits_in(update.remote_oid, head, fallback_base=policy_base)
        for oid in [head, *commits]:
            if oid not in checked_commits:
                violations.extend(commit_violations(read_commit(oid)))
                checked_commits.add(oid)
    return violations


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        help="exclusive base commit; empty/all-zero uses the discovered policy boundary",
    )
    parser.add_argument("--head", default="HEAD", help="inclusive head commit")
    parser.add_argument(
        "--pre-push", action="store_true",
        help="validate the exact outgoing refs supplied by Git on stdin",
    )
    parser.add_argument(
        "--ref-type",
        choices=("branch", "tag"),
        default="branch",
        help="tags must contain the attribution-policy introduction commit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.pre_push:
        try:
            return report_violations(pre_push_violations(sys.stdin.read()))
        except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
            print(f"attribution pre-push check failed: {error}", file=sys.stderr)
            return 1
    policy_commit, policy_base = policy_boundary(args.head)
    base = policy_base if args.ref_type == "tag" else args.base
    if args.ref_type == "tag" and (
        policy_commit is None or not is_ancestor(policy_commit, args.head)
    ):
        boundary = policy_commit or "<not present>"
        print(
            f"release tag {args.head} does not contain attribution-policy "
            f"introduction {boundary}",
            file=sys.stderr,
        )
        return 1
    violations = project_metadata_violations()
    for oid in commits_in(base, args.head, fallback_base=policy_base):
        violations.extend(commit_violations(read_commit(oid)))

    return report_violations(violations)


def report_violations(violations: list[Violation]) -> int:
    if violations:
        print("Lee-only attribution policy failed:", file=sys.stderr)
        for violation in violations:
            print(
                f"  {violation.location}: {violation.field}: {violation.value}",
                file=sys.stderr,
            )
        return 1

    print("attribution policy: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
