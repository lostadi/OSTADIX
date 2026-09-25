from __future__ import annotations

import unittest
from unittest.mock import Mock, patch
import subprocess
from pathlib import Path
import os
import tempfile

from scripts.check_attribution import (
    CommitMetadata,
    LEGACY_POLICY_BASELINE,
    ROOT,
    cargo_author_values,
    cff_project_author_violations,
    commit_violations,
    contains_forbidden_identity,
    owned_cargo_author_violations,
    policy_boundary,
    project_metadata_violations,
    revision_spec,
    select_scan_base,
)


def commit(**overrides: str) -> CommitMetadata:
    values = {
        "oid": "a" * 40,
        "author_name": "Lee Daghlar Ostadi",
        "author_email": "ostadi.lee@gmail.com",
        "committer_name": "Lee Daghlar Ostadi",
        "committer_email": "ostadi.lee@gmail.com",
        "message": "Document Codex as a supported development tool",
    }
    values.update(overrides)
    return CommitMetadata(**values)


class AttributionPolicyTests(unittest.TestCase):
    def test_tooling_mentions_are_not_attribution(self) -> None:
        self.assertEqual(commit_violations(commit()), [])

    def test_ai_author_and_committer_identities_are_rejected(self) -> None:
        violations = commit_violations(
            commit(
                author_name="Claude Sonnet",
                committer_email="codex-validation@localhost",
            )
        )
        self.assertEqual(
            {(item.field, item.value) for item in violations},
            {
                ("author name", "Claude Sonnet"),
                ("committer email", "codex-validation@localhost"),
            },
        )

    def test_only_exact_lee_name_is_allowed_for_both_git_identities(self) -> None:
        for field in ("author_name", "committer_name"):
            for name in ("lostadi", "Lee Ostadi", "Another Person", "AI Assistant"):
                with self.subTest(field=field, name=name):
                    self.assertTrue(commit_violations(commit(**{field: name})))
        self.assertEqual(
            commit_violations(commit(author_email="lee@example.invalid")), []
        )

    def test_all_supplemental_credit_is_rejected_even_for_unknown_tools(self) -> None:
        for key in (
            "Co-Authored-By", "Author", "Assisted-By", "Generated-By",
            "Reviewed-By", "Signed-Off-By", "Tested-By", "Pair-Programmed-By",
            "CoAuthored-By", "Credits", "Codex-Session-Id", "Agent-Transcript",
        ):
            with self.subTest(key=key):
                self.assertTrue(commit_violations(commit(
                    message=f"Change\n\n{key}: Another Person <person@example.invalid>\n"
                )))

    def test_explicit_ai_contribution_credit_is_rejected(self) -> None:
        for credit in (
            "Generated with Codex", "This commit was written by AI Assistant",
            "🤖 Generated with Claude Code", "Code reviewed by Gemini",
            "Implemented with the help of an LLM",
            "🤖 Generated with [Claude Code](https://example.invalid)",
            "AI-assisted commit", "LLM-generated",
        ):
            with self.subTest(credit=credit):
                self.assertTrue(commit_violations(commit(message=f"Change\n\n{credit}")))

    def test_factual_ai_tool_descriptions_remain_allowed(self) -> None:
        for message in (
            "Document AI-generated output detection",
            "Add Gemini integration and Codex CLI examples",
            "Preserve Gemini assistance and repair explicit Ostadix execution",
        ):
            with self.subTest(message=message):
                self.assertEqual(commit_violations(commit(message=message)), [])

    def test_ai_coauthor_and_contributor_trailers_are_rejected(self) -> None:
        violations = commit_violations(
            commit(
                message=(
                    "Implement feature\n\n"
                    "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>\n"
                    "Contributor: OpenAI Codex <codex@example.invalid>\n"
                )
            )
        )
        self.assertEqual(len(violations), 2)

    def test_project_author_metadata_is_clean(self) -> None:
        self.assertEqual(project_metadata_violations(), [])

    def test_owned_cargo_metadata_requires_sole_lee_without_rewriting_upstream_credit(self) -> None:
        for authors in (["Another Person"], ["Lee Daghlar Ostadi", "Another Person"], []):
            with self.subTest(authors=authors):
                manifest = {"package": {"authors": authors}}
                self.assertTrue(owned_cargo_author_violations("Cargo.toml", manifest))
                self.assertEqual(owned_cargo_author_violations("vendor/Cargo.toml", manifest), [])
        self.assertEqual(owned_cargo_author_violations(
            "crates/ostadix-api/Cargo.toml",
            {"package": {"authors": ["Lee Daghlar Ostadi <lee@example.invalid>"]}},
        ), [])

    def test_cff_software_and_preferred_citation_have_only_lee(self) -> None:
        text = (
            'authors:\n  - family-names: Ostadi\n    given-names: Lee Daghlar\n'
            '    orcid: "https://orcid.org/0009-0001-6380-9558"\n'
            'preferred-citation:\n  authors:\n    - family-names: Ostadi\n'
            '      given-names: Lee Daghlar\n'
        )
        self.assertEqual(cff_project_author_violations(text), [])
        for invalid in (
            text.replace("Lee Daghlar", "Someone Else", 1),
            text.replace("9558", "1234"),
            text.replace("preferred-citation:", "  - name: Another Person\npreferred-citation:"),
            text.replace("      given-names: Lee Daghlar", "      given-names: Someone Else"),
            'authors: [{name: "Lee Daghlar Ostadi"}, {name: "Another Person"}]\n',
            "title: Missing authors\n",
        ):
            with self.subTest(invalid=invalid):
                self.assertTrue(cff_project_author_violations(invalid))

    def test_agent_session_trailers_are_rejected(self) -> None:
        violations = commit_violations(
            commit(message="Fix runtime\n\nAgent-Logs-Url: https://example.invalid/session\n")
        )
        self.assertEqual([item.field for item in violations], ["agent-logs-url trailer"])

    def test_copilot_identity_is_rejected_but_tool_documentation_is_allowed(self) -> None:
        self.assertTrue(contains_forbidden_identity("GitHub Copilot <copilot@github.com>"))
        self.assertTrue(contains_forbidden_identity("copilot[bot]"))
        self.assertEqual(commit_violations(commit(message="Document Copilot integration")), [])

    def test_revision_spec_uses_policy_boundary_for_missing_or_zero_base(self) -> None:
        self.assertEqual(
            revision_spec(None, "HEAD", fallback_base=LEGACY_POLICY_BASELINE),
            f"{LEGACY_POLICY_BASELINE}..HEAD",
        )
        self.assertEqual(
            revision_spec(
                "0" * 40,
                "abc123",
                fallback_base=LEGACY_POLICY_BASELINE,
            ),
            f"{LEGACY_POLICY_BASELINE}..abc123",
        )
        self.assertEqual(
            revision_spec("base", "head", fallback_base="fallback"),
            "base..head",
        )

    @patch("scripts.check_attribution.subprocess.run")
    def test_policy_boundary_tracks_rewritten_introduction(
        self, run: Mock
    ) -> None:
        introduction = "1" * 40
        parent = "2" * 40
        run.side_effect = (
            subprocess.CompletedProcess([], 0, f"{introduction}\n", ""),
            subprocess.CompletedProcess([], 0, f"{parent}\n", ""),
        )
        self.assertEqual(policy_boundary("rewritten-head"), (introduction, parent))

    def test_checked_in_legacy_baseline_is_policy_introduction_parent(self) -> None:
        policy_commit, parent = policy_boundary("HEAD")
        self.assertIsNotNone(policy_commit)
        self.assertEqual(parent, LEGACY_POLICY_BASELINE)
        resolved = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "cat-file",
                "-e",
                f"{LEGACY_POLICY_BASELINE}^{{commit}}",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(resolved.returncode, 0)

    def test_missing_or_unrelated_push_base_uses_policy_boundary(self) -> None:
        fallback = "f" * 40
        self.assertEqual(
            select_scan_base(None, fallback, base_is_ancestor=False), fallback
        )
        self.assertEqual(
            select_scan_base("0" * 40, fallback, base_is_ancestor=False), fallback
        )
        self.assertEqual(
            select_scan_base("old-lineage", fallback, base_is_ancestor=False),
            fallback,
        )
        self.assertEqual(
            select_scan_base("current-base", fallback, base_is_ancestor=True),
            "current-base",
        )

    def test_workspace_inherited_author_identity_is_inspected(self) -> None:
        manifest = {
            "package": {"authors": {"workspace": True}},
            "workspace": {"package": {"authors": ["OpenAI Codex"]}},
        }
        self.assertEqual(
            cargo_author_values(manifest),
            [("workspace.package.authors", "OpenAI Codex")],
        )

    def test_identity_matching_is_narrow(self) -> None:
        self.assertTrue(contains_forbidden_identity("OpenAI Codex"))
        self.assertTrue(contains_forbidden_identity("claude-code@example.invalid"))
        self.assertTrue(contains_forbidden_identity("Assistant <noreply@anthropic.com>"))
        self.assertFalse(
            contains_forbidden_identity("Claude Shannon <claude@example.invalid>")
        )
        self.assertFalse(contains_forbidden_identity("Alice <alice@openai.com>"))
        self.assertFalse(contains_forbidden_identity("codec validation"))


class AttributionPrePushTests(unittest.TestCase):
    """Exercise the real hook against disposable Git history, never a remote."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ostadix-attribution-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ)
        self.env.update({
            "GIT_AUTHOR_NAME": "Lee Daghlar Ostadi",
            "GIT_AUTHOR_EMAIL": "lee@example.invalid",
            "GIT_COMMITTER_NAME": "Lee Daghlar Ostadi",
            "GIT_COMMITTER_EMAIL": "lee@example.invalid",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        self.git("init", "-q", "-b", "main")
        self.base = self.make_commit("Legacy baseline", author="Legacy Author")
        for name in ("NOTICE", "ORIGIN.md", "crates/ostadix-api/NOTICE", "SPEC.md", "ostadix-lang-info.md"):
            self.write(name, "Lee Daghlar Ostadi\n")
        self.write("README.md", "# Project\n\n## Citation and authorship\nLee Daghlar Ostadi\n")
        self.write(".github/CODEOWNERS", "* @lostadi\n")
        self.write("Cargo.toml", '[package]\nname = "fixture"\nversion = "0.1.0"\nauthors = ["Lee Daghlar Ostadi"]\n')
        for name in ("scripts/check_attribution.py", ".githooks/pre-push"):
            self.write(name, (ROOT / name).read_text())
        (self.repo / ".githooks/pre-push").chmod(0o755)
        self.policy = self.make_commit("Introduce attribution policy")

    def write(self, name: str, text: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def git(self, *args: str, env: dict[str, str] | None = None) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=env or self.env,
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def make_commit(self, message: str, author: str = "Lee Daghlar Ostadi") -> str:
        self.git("add", ".")
        env = dict(self.env, GIT_AUTHOR_NAME=author)
        self.git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-q", "-m", message, env=env)
        return self.git("rev-parse", "HEAD")

    def push_check(self, head: str, base: str | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_hook(f"refs/heads/candidate {head} refs/heads/published {base or '0' * 40}\n")

    def run_hook(self, protocol: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.repo / ".githooks/pre-push"), "origin", "unused.invalid"],
            cwd=self.repo, env=self.env, input=protocol, capture_output=True, text=True,
        )

    def test_new_branch_accepts_policy_history_without_rewriting_legacy_baseline(self) -> None:
        result = self.push_check(self.policy)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("attribution policy: pass", result.stdout)

    def test_outgoing_branch_is_checked_when_checked_out_head_is_clean(self) -> None:
        bad = self.make_commit("Candidate change", author="Someone Else")
        self.git("checkout", "--detach", self.policy)
        result = self.push_check(bad)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("author name: Someone Else", result.stderr)

    def test_interior_new_commit_cannot_hide_behind_clean_tip(self) -> None:
        self.make_commit("Candidate change", author="Someone Else")
        tip = self.make_commit("Clean tip")
        result = self.push_check(tip, self.policy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Someone Else", result.stderr)

    def test_outgoing_metadata_uses_exact_tip_instead_of_working_tree(self) -> None:
        self.write("NOTICE", "Author: Codex\n")
        bad = self.make_commit("Update authorship")
        self.git("checkout", "--detach", self.policy)
        result = self.push_check(bad)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTICE", result.stderr)
        self.write("NOTICE", "Author: Codex\n")
        result = self.push_check(self.policy)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_remote_object_scans_policy_history(self) -> None:
        bad = self.make_commit("Bad candidate", author="Someone Else")
        result = self.push_check(bad, "f" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Someone Else", result.stderr)

    def test_legacy_tip_without_policy_is_rejected(self) -> None:
        result = self.push_check(self.base)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not contain", result.stderr)

    def test_deletions_and_empty_push_publish_nothing(self) -> None:
        for protocol in ("", f"(delete) {'0' * 40} refs/heads/old {self.base}\n"):
            result = self.run_hook(protocol)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_protocol_and_noncommit_object_fail(self) -> None:
        for protocol in ("bad input\n", f"HEAD not-an-oid refs/heads/main {'0' * 40}\n"):
            result = self.run_hook(protocol)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid pre-push", result.stderr)
        blob = self.git("rev-parse", "HEAD:README.md")
        self.assertNotEqual(self.push_check(blob).returncode, 0)

    def test_annotated_tag_credit_and_tagger_are_checked(self) -> None:
        env = dict(self.env, GIT_COMMITTER_NAME="Other Tagger")
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "bad", "-m", "Release", env=env)
        result = self.push_check(self.git("rev-parse", "refs/tags/bad"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Other Tagger", result.stderr)
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "outer", "bad", "-m", "Release")
        result = self.push_check(self.git("rev-parse", "refs/tags/outer"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Other Tagger", result.stderr)
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "credit", "-m", "Release\n\nGenerated with AI")
        result = self.push_check(self.git("rev-parse", "refs/tags/credit"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AI contribution credit", result.stderr)


if __name__ == "__main__":
    unittest.main()
