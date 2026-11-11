# Publication identity and development provenance

New project commits must use **Lee Daghlar Ostadi** as both the Git author and
committer. This identifies the maintainer publishing the change; it does not
assert that the maintainer personally typed every line or worked without
assistance. Additional Git author/co-author identity trailers remain rejected.
Factual `Generated-By`, `Assisted-By`, `Reviewed-By`, `Tested-By`, and session
provenance are allowed in commit messages and tag annotations. The check
enforces the exact maintainer name and rejects known tool/vendor identities in
Git name and email fields. It accepts the maintainer's email variants without
verifying email ownership or applying a general address allowlist. It does not
rewrite existing commits.

OSTADIX uses AI coding agents for implementation, investigation and review.
[The development disclosure](AI_ASSISTED_DEVELOPMENT.md) distinguishes that
assistance from design responsibility and observed validation. Preserve actual
tool assistance and review records rather than removing them to pass a hook.
Credit must be accurate: a tool review is not a human review, a generated test
is not evidence of execution, and a maintainer identity is not proof of source
ownership or correctness. Keep credentials and private transcripts out of public
records. The author check neither certifies provenance truth nor scans for secrets.

The owned root and independent-engine Cargo author fields must name the
allowed author alone. The software and preferred-citation author blocks in
`CITATION.cff` must name the allowed author alone and use the declared ORCID.
Other people's upstream license or copyright notices are not rewritten.

The common implementation is `scripts/check_commit_authors.py`. CI and the
local pre-push hook call that script. The hook checks every outgoing ref
supplied by Git, including branches that are not checked out and newly
created remote branches. It reads author metadata from each exact outgoing
tip, checks new commit authors and commit messages, and checks annotated tag
authors and messages, including nested tags. Deleting a remote ref adds no
commit and needs no scan.

Configure the tracked hook for this checkout:

```bash
git config --local user.name 'Lee Daghlar Ostadi'
git config --local user.email 'ostadi.lee@gmail.com'
git config --local core.hooksPath .githooks
python3 scripts/check_commit_authors.py --head HEAD
python3 -m unittest -v tests.test_commit_authors
```

Before changing `core.hooksPath` in another checkout, inspect its existing value
and preserve any required existing hooks. The tracked `.githooks/pre-push` must
be executable. No remote access or remote mutation is performed by the check.

New branches, missing remote base objects, and rewritten lineages are scanned
from the commit that introduced the check, found by following the script's
renames. Older history is retained; this check does not certify or rewrite
it. A tip that does not contain that introduction commit is rejected. The
current working tree cannot mask an author problem in another outgoing
branch.

Local Git hooks can be bypassed explicitly, and CI runs afterwards. These
checks are a local gate and a CI regression gate, not a server-side access
rule. They enforce the declared publication identity and author metadata;
they do not infer authorship or responsibility from natural-language prose.
