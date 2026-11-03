# Commit author check

New project commits must use **Lee Daghlar Ostadi** as both the Git author and
committer. Commit trailers that name an additional author, contributor,
reviewer, generator, or session are rejected, and so are message lines that
name someone other than the allowed author as the writer of the commit.
Ordinary documentation that mentions a tool is not affected. The check
accepts the allowed author's email variants and rejects other identity
addresses; it does not rewrite existing commits.

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
rule. The text checks target known trailer and message forms rather than
claiming to recognize every possible natural-language claim.
