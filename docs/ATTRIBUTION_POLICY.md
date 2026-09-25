# Publication attribution policy

New project commits must use **Lee Daghlar Ostadi** as both the Git author and
committer. Additional authorship, contribution, review, generation, and session
credit trailers are rejected. Explicit commit-message credit such as
`Generated with ...` or `This commit was written by ...` is rejected when it
credits an AI tool. Factual documentation of supported AI tools remains allowed.
The policy accepts Lee's legitimate email variants while rejecting known AI
identity addresses; it does not rewrite existing commits.

The owned root and independent-engine Cargo author fields must name Lee alone.
The software and preferred-citation author blocks in `CITATION.cff` must name
Lee alone and use his ORCID when one is declared. Other people's upstream
license or copyright notices are not rewritten by this policy.

The common implementation is `scripts/check_attribution.py`. CI and the local
pre-push hook call that script. The hook checks every outgoing ref supplied by
Git, including branches that are not checked out and newly created remote
branches. It reads author metadata from each exact outgoing tip, checks new
commit authors and commit messages, and checks annotated tag authorship and
messages, including nested tags. Deleting a remote ref publishes no new credit
and requires no attribution scan.

Configure the tracked hook for this checkout:

```bash
git config --local user.name 'Lee Daghlar Ostadi'
git config --local user.email 'ostadi.lee@gmail.com'
git config --local core.hooksPath .githooks
python3 scripts/check_attribution.py --head HEAD
python3 -m unittest -v tests.test_attribution_policy
```

Before changing `core.hooksPath` in another checkout, inspect its existing value
and preserve any required existing hooks. The tracked `.githooks/pre-push` must
be executable. No remote access or remote mutation is performed by the check.

New branches, missing remote base objects, and rewritten lineages are scanned
from the existing attribution-policy introduction boundary. Pre-policy legacy
history is retained; this check does not certify or rewrite that older history.
Publishing a tip that does not contain the policy introduction is rejected.
The current working tree cannot mask attribution in another outgoing branch.

Local Git hooks can be bypassed explicitly, and CI runs after a push. These
checks provide a local publication gate and a CI regression gate; they are not
a remote server access-control rule. The text checks target contribution-credit
forms rather than claiming to recognize every possible natural-language claim.
