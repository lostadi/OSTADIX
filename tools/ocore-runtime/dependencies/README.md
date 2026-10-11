# Native dependency source candidates

`../provider_sources.py` maps every observed native provider occurrence to exact
source-package candidates. It reads existing evidence without executing builds
or changing captures. Repeated linker occurrences and cold archive members
remain in the result. A package ownership claim is a candidate for finding the
original implementation; it does not establish that implementation's source
ownership, O-core lowering, or dependency closure.

```bash
python3 tools/ocore-runtime/provider_sources.py \
  --report CAPTURE/capture/report.json \
  --package-catalog package-catalog.json \
  --source-metadata source-package-index-metadata.txt \
  --source-archives source-archives \
  --source-index-provenance source-index-provenance.json \
  --provider-observation hosted-loader-observation.json \
  --output NEW-source-candidates.json
python3 -m unittest discover -s tools/ocore-runtime -p test_provider_sources.py -v
```

The output path must be new. `--report`, `--source-metadata`,
`--source-index-provenance`, and `--provider-observation` can be repeated.
Loader observations are optional and explicitly distinct from original linker
selection. The helper preserves exact input hashes, occurrence pointers,
provider paths, sizes, hashes, and archive-member identities. It checks provider
bytes and source archive sizes and SHA-256 digests. It never selects a newer
package version or silently substitutes another implementation.

The package catalog uses schema
`ocore-native-provider-package-candidates-v1` and contains `packages` records
with `binary_package`, `binary_version`, `source_package`, `source_version`, and
`providers`. Each provider claim contains `path`, `bytes`, and `sha256` plus
its ownership evidence. Source metadata is Deb822 source-index text, including
the exact version's `Checksums-Sha256` records. Supplied source-index provenance
receipts must retain repository configuration, index authentication, and index
bytes; the helper hashes those receipts without claiming to authenticate an
arbitrary supplied receipt. Optional loader evidence uses
`ocore-hosted-native-provider-observation-v1` with a `providers` array.

The result schema is `ocore-native-provider-source-candidates-v1`. All
completion and native qualification flags remain false, even when every
candidate archive is available. The next step is to build and capture each
original source implementation, including vendor patches, assembly, runtime
helpers, and platform services, then establish exact source-to-output ownership
and import the complete required closure through O-core. Supplied native
libraries are never admitted as lowered dependencies.

An October 10, 2026 hosted observation retained 95,919 provider occurrences,
36 provider identities, and 16 exact source-package candidates. All 52 source
archives were fetched and matched the recorded SHA-256 and size. This remains
diagnostic evidence: the original CPython assembly member and the source-built
Rust driver are explicit non-package gaps, and no dependency implementation is
qualified merely by downloading its sources.
