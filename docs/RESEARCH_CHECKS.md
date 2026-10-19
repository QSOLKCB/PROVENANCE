# Source-bound research checks — v1

`provenance.research-check-receipt.v1` is an optional, separately versioned
artifact. It records declared source/build/output relationships and a retained
basis for each expected result. Its verifier derives exact-byte comparisons
from supplied evidence. It does not change research-manifest v1, canonical JSON
v1, historical fixtures, core events, custody, or any existing verifier.

## Boundary and motivation

An integrity check answers whether retained bytes match their declared hashes.
An expected-result comparison asks a different, narrower question: whether the
retained output equals a separately supplied expectation. Neither question proves
that the expectation is independently derived, the build ran, or the result is
semantically correct. All source, build and expectation-method metadata remains
`DECLARED`. The report keeps `build_execution`, `source_membership`,
`expectation_independence` and `semantic_correctness` at `not_checked` even when
every byte check and comparison succeeds.

The design is inspired by [SolidCraft's reference-test approach](https://github.com/tangency-labs/solidcraft/blob/main/docs/oracle.md),
which separates analytic/external expected values from produced results, and
Ubuntu's [source/build/output SBOM separation](https://documentation.ubuntu.com/release-notes/26.10/#linux-kernel-7-3).
No upstream test totals, CAD results, or SBOM compliance claims are adopted.
This is not an SPDX parser or a build executor. Numeric tolerances, CAD geometry,
round-trip equivalence, proof execution, and external-oracle authenticity are
outside v1. Such material can be retained as opaque basis/recipe bytes; it is
not interpreted as a successful check.

## Strict contract

Every object rejects unknown or missing keys. Canonical encoding is the existing
`provenance.canonical-json.v1`. List order is retained and affects identity.

The envelope contains `core`, `receipt_identity`, and `self_hash_exclusion`.
The exclusion field must equal `receipt_identity`. The receipt identity is the
SHA-256 identity of these bytes:

```text
"PROVENANCE/RESEARCH-CHECK-RECEIPT/v1\0" + canonical_json_bytes(core)
```

The core has exactly these fields:

- `schema`: `provenance.research-check-receipt.v1`
- `canonicalization`: `provenance.canonical-json.v1`
- `evidence_class`: `DECLARED`
- `source`: `repository`, `commit_algorithm`, `commit`. Repository is a nonempty
  declaration. Git algorithm is explicitly `sha1` or `sha256`, with respectively
  40 or 64 lowercase hex commit characters. It describes the source artifacts;
  it does not assert that later build/output/expectation artifacts belong to that
  commit.
- `artifacts`: nonempty list of `key`, `role`, `content_identity`, `byte_count`.
  Keys are unique nonempty strings. Roles are `source`, `build`, `output`,
  `expectation`, and `expectation_basis`. SHA-256 identities are algorithm-labeled
  lowercase hex; byte counts are non-negative safe integers, excluding booleans.
  Identical content identities may appear in different roles: an output is
  expected to share bytes with a matching expectation. Role labels alone cannot
  prove independent origin.
- `build`: nonempty unique `sources` references, a `recipe` reference, and
  nonempty unique `outputs` references. References must resolve to the matching
  source/build/output artifact roles. This is a declared relationship, not
  authenticated causal provenance.
- `checks`: nonempty list of `key`, `output`, `expectation`, `expectation_basis`,
  `expectation_method`, `comparison`. Each reference must resolve to its matching
  role, and the output must be in `build.outputs`. Check keys and
  output/expectation/basis triples must be unique. Method is `analytic` or
  `external_oracle`, describing a declared hand/mathematical derivation or
  separate tool/source; the retained basis explains its provenance and limits.
  Comparison is exactly `exact_bytes`; unsupported methods/comparisons fail
  schema validation rather than silently degrading.

Artifacts have no filesystem locator. The caller supplies a mapping from content
identities to retained `bytes`. The verifier opens no path, fetches no URL, and
executes no supplied recipe, proof, or receipt.

## Verification and gaps

`verify_research_check_receipt(data, contents)` returns the separately versioned
`provenance.research-check-verification-report.v1` report. The `canonical`,
`schema_valid`, and `identity_valid` booleans expose completed stages. Metadata
classification remains null until the strict core schema validates.

Every artifact must match both its byte count and SHA-256 identity before any
comparison runs. Missing artifacts are listed and fail `byte_integrity_verified`;
wrong bytes and ordinary lookup exceptions appear in `errors`. Other artifact
lookups continue after an ordinary backend failure. Process cancellation
(`KeyboardInterrupt`/`SystemExit`) propagates. Invalid/nested inputs return a
failed report rather than acquiring a successful comparison.

Verified bytes are retained for comparison without re-fetching from the backend.
Each check reports `matched`, `mismatched`, or `not_checked`. With any integrity
gap all comparisons remain `not_checked`, even when the output and expected
bytes happen to match. `comparisons_verified` requires a valid receipt, complete
artifact integrity, and every exact-byte comparison matching. A legitimate
mismatching result can have byte integrity true and comparisons false; it is
retained evidence of disagreement, not corrupted evidence.

## API and existing integration

```python
from provenance_research import (
    seal_research_check_receipt,
    verify_research_check_receipt,
)

sealed = seal_research_check_receipt(core)
report = verify_research_check_receipt(sealed, contents)
```

Sealing snapshots declarations and validates structure; it does not inspect the
artifact mapping or execute a check. `research_check_receipt_identity(core)`
computes the domain-separated identity of a valid core.

To link this into research-manifest v1, retain the sealed receipt as an artifact
with role `receipt`, then reference its key in a claim's `verification_receipts`.
The existing manifest verifier still verifies only that receipt's bytes. Invoke
the new check verifier explicitly, supplying its referenced artifacts, to check
the new contract. Store the receipt and its artifacts through the existing
`LocalEvidenceStore` APIs; package/transfer/custody remain ordinary evidence
operations. This module does not make their verifiers execute embedded receipts.
Corrections must create new artifacts and events, preserving previous evidence.

The [working example](../examples/research_check/README.md) binds the pinned
canonicalizer source, a fixed recipe, an observed output, a hand-authored expected
file, and its derivation. It deliberately keeps success claims narrower than
general correctness or independence.

## Validation

```bash
python3 -m unittest discover -s tests -p 'test_research*.py' -v
python3 -m examples.openai_math.verify
python3 -m examples.research_check.verify
```

Full validation follows the existing release suite, including the Rust CLI build
before complete Python test discovery. Focused research CI also checks the new
retained example. No old expected identity or historical receipt is regenerated.
