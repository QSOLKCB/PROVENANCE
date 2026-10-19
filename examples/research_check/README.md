# Retained source/build/output check

This offline public-data example compares one canonical JSON output with a
manually derived expectation. It adds new evidence; the OpenAI Math example and
its original manifest are unchanged.

The receipt binds:

- `provenance_core/canonical.py` from commit
  `41451bf690597a75f461299dfcbbee559c83e924` of QSOLKCB/PROVENANCE;
- `build.py`, a fixed local recipe containing its input;
- `output.json`, retained output produced by running that recipe;
- `expected.json`, separately hand-authored expected bytes;
- `expectation-basis.md`, the retained hand derivation and its limits.

The source revision applies to the source artifact, not to the later local
recipe, expectation or output. The recipe was run with Python 3.12.14 to capture
the initial output. This account is a declaration; the receipt verifier does
not authenticate that execution or certify expectation independence.

Verify without executing the producer:

```bash
python3 -m examples.research_check.verify
```

For a separate present-day reproduction, write to a new temporary file:

```bash
python3 -m examples.research_check.build > /tmp/provenance-research-reproduction.json
cmp examples/research_check/expected.json /tmp/provenance-research-reproduction.json
```

Do not overwrite retained output or regenerate the expectation to make a failing
check pass. A changed source intentionally fails receipt integrity; retain a new
receipt and output for a new revision. The verifier reads only the fixed paths
in the example helper, never paths or URLs from receipt metadata. A missing or
changed fixed file fails the helper before comparison, even when another file
has the same content digest. In the generic digest-addressed API, a missing
retained digest fails integrity and leaves comparisons `not_checked`.

Success establishes exact equality for this vector and integrity of the supplied
artifact set. It does not establish broad canonicalization correctness, source
membership, authentic build execution, or independent authorship. See
[the receipt contract](../../docs/RESEARCH_CHECKS.md).
