# PROVENANCE Phase 14 — Privacy and Selective Disclosure

Phase 14 lets a deployment disclose a verifiable derivative without publishing the original source bytes.

The reference implementation is deterministic byte-range redaction over a finalized Phase 11 forensic package.

~~~text
source forensic package
    ↓ verified through an open directory descriptor
retained source artifact
    ↓ deterministic byte-range mask
new DERIVED artifact
    ↓
finalized selective-disclosure package
~~~

## Core rule

A redacted artifact is **not** the original artifact.

It receives a new content identity and is linked to the source by a DERIVED event:

~~~text
evidence_class = DERIVED
actor          = provenance-privacy:redaction/v1
operation      = privacy.redact.byte_ranges
inputs         = [source artifact identity]
outputs        = [derivative artifact identity]
relationship   = derived_from → source artifact identity
~~~

A redaction that produces bytes identical to the source is rejected rather than represented as a new derivative.

## Disclosure layout

~~~text
disclosure/
├── disclosure.json
├── source_artifact_record.json
├── redaction_spec.json
├── derivative.bin
├── derivative_artifact_record.json
└── derivation_event.json
~~~

The disclosure intentionally omits the original source content bytes.

`source_artifact_record.json` preserves the original artifact metadata and original retention state as an exact witness.

`disclosure.json` separately declares:

~~~text
source_disclosure_retention     = DIGEST_ONLY
derivative_disclosure_retention = CONTENT_RETAINED
~~~

This distinction is important:

~~~text
original artifact was CONTENT_RETAINED in the source package
does not imply
original content is disclosed in this selective disclosure
~~~

## Redaction specification

The reference transform uses sorted, non-overlapping half-open byte ranges:

~~~text
[start, end)
~~~

Each selected source byte is replaced with one declared `mask_byte` value.

The transform preserves total byte length.

Example:

~~~text
source:     token=SECRET-12345
range:            ^^^^^^^^^^^^
mask byte: *
derivative: token=************
~~~

Ranges must:

- contain at least one byte;
- remain within the source byte count;
- not overlap;
- be expressed in canonical sorted order after normalization.

Byte offsets and lengths are themselves disclosed metadata. Use a different privacy transform if those positions are sensitive.

## What standalone verification proves

Without the source package, the independent verifier can verify:

~~~text
disclosure envelope identity
exact disclosure membership
all disclosed member hashes and byte counts
source artifact digest + exact original ArtifactRecord metadata
redaction-spec identity
retained derivative content identity
DERIVED event identity
source → derivative lineage relationship
~~~

The report then states:

~~~text
integrity              = VERIFIED
lineage                = VERIFIED
transformation         = NOT_ATTEMPTED_SOURCE_WITHHELD
source_package_binding = NOT_ATTEMPTED
source_content_disclosed = false
~~~

This does **not** claim that the hidden source bytes were independently re-read.

## What source-bound verification additionally proves

When the original Phase 11 package is supplied, the verifier:

1. independently verifies that source package;
2. checks the package identity named by the disclosure;
3. verifies the source artifact is uniquely present and `CONTENT_RETAINED`;
4. verifies its exact ArtifactRecord equals the disclosure witness;
5. reads and hashes the original source bytes;
6. reapplies the declared redaction ranges/mask;
7. compares the recomputed derivative byte-for-byte with `derivative.bin`.

Successful verification reports:

~~~text
source_package_binding = VERIFIED
transformation         = VERIFIED
~~~

Disclosure integrity remains a separate dimension. Supplying the wrong source package can make source binding/transformation fail without changing the fact that the disclosure's own hashes and lineage record are internally valid.

## Descriptor binding

The producer holds the source package directory open, verifies that exact descriptor, reads source bytes through it, and verifies the staged disclosure against the same descriptor before atomic publication.

This prevents source-path replacement between verification and derivation.

Phase 14 also exposes descriptor-bound Phase 11 package verification through `verify_forensic_package_fd()`.

## Retention policy

Phase 14 does not add a hidden deletion mechanism.

The existing core retention states remain authoritative:

~~~text
CONTENT_RETAINED
DIGEST_ONLY
MISSING
~~~

The reference redaction producer requires a source artifact whose content is retained in the source package, because deterministic redaction cannot be computed from a digest alone.

A `DIGEST_ONLY` source is therefore rejected for redaction.

Selective disclosure can then disclose only the source digest/metadata while retaining the derivative bytes.

## CLI

Create a disclosure:

~~~bash
provenance redact-disclosure \
  --package /path/to/source-package \
  --source sha256:<source-digest> \
  --range 17:29 \
  --output /path/to/disclosure
~~~

Multiple `--range START:END` values are allowed.

Default mask byte is decimal `42` (`*`). Override with `--mask-byte 0..255`.

Verify without source bytes:

~~~bash
provenance verify-disclosure \
  --disclosure /path/to/disclosure
~~~

Verify and recompute against the original package:

~~~bash
provenance verify-disclosure \
  --disclosure /path/to/disclosure \
  --source-package /path/to/source-package
~~~

## What this is not

The reference transform is **redaction**, not encryption.

It does not provide:

~~~text
confidentiality for the disclosed derivative beyond removed byte values
access control
key management
semantic PII detection
format-aware structured-field redaction
cryptographic zero-knowledge proof
reversible tokenization
~~~

Those may be added as optional future privacy mechanisms without changing the rule that every privacy transform creates a derivative and preserves known lineage.

## Security/privacy cautions

- Redaction ranges can reveal where sensitive material existed.
- Source byte count and media type remain disclosed.
- The source SHA-256 identity remains disclosed and may enable confirmation attacks if an adversary can guess candidate source content.
- Do not treat digest-only disclosure as anonymity.
- Credentials/private keys should still be excluded at collection time where possible rather than collected and redacted later.

## CI exit-gate evidence

The Phase 14 test lane verifies:

~~~text
source secret absent from every disclosure file
standalone lineage verification
source-bound exact transform recomputation
wrong source package separated from disclosure integrity
tampered derivative rejection
OBSERVED-vs-DERIVED relabeling rejection
DIGEST_ONLY source rejection
overlapping-range rejection
no-op redaction rejection
original-retention vs disclosure-retention distinction
~~~

~~~bash
python3 -m unittest tests.test_privacy -v
~~~
