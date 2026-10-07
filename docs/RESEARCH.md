# External Research Provenance — v1.2.0

This optional module records an exact external repository revision, artifact
identities, usage bindings, citations and formalization boundaries. The core
bundle, canonicalization, custody, signatures and existing verifier contracts
keep their current schema versions and meanings.

## Evidence boundary

All research metadata is `DECLARED`. A supplied repository URL, commit, license,
theorem name or scope statement is a declaration. Artifact byte verification is
a separate derived result. Matching hashes do not establish that the artifacts
belong to the stated repository revision, that a theorem is true, or that a
distribution meets its license obligations.

`verify_research_manifest` checks canonical encoding, strict schema, domain
identity, cross references, byte counts and SHA-256 hashes. Its output reports
`byte_integrity_verified` only when every listed artifact is supplied and matches.
Missing artifacts remain listed and fail that result. All supplied artifact
bytes are addressed by digest, so no manifest path is opened or URL fetched.

Verification receipts are referenced artifacts, not an automatic proof-success
flag. Their bytes are checked like any other artifact. Receipt authenticity,
execution, theorem equivalence and mathematical validity need a separate
checker. The report explicitly leaves upstream membership, mathematical
validity and license compliance `not_checked`. `metadata_class` is null until
the core passes schema validation; invalid input never acquires a classification.
Artifact lookup failures are visible gaps. Ordinary backend exceptions also
record their type/message in `errors` and allow remaining artifact checks to
continue; process cancellation (`KeyboardInterrupt`/`SystemExit`) propagates.
Excessive JSON/canonical nesting
returns a failed report rather than propagating a recursion exception.

## Manifest contract

`provenance.research-manifest.v1` uses the existing
`provenance.canonical-json.v1`. Every object rejects unknown or missing keys.
The envelope contains `core`, `research_identity` and `self_hash_exclusion`.
The last field must be `research_identity`. Its identity is:

```text
sha256("PROVENANCE/RESEARCH-MANIFEST/v1\0" + canonical_json_bytes(core))
```

| Core field | Meaning |
|---|---|
| `schema`, `canonicalization`, `evidence_class` | Exact version identifiers and `DECLARED` |
| `source` | `project`, `repository`, exact lowercase Git `commit`, explicit `commit_algorithm`, declared `license` |
| `artifacts` | Nonempty list of `key`, portable relative `path`, `origin`, `role`, `content_identity`, `byte_count` |
| `uses` | Nonempty list of `upstream`, nullable `local`, `mode`, nullable `modification_notice` |
| `claims` | Nonempty list separating manuscript, formalized and local scope |
| `attribution` | Credit, upstream license artifact, NOTICE observation state and upstream citation artifacts |

`commit_algorithm` is `sha1` (40 lowercase hex commit characters) or
`sha256` (64). The algorithm is declared explicitly, never inferred from length;
unknown algorithms and width mismatches are rejected. This field identifies the
Git object algorithm separately from the manifest/artifact SHA-256 algorithm.

Artifact keys and origin/path pairs must be unique. Origins are `upstream` and
`local`. Roles are `source`, `local`, `license`, `notice`, `citation`, `scope`,
`comparator`, `receipt`. Byte counts are non-negative safe integers; hashes use
`sha256:<64 lowercase hex>`. Paths are metadata only and must not contain
absolute paths, empty/dot/parent segments, backslashes, colons or control characters
(C0 U+0000–U+001F, DEL U+007F, and C1 U+0080–U+009F).
Artifact order is meaningful canonical input; sealing preserves list order.

| Usage mode | Required binding |
|---|---|
| `reference` | Upstream artifact; local and modification notice are null |
| `copied` | Upstream and local artifacts have identical hashes and byte counts; notice is null |
| `adaptation` | Upstream and local artifacts plus a nonempty modification notice |
| `derived` | Upstream and local artifacts plus a nonempty modification notice |

Each claim contains `family`, `manuscript`, `manuscript_scope`,
`formalized_scope`, `local_scope`, nullable `scope_artifact`, `declarations`,
nullable `comparator`, and `verification_receipts`. Artifact references must
resolve to the appropriate roles. Comparator references require a scope artifact
and at least one declaration. Empty receipts mean no execution evidence supplied.
For unformalized work, use an explicit scope description with null formal artifact
references and an empty declaration list.

Attribution contains `credit`, `license_artifact`, `notice_status`,
`notice_artifact`, and nonempty `citations`. NOTICE status is `present`,
`not_observed`, or `absent_in_inspected_tree`; only `present` accepts a NOTICE
artifact reference. The observation status is itself a declaration.

License and citation artifacts are mandatory so downstream consumers can retain
the source license and exact citation rather than a guessed bibliographic entry.
Modification notices must also appear in redistributed modified files where
required by the source license. This manifest records the notice; it does not
insert notices or certify legal compliance.

## Python API and existing store

```python
from provenance_core import EvidenceClass, EventCore, EventEnvelope
from provenance_research import seal_research_manifest, verify_research_manifest
from provenance_store import LocalEvidenceStore

# core is a declaration following the schema above.
# contents maps sha256 identities to the exact retained artifact bytes.
sealed = seal_research_manifest(core)
report = verify_research_manifest(sealed, contents)
if not report["byte_integrity_verified"]:
    raise ValueError(report)

store = LocalEvidenceStore("research-store")
for raw in contents.values():
    store.put_artifact(raw)
record = store.put_artifact(sealed, media_type="application/json")
store.put_event(EventEnvelope.seal(EventCore(
    evidence_class=EvidenceClass.DECLARED,
    actor="operator:research", operation="research.register",
    inputs=tuple(contents), outputs=(record.content_identity,),
)))
snapshot = store.finalize(scope="closed")
```

The snapshot can pass through existing custody, export, package, signing and
transfer paths. Those paths verify ordinary retained artifact bytes. They do
not implicitly run this research-specific verifier. Run it explicitly as above
to check the research declaration contract. Corrections produce new sealed
artifacts and events; they never rewrite earlier evidence.

The working offline example is [OpenAI Math](../examples/openai_math/README.md).
It retains five unmodified files at one upstream commit, the original Apache-2.0
license and supplied citation. It has no proof-execution receipts or adopted
mathematical result. The challenge statement's placeholder is upstream
specification material, not a PROVENANCE proof.

## Validation

```bash
python3 -m unittest discover -s tests -p 'test_research.py' -v
python3 -m examples.openai_math.verify
```

The tests exercise fixed identities, tampering, missing/wrong bytes, strict JSON,
cross references, reuse notices, sealing immutability and existing-store integration.
