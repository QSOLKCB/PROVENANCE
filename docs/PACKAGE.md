# PROVENANCE Phase 11 — Portable Forensic Package

Phase 11 creates a portable archival envelope around finalized PROVENANCE evidence without changing the identities of the enclosed evidence.

~~~text
PACKAGE_CONTRACT=provenance.forensic-package.v1
PACKAGE_STATE=FINALIZED
EMBEDDED_BUNDLE_CONTRACT=provenance.bundle.v1
VERIFIER=provenance_verify.verify_forensic_package
~~~

## Bundle versus package

Phase 2 defines the independently verifiable evidence bundle:

~~~text
manifest.json
events/
artifact_records/
artifacts/
~~~

Phase 11 does not replace that contract. It embeds one verified Phase 2 bundle under `evidence/` and adds the archival material needed to move the evidence away from the live store.

## Layout

~~~text
package/
├── package.json
├── evidence/
│   └── <unchanged provenance.bundle.v1 contents>
├── custody/
│   └── sha256/
│       └── <custody-digest>.json
├── schemas.json
├── verification.json
└── gaps.json
~~~

`package.json` binds every file except itself by:

~~~text
path
sha256 content identity
byte count
~~~

The package envelope uses domain-separated identity:

~~~text
PROVENANCE/FORENSIC-PACKAGE/v1
~~~

with:

~~~text
self_hash_exclusion = package_identity
~~~

## State versus collection scope

These are deliberately separate:

~~~text
package_state = FINALIZED
evidence_scope = closed | open
~~~

A finalized package may therefore preserve an `open` evidence collection exactly as it existed. The package must not relabel an open collection as closed merely because the archival envelope has been finalized.

## Included metadata

`schemas.json` records the exact evidence/package contract identifiers and canonicalization version.

`verification.json` stores the independently recomputed Phase 2 bundle report and custody verification report for the bytes actually placed in the package.

`gaps.json` is recomputed from the embedded evidence and records explicit archival gaps such as:

~~~text
OPEN_COLLECTION
MISSING_ARTIFACT
DIGEST_ONLY_ARTIFACT
EVENT_COLLECTION_STATUS
CUSTODY_NOT_PRESENT
PARTIAL_CUSTODY_COVERAGE
~~~

The package verifier recomputes this file. Gap metadata therefore cannot be edited into a more flattering story without invalidating verification.

## Custody snapshot

The producer takes a stable read-only snapshot of immutable custody records.

It enumerates the custody record set, reads and independently verifies the records, re-enumerates the directory, and retries if the set changed during capture.

This does not claim a global transaction across a concurrently changing external system. It creates a stable custody snapshot from the local append-only ledger.

The CLI/MCP wrappers append a later `EXPORTED` custody event to the live custody ledger after successful package publication. That post-publication record is intentionally not retroactively inserted into the already finalized package.

## Atomic publication

The producer:

~~~text
verify source snapshot
→ obtain stable custody snapshot
→ build hidden staging directory
→ copy evidence without following symlinks
→ write custody + metadata
→ bind all members in package.json
→ independently verify staged package
→ atomic rename to final destination
→ independently verify published package
~~~

A failed build removes its staging/output directory rather than leaving a partially published package.

## Verification

Python:

~~~python
from provenance_verify import verify_forensic_package

report = verify_forensic_package("/path/to/package")
print(report.integrity_verified)
print(report.package_identity)
~~~

The verifier rejects:

~~~text
missing declared files
undeclared files
undeclared directories
symbolic links
special filesystem objects
member hash mismatches
member byte-count mismatches
invalid embedded evidence
invalid custody chains
schema metadata drift
verification metadata drift
gap metadata drift
package identity mismatch
~~~

## CLI

~~~bash
provenance package \
  --store /path/to/store \
  --custody /path/to/custody \
  --destination /path/to/forensic-package
~~~

The older `provenance export` command remains the Phase 7/8 snapshot-copy operation. Phase 11 does not silently change that historical interface.

## MCP

~~~text
provenance.package
~~~

takes one `destination` argument and uses the same Phase 11 producer/verifier contract as the CLI.

## Exit-gate demonstration

The Phase 11 test suite creates a package under one simulated machine directory, copies it to a second machine directory, removes the original package, and independently verifies the moved package with the same package identity and evidence manifest identity.

~~~bash
python3 -m unittest discover -s tests -p 'test_package.py' -v
~~~

---

## Phase 12 detached authenticity

Signatures and external anchors do not become members of the Phase 11 package.

They are detached sidecars that bind the finalized `package.json` / package identity without changing package closure or package identity.

See [TRUST.md](TRUST.md).

---

## Phase 13 verification execution

The default forensic-package verifier uses bounded parallel member hashing/counting and the optimized Phase 2 embedded-bundle verifier.

A serial reference entry point remains available:

~~~python
from provenance_verify import verify_forensic_package_reference
~~~

The optimized/reference package reports must compare exactly equal for stable inputs.

See [PERFORMANCE.md](PERFORMANCE.md).

---

## Phase 14 selective disclosure

A finalized Phase 11 package may be used as the source for a detached Phase 14 selective disclosure.

The source package itself is not rewritten. The privacy producer verifies the package and reads the retained source artifact through the same open directory descriptor.

The resulting disclosure intentionally omits source content bytes while binding the source package identity, source artifact digest/record metadata, redaction specification, derivative bytes, and DERIVED lineage event.

See [PRIVACY.md](PRIVACY.md).
