# PROVENANCE Evidence Bundle — v1

## Status

~~~text
BUNDLE_CONTRACT=provenance.bundle.v1
VERIFIER=provenance_verify
STORAGE_BACKEND=UNSPECIFIED
~~~

This document defines the physical evidence-bundle layout consumed by the Phase 2 independent verifier.

It does **not** define how evidence must be stored while a system is running. Persistent storage remains a later module.

---

# Layout

A bundle uses identity-derived paths:

~~~text
bundle/
├── manifest.json
├── events/
│   └── sha256/
│       └── <event-digest>.json
├── artifact_records/
│   └── sha256/
│       └── <artifact-record-digest>.json
└── artifacts/
    └── sha256/
        └── <content-digest>
~~~

All JSON files must use provenance.canonical-json.v1.

Paths are derived from validated SHA-256 identities. Evidence records do not supply arbitrary filesystem paths.

---

# Manifest

manifest.json is a canonical provenance.manifest.v1 envelope.

It binds:

- the manifest core;
- artifact content identities;
- structured artifact-record identities;
- artifact retention states;
- event identities;
- collection scope.

The manifest identity is recomputed from the canonical manifest core.

The manifest_identity field is outside that hashed core and must declare:

~~~text
self_hash_exclusion = manifest_identity
~~~

---

# Artifact states

## CONTENT_RETAINED

The bundle must contain:

~~~text
artifact_records/sha256/<record-digest>.json
artifacts/sha256/<content-digest>
~~~

The verifier recomputes:

- structured artifact-record identity;
- exact content byte count;
- raw SHA-256 content identity.

## DIGEST_ONLY

The bundle must contain:

~~~text
artifact_records/sha256/<record-digest>.json
~~~

It must **not** contain retained content for that artifact.

The record means the content identity and metadata were recorded, not that the source bytes remain available.

## MISSING

The manifest records the known content identity with:

~~~text
record_identity = null
retention = MISSING
~~~

No artifact-record or content file is expected.

A closed manifest may not contain MISSING evidence. Known missing evidence therefore requires an open manifest.

---

# Event records

Every manifest event must resolve to:

~~~text
events/sha256/<event-digest>.json
~~~

The verifier checks:

- canonical JSON;
- provenance.event.v1 schema;
- evidence class;
- collection status;
- event self-hash exclusion;
- domain-separated event identity;
- artifact input/output references;
- relationship targets;
- source references for DERIVED events.

Event inputs and outputs must resolve to artifact content identities declared by the manifest.

Relationship targets must resolve to either:

- an artifact content identity in the manifest; or
- an event identity in the manifest.

---

# Closed physical membership

The verifier derives the exact expected file set from the manifest.

A valid bundle may not contain:

- missing declared files;
- undeclared extra files;
- symbolic links;
- FIFOs, sockets, device nodes, or other non-regular filesystem entries;
- substituted artifact-record files;
- retained content for DIGEST_ONLY or MISSING entries.

Bundle membership is therefore verified from identities rather than trusted filenames supplied by the producer.

---

# Verification

Python API:

~~~python
from pathlib import Path
from provenance_verify import verify_bundle

report = verify_bundle(Path("bundle"))

print(report.integrity_verified)
print(report.errors)
~~~

Before reading JSON evidence, the verifier requires each record to be a regular, non-symlink file. Special filesystem objects are rejected rather than opened.

The verifier is read-only.

It does not:

- repair evidence;
- rewrite canonical JSON;
- fill missing files;
- infer missing events;
- promote declarations into observations;
- alter the monitored system.

---

# Failure semantics

A verification failure means the evidence did not satisfy the declared v1 bundle contract.

It does **not** by itself establish:

~~~text
fraud
malice
negligence
legal liability
scientific falsehood
~~~

Those are downstream interpretations.

---

# Core rule

~~~text
RECOMPUTE.
DO NOT TRUST STORED CLAIMS WHEN THEY CAN BE RECOMPUTED.
DO NOT REPAIR THE EVIDENCE TO MAKE IT PASS.
~~~
