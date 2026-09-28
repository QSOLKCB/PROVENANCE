# PROVENANCE Local Store — v1

## Status

~~~text
STORE_FORMAT=provenance.local-store.v1
BACKEND=LOCAL_FILESYSTEM
DATABASE=NONE
CUSTODY_SEMANTICS=NOT_YET_IMPLEMENTED
~~~

The Phase 3 local store persists PROVENANCE evidence on a local filesystem without requiring an external service or database.

The store backend and the evidence-bundle contract are related but distinct:

~~~text
LOCAL STORE
    ↓ finalize()
VERIFIER-COMPATIBLE SNAPSHOT
    ↓
provenance_verify
~~~

The mutable store root is not itself an evidence bundle.

---

# Layout

~~~text
store/
├── .store.lock
├── HEAD
├── objects/
│   ├── artifacts/
│   │   └── sha256/
│   ├── artifact_records/
│   │   └── sha256/
│   └── events/
│       └── sha256/
└── snapshots/
    └── sha256/
        └── <manifest-digest>/
            ├── manifest.json
            ├── artifacts/
            ├── artifact_records/
            └── events/
~~~

HEAD points to the currently finalized manifest identity.

Snapshots beneath snapshots/sha256/ conform to BUNDLE.md and are independently verified before HEAD advances.

---

# Object publication

Store objects are immutable after publication.

Publication follows:

~~~text
write temporary file
→ fsync temporary file
→ atomically link into identity path
→ fsync containing directory
→ remove temporary file
~~~

The final identity path is never overwritten.

If an object already exists:

- exact bytes are reused;
- conflicting bytes fail explicitly;
- the existing object is not repaired or replaced.

An interrupted temporary write may leave no authoritative object.

Temporary files are not evidence authority.

---

# Deduplication

Raw artifact bytes use their ordinary SHA-256 content identity.

Exact content can therefore be stored once and referenced by multiple events or snapshots.

Deduplication is based on cryptographic identity and exact bytes.

It is never based on:

- filename;
- media type alone;
- path similarity;
- timestamps.

---

# Snapshots

finalize() builds a verifier-compatible snapshot from the currently bound:

- artifact states;
- artifact records;
- retained artifact bytes;
- event records.

The snapshot manifest is sealed using the Phase 1 evidence model.

Before publication through HEAD, the snapshot must pass provenance_verify.

If verification fails:

~~~text
HEAD DOES NOT ADVANCE
~~~

A snapshot created before a failed HEAD update may remain as an unreferenced immutable snapshot. It is not the current store state until HEAD points to it.

---

# Reopening

Opening an existing store reads HEAD, independently verifies the referenced snapshot, and reconstructs working state from the verified manifest.

The store does not trust unverified mutable process state from an earlier run.

A previously finalized open snapshot may later be extended into a new snapshot.

For example:

~~~text
snapshot A
artifact X = MISSING

        ↓ bytes later become available

snapshot B
artifact X = CONTENT_RETAINED
~~~

Snapshot A remains unchanged.

Snapshot B records the later evidentiary state.

---

# Failure semantics

Phase 3 tests cover:

- interrupted object writes;
- partial temporary writes;
- corrupt existing objects;
- duplicate object reuse;
- missing artifact records;
- missing event records;
- permission failure during publication;
- HEAD publication failure;
- corrupt current snapshots;
- reopen and extension;
- resolution of previously missing evidence.

A failure must not silently publish partial evidence as the current state.

---

# Filesystem boundary

The initial local store intentionally targets POSIX-style descriptor-relative filesystem support.

Managed directories are opened without following symlinks.

Object publication uses no-overwrite semantics.

Finalization uses a local exclusive lock to serialize HEAD publication.

This lock is an operational store mechanism.

It is not custody evidence and does not establish human identity.

---

# Custody boundary

Phase 3 stores evidence.

It does not yet define custody events.

The following remain Phase 4 work:

~~~text
CAPTURED
STORED
VERIFIED
EXPORTED
TRANSFERRED
SUPERSEDED
~~~

The filesystem backend must not invent custody claims merely because a file exists on disk.

---

# Core rule

~~~text
OBJECTS ARE IMMUTABLE.
FINAL SNAPSHOTS MUST VERIFY.
HEAD MOVES ONLY AFTER VERIFICATION.
PARTIAL WORK IS NEVER AUTHORITATIVE.
~~~
