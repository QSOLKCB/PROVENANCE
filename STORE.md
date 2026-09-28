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

The directory name, HEAD identity, and manifest identity must agree. An internally valid bundle stored beneath the wrong snapshot identity is rejected.

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

Snapshot members are copied into independent inodes rather than hard-linked to the mutable object pool or other snapshots. Editing one exported snapshot therefore cannot rewrite the object pool or another historical snapshot through inode aliasing.

Before publication through HEAD, the snapshot must pass provenance_verify and its verified manifest identity must match the identity being published.

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

Evidence availability is monotonic across finalized snapshots:

~~~text
MISSING → DIGEST_ONLY → CONTENT_RETAINED
~~~

Downgrades are rejected.

A DIGEST_ONLY → CONTENT_RETAINED upgrade must preserve stable artifact metadata such as content identity, byte count, and media type.

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
- resolution of previously missing evidence;
- rejection of evidence-availability downgrades;
- stale concurrent finalizers;
- HEAD/manifest identity substitution;
- snapshot inode isolation;
- relative-root changes after chdir;
- directory-fsync durability failures.

A failure must not silently publish partial evidence as the current state.

---

# Filesystem boundary

The initial local store intentionally targets POSIX-style descriptor-relative filesystem support.

The supplied store root is bound to an absolute path at construction time so later process working-directory changes cannot redirect an existing store instance.

Managed directories are opened without following symlinks.

Object publication uses no-overwrite semantics.

Finalization uses a local exclusive lock to serialize HEAD publication. While holding that lock, the instance compares its loaded HEAD generation with the current on-disk HEAD; stale instances must reopen instead of replacing a newer authoritative snapshot.

Snapshot files and containing directories are fsynced before snapshot publication, and the snapshots parent is fsynced after the final snapshot rename. HEAD is advanced only after that durability sequence and independent verification succeed.

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
