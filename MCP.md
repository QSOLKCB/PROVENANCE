# PROVENANCE MCP Stdio Interface — v1

## Status

~~~text
INTERFACE=provenance-mcp:stdio/v1
TRANSPORT=stdio
REMOTE_TRANSPORT=NOT_IMPLEMENTED
CORE_SCHEMA_CHANGES=NONE
~~~

Phase 7 exposes the existing PROVENANCE core, local store, custody ledger, and verifier through MCP.

MCP is an interface layer. Deleting `provenance_mcp/` does not change any existing evidence identity or verification rule.

---

# Protocol compatibility

The stdio server is dependency-free and supports both current MCP lifecycle eras used by the reference tests:

~~~text
2026-07-28  modern/stateless era
2025-11-25  initialize-handshake era
~~~

Modern requests carry their protocol revision and client capabilities in `params._meta`. The connection is pinned to the era selected by its opening request.

The server emits one JSON-RPC message per UTF-8 line on stdout and writes no ordinary application output to stdout.

Ambiguous/non-JSON framing is rejected before MCP dispatch. Duplicate object keys and non-finite JSON numeric tokens are not silently normalized.

---

# Start the server

~~~bash
python3 -m provenance_mcp \
  --store /path/to/provenance-store \
  --custody /path/to/provenance-custody
~~~

Both roots are explicit. Phase 7 does not start a network listener and does not infer a remote endpoint.

An MCP server is permanently bound to the filesystem identity of the store root it opened at construction. Current-state refreshes happen in-place through that bound store object. If the configured store pathname is renamed/replaced so it resolves to a different directory inode, the server rejects the operation rather than silently switching to the replacement store.

---

# Tools

## provenance.record

Records caller-supplied JSON without upgrading it to observed truth.

Caller content is stored as:

~~~text
provenance.mcp-declaration.v1
evidence_class = DECLARED
~~~

The MCP server separately creates a unique retained receipt:

~~~text
provenance.mcp-receipt.v1
evidence_class = OBSERVED
actor = provenance-mcp:stdio/v1
~~~

This separation matters.

Two byte-identical declarations may share the same declaration identity, but two MCP calls receive different receipt artifacts/events. Therefore:

~~~text
SAME DECLARATION
!=
SAME OCCURRENCE
~~~

A successful record call is also durably represented in the MCP operational working-state journal before the tool returns. The journal contains identities and working membership, not a second evidence schema, and is excluded from finalized evidence identity.

The working-state journal is multi-writer safe. All MCP server processes sharing a store serialize working-state recovery, record publication, journal replacement, and finalization through one POSIX advisory lock in the store root. After acquiring that lock, a server reloads the current store HEAD and replays the complete durable journal before performing its mutation. A writer therefore extends the merged working set instead of replacing it from stale process-local state.

This rule covers both concurrent writes and stale long-lived server instances:

~~~text
SERVER A ACKNOWLEDGES RECORD A
SERVER B ACKNOWLEDGES RECORD B
    ↓
DURABLE JOURNAL = A ∪ B
    ↓
ANY LATER FINALIZER = A ∪ B
~~~

The same lock also serializes shared custody-ledger initialization for concurrently starting MCP servers using the same roots.

After process restart, the server revalidates the journaled artifact records, retained bytes, and event identities against the object pool before reattaching them to the working snapshot. The journal's `pending_verified_artifacts` set must exactly equal the journaled artifact membership; recovery rejects extra, missing, or duplicate pending subjects before any VERIFIED custody can be appended.

If the store HEAD advanced because finalization committed immediately before a crash, restart requires the journaled members to be present in that verified HEAD and completes fresh VERIFIED custody before clearing the journal.

The caller cannot supply an `evidenceClass` override.

## provenance.inspect

Resolves a PROVENANCE identity to its evidence kind/resource, or reports the current working/finalized store summary.

## provenance.finalize

Delegates snapshot creation to `LocalEvidenceStore.finalize()`, requires its independent verification result, then appends VERIFIED custody for Phase 7 artifacts and the manifest.

## provenance.verify

Returns the existing independent bundle-verification report and independent custody-verification report.

The MCP layer does not implement a second verifier.

## provenance.export

Copies the current immutable verified snapshot to a new destination directory, independently verifies the copy, and then appends EXPORTED custody for the manifest.

The destination must not already exist and must be outside the live evidence store, custody ledger, and source snapshot tree. This prevents an export from recursively copying into itself or contaminating the evidence roots it is meant to preserve.

Export publication is descriptor-bound. The destination parent is opened as a non-symlink directory descriptor, ancestry is checked against the protected evidence roots, and the snapshot is copied through that held descriptor rather than by reopening the checked pathname. The parent pathname/identity and protected-root ancestry are checked again before success is reported. A parent rename/symlink substitution during export therefore fails and the descriptor-bound partial copy is removed.

This Phase 7 export is a snapshot-copy interface only. It does not claim to complete the later Phase 11 portable forensic-package contract, which may additionally package custody, schemas, verification metadata, and declared gaps.

---

# Resources

Phase 7 exposes:

~~~text
provenance://event/<identity>
provenance://artifact/<identity>
provenance://manifest/<identity>
provenance://custody/<identity>
~~~

Event, manifest, and custody resources return canonical JSON.

Retained artifact resources return exact bytes through MCP blob content. DIGEST_ONLY artifacts return explicit retention metadata rather than fabricated content.

Artifact reads use the **current working store binding**, not merely the most recently finalized manifest binding. A monotonic DIGEST_ONLY → CONTENT_RETAINED upgrade is therefore visible immediately, before the next finalization.

Resource reads use identity-derived paths and descriptor-safe non-symlink file opens.

Before serving a resource, Phase 7 recomputes the identity bound by the URI:

~~~text
event      -> recompute event identity from canonical core
custody    -> recompute custody identity from canonical core
manifest   -> recompute manifest identity from canonical core
artifact   -> recompute artifact-record identity
retained bytes -> recompute raw SHA-256 content identity
~~~

A canonical object placed under the wrong content-addressed filename is therefore not served as that identity. Resource corruption is reported as an internal evidence/read failure rather than silently relabeling the bytes.

Unknown resource URIs return MCP invalid-params/resource-not-found semantics instead of an internal error.

---

# Evidence classification boundary

The central Phase 7 rule is:

~~~text
CALLER ASSERTION
    -> DECLARED

MCP SERVER RECEIPT OF CALL
    -> OBSERVED
~~~

An MCP client saying:

~~~text
"I called tool X because Y"
~~~

does not make X or Y independently observed facts.

PROVENANCE can observe that the MCP server received that declaration. It cannot silently promote the declaration's truth.

---

# Self-demonstration

The Phase 7 integration test launches the real server as a child process and communicates over stdio.

The executed flow is:

~~~text
server/discover
    ↓
tools/list
    ↓
provenance.record
    ↓
repeat identical provenance.record
    ↓
provenance.inspect
    ↓
provenance.finalize
    ↓
resources/read
    ↓
resources/list
    ↓
provenance.verify
    ↓
provenance.export
    ↓
independent verify_bundle(export)
~~~

The test requires:

~~~text
caller declaration event = DECLARED
MCP receipt event = OBSERVED
identical declarations may deduplicate
identical calls must not collapse
finalized bundle verifies
custody verifies
exported copy independently verifies
legacy initialize era still lists tools
modern era remains connection-pinned
~~~

---

# Non-goals

Phase 7 does not implement:

~~~text
remote MCP transport
HTTP MCP transport
MCP authorization
sampling
elicitation
tasks extension
MCP Apps
provider authentication
generic provider adapters
Rust CLI/TUI
read-only web UI
full Phase 11 forensic-package export
~~~

Those capabilities must earn their place in later roadmap phases.

---

# Core rule

~~~text
MCP IS AN INTERFACE.
CALLER CLAIMS STAY DECLARED.
OCCURRENCES MUST NOT COLLAPSE.
VERIFICATION REMAINS INDEPENDENT.
~~~
