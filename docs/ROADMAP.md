# PROVENANCE Roadmap — v0.1

## Status

```text
PROJECT=PROVENANCE
STATE=BOOTSTRAP
ARCHITECTURE=MODULAR_MONOREPO
PRIMARY_GOAL=FRAMEWORK_NEUTRAL_CHAIN_OF_CUSTODY
```

This roadmap defines the intended development sequence for `QSOLKCB/PROVENANCE`.

The ordering is deliberate.

PROVENANCE must establish the evidence contract before building integrations around it.

The primary rule is:

```text
EVIDENCE SEMANTICS
    ↓
INVARIANTS
    ↓
REFERENCE IMPLEMENTATION
    ↓
INDEPENDENT VERIFICATION
    ↓
REAL OBSERVATION
    ↓
INTERFACES
    ↓
PRESENTATION
    ↓
SCALE
```

Do not reverse this order merely to obtain a more impressive demo.

---

# Roadmap Principle

Every phase must preserve:

```text
MINIMUM_OVERHEAD
subject to
ZERO_UNDECLARED_LOSS_OF_EVIDENTIARY_ACCURACY
```

Performance improvements are valid only when the evidence contract remains unchanged or the change is explicitly versioned.

## Portability Objective

The local reference path is POSIX-first and terminal-native.

Prefer:

```text
POSIX-style files and directories
POSIX advisory record locking
integer time arithmetic
argv-based subprocess execution
UTF-8 text protocols
loopback HTTP
terminal keyboard operation
```

Avoid making these mandatory:

```text
Bash
systemd
GNU-specific commands
Node.js
desktop GUI frameworks
network connectivity
vendor-specific authentication
```

Optional host tools such as chronyc or ntpdate may enrich evidence, but absence of those tools must not invalidate the core local workflow.

---

# Phase 0 — Constitutional Foundation

## Goal

Define what PROVENANCE is before implementing it.

## Status

```text
SUBSTANTIALLY COMPLETE
```

## Deliverables

- `README.md`
- `README4AIs.md`
- `AGENTS.md`
- `docs/INVARIANTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DONORS.md`
- `docs/LINEAGE.md`
- `docs/ROADMAP.md`

## Exit Gate

The repository must clearly define:

```text
what PROVENANCE records
what PROVENANCE does not control
what counts as evidence
how uncertainty is represented
how modules are separated
which invariants cannot silently change
```

---

# Phase 1 — Canonical Evidence Core

## Status

```text
COMPLETE
```

## Goal

Implement the smallest useful `provenance-core`.

No adapters.

No MCP.

No UI.

No database.

No signatures.

## Initial Scope

Implement:

```text
canonical structured bytes
artifact identity
event identity
evidence classification
relationships
manifest core/envelope
basic failure representation
```

## Required Evidence Classes

```text
OBSERVED
DECLARED
DERIVED
```

## Initial Cryptographic Identity

Start with:

```text
SHA-256
```

with explicit algorithm-qualified identifiers:

```text
sha256:<digest>
```

## Canonicalization Requirements

The first canonical format must define:

```text
UTF-8
object-key ordering
compact separators
finite numeric values only
duplicate-key rejection
newline policy
self-hash exclusion
schema version
canonicalization version
```

Raw artifacts must remain raw.

Canonicalization applies to PROVENANCE records, not source evidence bytes.

## Content Identity and Domain Separation

Raw artifact bytes use ordinary algorithm-qualified content identity:

```text
sha256:<SHA-256 of the exact artifact bytes>
```

This is intentionally interoperable with ordinary forensic and cryptographic tooling.

Structured PROVENANCE records use explicit semantic domains:

```text
PROVENANCE/ARTIFACT-RECORD/v1
PROVENANCE/EVENT/v1
PROVENANCE/MANIFEST/v1
```

The structured artifact-record identity binds metadata such as media type, byte count, and retention state without changing the ordinary SHA-256 identity of the underlying raw artifact bytes. Manifests bind artifact-record identity and retention state, including explicit known-missing entries.

## Exit Gate

Given the same valid structured evidence:

```text
same input
→ same canonical bytes
→ same identity
```

must hold exactly.

---

# Phase 2 — Independent Verifier

## Status

```text
COMPLETE
```

## Goal

Create `provenance-verify`.

The verifier must consume finalized evidence without requiring the original monitored system.

## Implement

Verification for:

```text
schema
canonical representation
artifact byte counts
artifact hashes
event hashes
manifest membership
self-hash exclusion
bundle closure
relationship references
```

## Required Test Classes

### Positive fixtures

```text
valid artifact
valid event
valid manifest
valid closed bundle
```

### Negative fixtures

```text
changed artifact byte
changed event field
wrong byte count
missing artifact
extra undeclared artifact
duplicate manifest entry
malformed digest
duplicate JSON key
noncanonical JSON
unsafe relative path
self-hash defect
```

## Core Rule

```text
RECOMPUTE
NOT TRUST
```

## Exit Gate

A valid fixture must pass.

Changing one covered byte must fail verification.

---

# Phase 3 — Local Evidence Store

## Status

```text
COMPLETE
```

## Goal

Implement the first `provenance-store`.

Keep it boring.

## Preferred Initial Backend

```text
local filesystem
+
content-addressed artifacts
```

A database is not required.

## Responsibilities

Persist the Phase 3 evidence objects:

```text
artifact content
artifact records
events
manifests / verified snapshots
```

Custody records and custody semantics begin in Phase 4. The Phase 3 filesystem backend must not manufacture custody claims from storage activity alone.

Derived indexes may be added only when needed.

## Deduplication

Exact artifact identity may allow:

```text
store once
reference many times
```

Deduplication must use strong content identity.

Never filename identity.

## Required Failure Cases

Test:

```text
interrupted write
partial artifact
missing object
hash mismatch
duplicate object
read-only failure
permission failure
```

Partial writes must not become finalized evidence.

## Exit Gate

Evidence can be:

```text
recorded
closed
reopened
verified
```

without requiring external services.

---

# Phase 4 — Minimal Custody Chain

## Status

```text
COMPLETE
```

## Goal

Move from artifact integrity to actual chain of custody.

## Implement

Minimal custody events:

```text
CAPTURED
STORED
VERIFIED
EXPORTED
TRANSFERRED
SUPERSEDED
```

## Requirements

Custody must be:

```text
append-only
identity-bound
time-attributed
actor/source-attributed where supported
```

Unknown handlers remain unknown.

The Phase 4 reference implementation uses a domain-separated custody identity, an independent custody-chain verifier, and an append-only local custody ledger whose current tips are derived from immutable records instead of trusted mutable HEAD files.

Clock observations are explicit evidence:

```text
LOCAL
NETWORK
AUTHENTICATED_NETWORK
SIGNED_ATTESTATION
```

The reference clock observer prefers existing host chrony state and otherwise falls back to the local system clock. It does not automatically initiate network time queries. An explicit operator diagnostic may invoke ntpdate in query-only mode.

Custody time arithmetic uses integers only. System time and optional diagnostic offsets are represented as integer nanoseconds; RFC3339/base-60 formatting is presentation only.

Chain order is determined by previous_custody, not wall-clock ordering.

The Phase 3 store and Phase 4 custody ledger use POSIX advisory record locks rather than flock-specific locking.

## Important Boundary

Custody history must never claim:

```text
legal identity
physical possession
human intent
```

unless separate evidence supports those claims.

## Exit Gate

An artifact can move through multiple custody events while preserving:

```text
original identity
historical custody
correction history
```

## What Comes Next

After Phase 4 review/merge, implementation proceeds in this order:

```text
Phase 5  Ollama reference adapter
    ↓
Phase 6  real Ollama GitHub Actions smoke test
    ↓
Phase 7  MCP stdio interface
    ↓
Phase 8  Rust terminal CLI/TUI
    ↓
Phase 9  localhost read-only HTTP viewer
    ↓
Phase 10 generic/provider adapters
```

Phase 5 should exercise the existing contracts rather than invent new ones:

```text
Ollama request
→ observed request artifact
→ Ollama response
→ observed response artifact
→ event relationship
→ store
→ custody
→ independent verification
```

The first Ollama adapter remains local and authentication-free. Provider authentication and OpenAI-compatible remote endpoints belong to later adapter/TUI work, behind provider-neutral interfaces.

---

# Phase 5 — Ollama Reference Adapter

## Status

```text
IMPLEMENTED
```

## Goal

Observe a real AI system.

Ollama is the first reference adapter because it provides a local, reproducible integration target.

## Module

```text
provenance-adapters/ollama
```

## Capture

At minimum:

```text
request
response
declared model identifier
adapter identifier/version
request/response relationship
capture times
observation boundary
```

## Classification Example

```text
request bytes received by adapter
    → OBSERVED

response bytes received from Ollama
    → OBSERVED

model identifier reported by Ollama
    → DECLARED

SHA-256 of response
    → DERIVED
```

## Explicit Non-Goals

Do not claim observation of:

```text
hidden model state
chain-of-thought
provider-internal computation
actual GPU kernel execution
true model provenance beyond exposed metadata
```

## Reference implementation

The Phase 5 adapter is local-only and stdlib-only.

It uses the native non-streaming Ollama `/api/generate` endpoint and retains the exact request and response body bytes.

It records:

```text
OBSERVED request event
OBSERVED response event
DECLARED model identifier event
CAPTURED / STORED / VERIFIED custody
```

The model identifier used for the declaration is the value returned by Ollama, not an assumption that the request alias was honored exactly.

See `OLLAMA.md`.

## Exit Gate

A real local inference can produce:

```text
request artifact
response artifact
event chain
manifest
verified bundle
```

---

# Phase 6 — GitHub Actions Ollama Smoke Test

## Status

```text
IMPLEMENTED
```

## Goal

Prove the architecture against a real model inside CI.

## Test Philosophy

The model output itself is **not** the golden fixture.

Do not require:

```text
prompt X
→ exact response Y
```

Instead assert:

```text
request captured
response captured
request digest valid
response digest valid
event relationship valid
manifest valid
verification passes
```

Then:

```text
tamper with retained evidence
→ verification fails
```

## Model Choice

Use the smallest practical Ollama model capable of completing the integration test.

Model intelligence is irrelevant.

The test validates PROVENANCE.

## CI Constraints

The Ollama workflow is separate from fast core CI.

Routine core changes do not automatically require a model download.

The initial matrix uses two independent GitHub-hosted runners:

```text
qwen2.5:0.5b
qwen2:0.5b
```

Each runner starts its own local Ollama server. Model weights are not cached in the initial trust lane.

## Exit Gate

A clean GitHub Actions runner can:

```text
install/start Ollama
pull test model
perform inference
record evidence
verify evidence
detect tampering
```

---

# Phase 7 — MCP Interface

## Status

```text
IMPLEMENTED
```

## Goal

Expose PROVENANCE through MCP without making MCP part of the core evidence contract.

## Module

```text
provenance-mcp
```

## Initial Transport

```text
stdio
```

Keep remote transport for later.

## Initial Tools

Conceptually:

```text
provenance.record
provenance.inspect
provenance.verify
provenance.finalize
provenance.export
```

## Initial Resources

Conceptually:

```text
provenance://event/<id>
provenance://artifact/<identity>
provenance://manifest/<id>
provenance://custody/<id>
```

## Important Classification Rule

Information supplied through:

```text
provenance.record(...)
```

is not automatically OBSERVED.

Caller-supplied assertions remain:

```text
DECLARED
```

unless independently observed.

## Self-Demonstration Test

A client should be able to:

```text
perform action
↓
record through MCP
↓
request provenance
↓
verify returned evidence
```

## Reference implementation

The Phase 7 reference server is dependency-free and stdio-only.

It supports the current `2026-07-28` stateless MCP era and the `2025-11-25` initialize-handshake era without making either lifecycle part of the evidence core.

`provenance.record` stores caller assertions as DECLARED evidence and emits a separate unique OBSERVED MCP receipt so repeated identical calls cannot collapse into one occurrence.

The interface delegates finalization and verification to the existing store/verifier modules, exposes evidence through identity-derived `provenance://` resources, and includes a narrow snapshot-copy export without claiming completion of the later Phase 11 forensic-package contract.

See `MCP.md`.

## Exit Gate

An executed stdio client/server integration can:

```text
record through MCP
preserve caller data as DECLARED
prove each call occurrence separately
finalize through the existing store
read identity-addressed evidence resources
independently verify bundle + custody
export and independently verify a snapshot copy
```

MCP can be removed entirely without invalidating existing evidence.

---

# Phase 8 — CLI

## Status

```text
IMPLEMENTED
```

## Goal

Provide a minimal human/operator interface without requiring MCP or a UI.

## Module

```text
provenance-cli
```

## Initial Commands

Possible surface:

```text
provenance record
provenance inspect
provenance verify
provenance finalize
provenance export
```

The preferred interactive operator surface is a small Rust TUI inspired by the efficient Codex CLI interaction model:

```text
type /
→ command palette
→ filter/select action
→ keyboard-first execution
```

The TUI should remain a client of existing PROVENANCE contracts rather than a second implementation of them.

Authentication should be provider-neutral. Later auth adapters may support:

```text
none
API key
OAuth device authorization
OAuth loopback/browser authorization
provider-specific delegated login
```

Browser-based sign-in should open an explicit authorization URL and receive only the token/code material needed by that provider. Credentials must not become ordinary custody/evidence payloads.

OpenAI-compatible HTTP APIs are an important interoperability target, but compatibility at the transport/API surface must not make OpenAI-specific semantics part of provenance-core.

## Reference implementation

The Phase 8 reference surface uses a zero-dependency Rust binary named `provenance` for terminal interaction and a small Python backend that composes the existing core, store, custody, and independent verifier modules.

Implemented commands:

```text
provenance record
provenance inspect
provenance verify
provenance finalize
provenance export
provenance tui
```

Operator-supplied content is recorded as DECLARED. Each successful record invocation also creates a unique OBSERVED CLI receipt so occurrence evidence does not collapse when declaration content deduplicates.

The terminal mode is deliberately line-oriented for the first implementation:

```text
/
→ command palette
/ver
→ filtered palette
/verify
→ keyboard-first execution
```

No external Rust crates, network service, MCP transport, or provider authentication are required.

For cross-interface continuity, Phase 8 shares Phase 7's hardened operational working-state lock/journal. The historical MCP-named journal is operational metadata rather than evidence semantics; CLI and MCP therefore serialize into one recoverable pending working set and either interface can finalize the union.

See `CLI.md`.

## Rule

The CLI wraps existing core/verifier behavior.

It must not reimplement evidence semantics.

## Exit Gate

An executed terminal integration can:

```text
record operator-supplied evidence
preserve the declaration/observation boundary
inspect working and finalized state
finalize through the existing store
independently verify bundle + custody
export and independently verify a snapshot copy
share pending working state with MCP
drive the slash-command palette from a terminal
```

A user can create and independently verify a basic evidence bundle from a terminal.

---

# Phase 9 — Read-Only UI

## Status

```text
IMPLEMENTED
```

## Goal

Make provenance understandable to humans.

The UI remains a viewer.

## Module

```text
provenance-ui
```

## Initial Technology Direction

Keep the first viewer deliberately simple:

```text
small local HTTP server
pure HTML
pure CSS
minimal vanilla JavaScript
no frontend framework
```

Default network binding:

```text
127.0.0.1
```

LAN/public binding must require explicit operator action. The UI is read-only and has no evidentiary authority.

Avoid inetd-style miscellaneous service exposure; the viewer needs one narrow HTTP surface only.

## Primary Views

### Evidence graph

Show relationships between:

```text
actors
events
artifacts
tools
outputs
custody
human actions
```

### Timeline

Show:

```text
observed sequence
timestamps
partial ordering
collection gaps
```

### Artifact inspector

Display:

```text
identity
media type
byte count
retention state
source
custody
verification
```

### Verification panel

Never show a single generic:

```text
TRUSTED
```

Prefer:

```text
integrity = VERIFIED
custody = PARTIAL
signature = NOT_PRESENT
replay = NOT_ATTEMPTED
```

### Evidence gaps

Make missing observation visually obvious.

## Reference implementation

The Phase 9 reference viewer is a dependency-free Python localhost service with pure HTML, pure CSS, and minimal vanilla JavaScript.

It consumes only finalized immutable store snapshots and immutable custody records. It deliberately avoids constructing the mutable store and custody-ledger reference objects merely to display evidence.

The viewer independently runs:

```text
verify_bundle()
verify_custody_records()
```

and presents separate verification dimensions rather than a generic trust score.

The HTTP surface accepts only:

```text
GET
HEAD
```

Mutation methods return HTTP 405.

Default binding is `127.0.0.1`. Non-loopback binding requires the explicit `--allow-non-loopback` operator flag.

Phase 9 tests fingerprint the evidence roots before and after direct projection and HTTP requests so accidental UI mutation is detectable.

See `UI.md`.

## Exit Gate

Deleting the UI changes no evidence identity and no verification outcome.

---

# Phase 10 — Generic Adapter Interface

## Status

```text
IMPLEMENTED
```

## Goal

Make adapters easy to build without letting them redefine the core.

## Define

A minimal adapter contract for:

```text
observation source
input capture
output capture
declared metadata
observation boundary
failure reporting
extensions
```

## Initial Additional Adapters

Potential targets:

```text
OpenAI
Anthropic / Claude
Google / Gemini
xAI / Grok
llama.cpp
generic HTTP
CLI/process
filesystem
```

Adapters should be developed only when a real integration or test case exists.

Do not create empty provider modules for completeness.

## Reference implementation

Phase 10 defines a provider-neutral `AdapterContract`, shared capture/translation records, and one persistence path that composes the existing store, custody, and verifier modules.

The first two additional executable adapters are deliberately structurally different:

```text
GenericHTTPAdapter
    → ordinary HTTP/HTTPS request-response boundary

ProcessAdapter
    → local argv/stdin/stdout/stderr process boundary
```

Both emit ordinary core `ArtifactRecord` and `EventEnvelope` values. Provider- or transport-specific metadata remains a retained DECLARED artifact under an explicit extension namespace rather than changing `provenance-core`.

Failure observations remain persistable and use `COLLECTION_FAILED` instead of disappearing when the underlying operation fails.

HTTP credential-bearing header values and inherited process environments are runtime-only and are not retained as ordinary evidence payloads.

See `ADAPTERS.md`.

## Exit Gate

At least two structurally different providers/systems can emit evidence into the same core schema without provider-specific changes to core semantics.

The Phase 10 executed test uses a local HTTP server and a local child process, persists both observations through the same store/custody path, and independently verifies the resulting evidence.

---

# Phase 11 — Exportable Evidence Bundles

## Status

```text
IMPLEMENTED
```

## Goal

Create portable forensic packages.

## Bundle Requirements

A finalized bundle should be able to include:

```text
manifest
events
artifact content or explicit digest-only references
custody records
schema/version information
verification metadata
declared gaps
```

## Closed Bundle Mode

A finalized closed bundle must reject:

```text
missing declared artifacts
undeclared extra artifacts
hash mismatches
unsafe paths
silent substitutions
```

## Open Collection Mode

The architecture may also support evidence that is still being collected.

Do not confuse:

```text
OPEN
```

with:

```text
FINALIZED
```

## Reference implementation

Phase 11 adds a separate `provenance.forensic-package.v1` archival envelope around an unchanged Phase 2 `provenance.bundle.v1` snapshot.

The package contains:

```text
package.json
evidence/           # unchanged Phase 2 bundle
custody/sha256/    # stable immutable custody snapshot
schemas.json
verification.json
gaps.json
```

Every package member is bound by path, SHA-256 content identity, and byte count. `package.json` has its own domain-separated identity and self-hash exclusion.

The producer stages the package, independently verifies it, atomically publishes it, and verifies the published destination again.

The independent package verifier recomputes embedded evidence verification, custody verification, schema metadata, and declared gaps; it rejects missing/extra/unsafe/substituted members and undeclared directories.

A finalized package explicitly separates:

```text
package_state = FINALIZED
evidence_scope = open | closed
```

so an archived open collection is never silently upgraded to closed.

The Rust CLI exposes `provenance package`; MCP exposes `provenance.package`. The historical Phase 7/8 `export` snapshot-copy contract remains unchanged.

See `PACKAGE.md`.

## Exit Gate

A bundle created on one machine can be moved to another and independently verified.

The executed Phase 11 test copies the finalized package to a separate simulated machine directory, removes the original package, and verifies the moved copy with the same package identity and evidence manifest identity.

---

# Phase 12 — Signatures and External Anchoring

## Status

```text
IMPLEMENTED
```

## Goal

Add optional authenticity mechanisms.

## Potential Mechanisms

```text
digital signatures
signed releases
Git commits
transparency logs
timestamp services
DOI records
external append-only systems
```

Blockchain may be supported as an optional anchor.

It is not required.

## Boundary

A valid signature proves only what the signature mechanism establishes.

It does not automatically prove:

```text
truth
legal identity
intent
correctness
physical location
```

## Reference implementation

Phase 12 uses detached trust records so finalized Phase 11 packages remain byte-identical.

Reference signature mechanism:

```text
OpenSSH SSHSIG
algorithm = ssh-ed25519
namespace = provenance
signed bytes = exact canonical package.json bytes
```

Reference external anchor mechanism:

```text
Git commit
→ exact canonical PROVENANCE anchor payload
→ exact commit OID + repository-relative path
→ verification against a supplied Git object database
```

The verifier reports integrity, signature, and external-anchor assurance independently. Signature and anchor verification may remain valid even when current package-member integrity has failed, because they bind the signed/anchored package declaration rather than silently repairing damaged evidence.

Signing and Git anchor records are optional detached sidecars. No private signing key enters the evidence package or MCP interface, and Phase 12 performs no automatic network calls.

See `TRUST.md`.

## Exit Gate

The verifier can distinguish:

```text
integrity verification
signature verification
external-anchor verification
```

as separate dimensions.

The executed Phase 12 CI lane generates a real Ed25519 key, signs and verifies a real Phase 11 package, creates and verifies a real Git commit anchor, and proves that integrity/signature/anchor outcomes remain separate.

---

# Phase 13 — Performance Hardening

## Status

```text
IMPLEMENTED
```

## Goal

Reduce overhead without changing evidence semantics.

Use patterns from `QSOLKCB/OPT`.

## Candidate Techniques

```text
streaming hashing
content deduplication
bounded batching
proven-equivalent caching
signature-bound incremental verification
bounded parallel verification
verified dependency reuse
```

## Required Rule

For every optimized path:

```text
OPTIMIZED_RESULT
==
REFERENCE_RESULT
```

where exact semantics are claimed.

## Benchmark Requirements

Record:

```text
runner
OS
CPU
toolchain
workload
repetitions
variance where relevant
```

Do not promote environment-specific numbers into universal defaults.

## Reference implementation

Phase 13 applies bounded deterministic parallel execution to independent verifier work while retaining serial reference entry points.

```text
bundle artifact/content checks   → bounded parallel
bundle event checks              → bounded parallel
package member hashing/counting  → bounded parallel
semantic reduction/error order   → deterministic input order
```

Worker policy:

```text
hard cap = 4 workers
effective default = min(4, logical CPU count)
2 queued/in-flight batches per worker
```

The conformance suite compares complete optimized/reference report objects on valid and multiply corrupted evidence and directly witnesses overlapping worker execution without exceeding the cap.

The CI benchmark refuses to report performance unless exact report equivalence holds.

Recorded environment-scoped observation on GitHub Actions (AMD EPYC 7763, 4 logical CPUs, CPython 3.12.3, 32 × 1 MiB retained artifacts + 32 events, 5 repetitions):

```text
bundle verifier:
  serial median    43.851859 ms
  optimized median 26.336839 ms
  observed gain    39.941%

forensic-package verifier:
  serial median    92.626357 ms
  optimized median 61.895547 ms
  observed gain    33.177%
```

These measurements are environment-specific observations and must be re-measured before transfer to another environment.

See `PERFORMANCE.md`.

## Exit Gate

Measured overhead improves without weakening:

```text
invariants
test coverage
verification strength
failure visibility
```

The Phase 13 reference benchmark measured lower median runtime for both bundle and forensic-package verification while the optimized and serial reports remained exactly equal.

---

# Phase 14 — Privacy and Selective Disclosure

## Status

```text
IMPLEMENTED
```

## Goal

Allow deployments to preserve integrity without exposing everything.

## Potential Features

```text
digest-only artifacts
encrypted artifacts
redacted derivatives
access-controlled content
selective export
retention policies
```

## Rule

A redacted artifact is a new derivative.

It must retain lineage to its source where permitted.

## Reference implementation

Phase 14 adds deterministic byte-range redaction and a finalized selective-disclosure package.

The producer starts from a verified Phase 11 forensic package containing a retained source artifact and creates:

```text
source artifact digest + exact original ArtifactRecord witness
redaction specification
new retained derivative artifact
DERIVED source → derivative event
finalized selective-disclosure envelope
```

The original source bytes are intentionally omitted from the disclosure. The disclosure explicitly separates the source artifact's original retention metadata from the disclosure's `DIGEST_ONLY` treatment.

Standalone verification proves disclosure integrity and declared lineage without claiming the hidden transformation was recomputed. Supplying the original source package additionally lets the verifier bind the source package and reapply the redaction transform byte-for-byte.

Redaction requires retained source content and rejects digest-only sources, overlapping ranges, no-op transforms, tampering, and attempts to relabel the derivative as OBSERVED/original evidence.

The source package is verified/read through one held directory descriptor before staged disclosure publication.

CLI commands:

```text
provenance redact-disclosure
provenance verify-disclosure
```

See `PRIVACY.md`.

## Exit Gate

An investigator can verify that a disclosed derivative corresponds to a declared source relationship without the system falsely claiming the derivative is the original artifact.

The Phase 14 CI suite proves this both with source bytes withheld and, when the original package is supplied, by exact redaction-transform recomputation.

---

# Phase 15 — Distributed Custody

## Status

```text
IMPLEMENTED
```

## Goal

Support evidence spanning multiple services or organizations.

Only pursue when real deployments require it.

## Problems to Solve

```text
distributed ordering
multiple clocks
transfer acknowledgements
remote artifact identity
partial custody
network partitions
duplicate delivery
cross-system signatures
```

## Rule

Do not manufacture global ordering.

Preserve partial ordering when that is all the evidence supports.

## Reference implementation

Phase 15 implements an offline, signed, partially ordered transfer protocol over finalized Phase 11 forensic packages.

Sender side:

```text
verified forensic package
→ signed transfer offer
→ finalized transfer bundle
```

Receiver side:

```text
verify transfer
→ preserve package identity
→ append receiver-local CAPTURED/STORED/VERIFIED custody
→ sign receiver receipt
```

Sender and receiver clock observations remain separate. The verifier records only evidence-backed causal edges and reports `ordering = PARTIAL`; wall-clock comparison is never used to manufacture global order.

The transfer bundle is self-contained and requires no network service, so delayed/offline/store-and-forward handoff remains verifiable after a partition.

Duplicate delivery is idempotent for a completed receipt and does not append duplicate receiver custody. If the live receiver custody ledger no longer contains the acknowledgements named by the receipt, duplicate delivery fails rather than silently restoring continuity.

Crash recovery accepts only a valid local acknowledgement prefix:

```text
CAPTURED
CAPTURED → STORED
CAPTURED → STORED → VERIFIED
```

Cross-system authenticity uses role-separated Ed25519 SSHSIG records under the `provenance-transfer` namespace. Key possession does not by itself establish organization/legal identity.

CLI commands:

```text
provenance transfer-create
provenance transfer-receive
provenance verify-transfer
provenance verify-receipt
```

See `TRANSFER.md`.

## Exit Gate

Evidence can cross independently operated systems without silently losing origin, identity, custody, or uncertainty.

The Phase 15 CI suite proves this across separate sender/receiver directories, including offline copied handoff, intentionally reversed sender/receiver wall clocks, preserved package identity, receiver-local custody, signed acknowledgements, duplicate delivery, crash-prefix recovery, wrong-recipient rejection, and tamper detection.

---

# Phase 16 — Release-Grade Trust Lane

## Status

```text
IMPLEMENTED
```

## Goal

Create a high-assurance release process distinct from routine fast CI.

Formal verification does **not** run as a normal development dependency in this phase. The implementation remains free to evolve until the release candidate is actually frozen.

## Routine Lane

May use:

```text
verified caches
incremental test selection
bounded parallelism
optimized fixtures
```

where invariants permit.

## Release Lane

Prefer:

```text
fresh checkout
pinned toolchain
pinned dependencies
full invariant suite
full tamper suite
canonical fixture verification
real Ollama integration
MCP integration
CLI integration
read-only UI integration
bundle export
independent verification
```

## Reference implementation

Phase 16 adds `.github/workflows/full.yml` as a separate high-assurance lane.

It uses fresh GitHub-hosted checkouts, pinned Python/Rust/Ollama toolchains and pinned action commits, runs the complete Python invariant/tamper/integration corpus, builds and tests the Rust CLI, repeats the canonical core/verifier checks under a second Python hash seed, requires a clean source tree after validation, and executes the existing real Ollama smoke path against both small reference models.

Routine module CI remains path-filtered. The full lane runs automatically when its own release contract changes and is otherwise invoked manually against the exact release candidate ref.

The real-model jobs retain their observation directories as short-lived workflow artifacts for inspection. These are CI artifacts, not the final Phase 18 archival bundle.

See `RELEASE.md`.

## Boundary

A green Phase 16 lane means the exact tested candidate passed the release-grade engineering gate.

It does **not** mean:

```text
implementation frozen
formal verification complete
archival final release complete
```

Those are Phase 17 and Phase 18 responsibilities.

## Exit Gate

The implementation intended for the archival release passes the complete release-grade trust lane at its exact candidate commit and is ready to be frozen as the formalization target.

---

# Phase 17 — Immutable Candidate Freeze

## Status

```text
COMPLETE
```

Frozen implementation baseline:

```text
tag:    v1.0.0
commit: 0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742
```

The GitHub release is immutable. Later documentation, proof sources, archival metadata, and post-release maintenance on `main` do not redefine this target.

## Goal

Create the **penultimate project tag** that freezes the final implementation before formal verification begins.

This tag is the immutable target that Lean proofs and archival claims refer to.

## Required Sequence

```text
all implementation phases complete
    ↓
full release-grade trust lane green
    ↓
cut penultimate tag
    ↓
record exact commit SHA
    ↓
freeze implementation and evidence contracts
```

## Freeze Rule

After the penultimate tag:

```text
NO implementation change
NO schema semantic change
NO verifier semantic change
NO evidence-contract change
```

is permitted without invalidating the freeze and starting Phase 17 again with a new penultimate tag.

The final release may add formal proof sources, archival metadata, and release documentation, but the frozen implementation being proved must remain byte-for-byte identifiable from the penultimate tag.

## Why This Comes Late

Formalizing a moving implementation creates drag without increasing final assurance.

The project therefore waits until ordinary engineering, integration, UI, privacy, distribution, performance, and release hardening are complete before committing the stable target to Lean.

## Exit Gate

An immutable penultimate tag exists whose exact commit SHA is the declared target of final formal verification.

---

# Phase 18 — Formal Verification and Archival Final Release

## Status

```text
IN PROGRESS
FORMAL PROOF SET IMPLEMENTED
FINAL ARCHIVAL TAG / ZENODO PUBLICATION PENDING
```

Current archival identifier:

```text
DOI: 10.5281/zenodo.23043860
```

Reference formal toolchain:

```text
Lean 4.34.1
```

Implemented formal claims:

```text
FV-01 self-hash exclusion
FV-02 append-only history extension
FV-03 classification non-promotion
FV-04 presentation non-interference
```

The proof set is intentionally narrower than whole-program verification and is bridged explicitly to named frozen runtime code/tests in `FORMAL_VERIFICATION.md`.

## Goal

Formally verify stable, high-value invariants against the frozen Phase 17 target, then publish the final immutable tag and Zenodo archival record.

## Candidate Formal Targets

Potential targets include:

```text
self-hash exclusion
append-only correction semantics
classification preservation
manifest sealing
verification purity
non-authority of presentation
event/artifact identity separation
read-only UI non-interference
```

Only stable claims that materially improve confidence belong in the final proof set.

## Lean Boundary

Lean proofs must explicitly identify:

```text
frozen target tag
frozen target commit SHA
modeled invariant
runtime invariant/test it corresponds to
Lean version/toolchain
proof source identity
```

Formal verification proves the encoded model.

It does not automatically prove:

```text
runtime implementation equivalence beyond the stated bridge
source data truth
adapter honesty
external system behavior
legal or factual truth
```

## Final Archival Sequence

The intended final sequence is:

```text
penultimate immutable implementation tag
    ↓
Lean formalization against that exact frozen target
    ↓
cold/reconstructed formal verification pass
    ↓
prepare archival bundle and reserve Zenodo DOI
    ↓
final tag containing proof/archive material
while frozen implementation remains unchanged
    ↓
publish Zenodo record linked to the final tag
and the frozen target commit
```

The Zenodo record should retain enough material to identify and reconstruct:

```text
the frozen implementation target
the final formal proof sources
the proof toolchain
the executed verification evidence
the final repository tag
the DOI/version metadata
```

## Restart Rule

If a formal proof exposes an implementation defect that requires changing the frozen implementation:

```text
DO NOT patch under the freeze.
Return to Phase 16.
Fix and re-run the release lane.
Cut a new penultimate tag.
Restart formal verification.
```

## Reference implementation

Phase 18 adds a self-contained Lean project under `formal/`, pinned to `leanprover/lean4:v4.34.1`.

The dedicated `formal.yml` workflow:

```text
verifies v1.0.0 → frozen SHA
checksum-verifies the official Lean 4.34.1 release bundle
builds the Lean proof set
runs bundled leanchecker
rejects proof placeholders
emits a machine-readable success attestation
retains Lean/Lake versions and build/checker logs
generates a proof-source evidence manifest
archives the frozen v1.0.0 source
archives the formal proof sources
computes SHA-256 archive checksums
retains the archive as a workflow artifact
```

The machine-readable target declaration is `formal/TARGET.json`.

The archival evidence generator is `scripts/phase18_manifest.py`.

See `FORMAL_VERIFICATION.md` and `ARCHIVAL_RELEASE.md`.

## Exit Gate

The project has:

```text
an immutable penultimate implementation tag
a successful Lean verification against that exact target
a final immutable release tag
a Zenodo archival record binding the release and proof evidence
```

The first two conditions are executable within this repository. The final two remain pending until the Phase 18 archival tag is cut and DOI `10.5281/zenodo.23043860` is published with the generated archive material.

The final release claim must remain narrower than the exact invariants actually formalized and executed.

---

# CI Roadmap

CI should evolve with the modules.

Target structure:

```text
core.yml
verify.yml
store.yml
ollama.yml
mcp.yml
cli.yml
ui.yml
full.yml
```

Do not create workflows before the corresponding module exists.

---

# CI Speed Rule

Fast CI should come from:

```text
module isolation
path-aware execution
small invariant-complete fixtures
proven reuse
parallel independent work
```

Never from:

```text
ignored failures
weakened assertions
removed invariants
unreported skips
```

A validation failure must remain a validation failure.

---

# Versioning Strategy

The project should version contracts independently where useful.

Potential future versions:

```text
event schema
artifact schema
manifest schema
custody schema
canonicalization
MCP interface
adapter interface
```

Do not force every internal change to create a new universal evidence schema version.

Do not silently change stable evidence meaning within an existing version.

---

# Module Extraction Rule

Remain a monorepo until splitting creates a demonstrated benefit.

A module may become its own package or repository later when:

```text
independent release cadence exists
external consumers need it independently
dependency isolation materially improves
maintenance boundaries become real
```

Do not split merely because the architecture diagram contains separate boxes.

---

# Explicit Non-Goals

The roadmap does not include plans to turn PROVENANCE into:

```text
AI alignment middleware
content moderation
policy enforcement
decision approval
legal judgement
medical judgement
truth scoring
automatic liability assignment
mandatory blockchain infrastructure
```

Those remain outside the project contract.

---

# Release Milestone Candidates

Potential early milestones:

## v0.1 — Evidence Core

```text
canonicalization
artifact identity
event model
manifest
verifier
tamper fixtures
```

## v0.2 — Local Observation

```text
local store
custody basics
Ollama adapter
GitHub Actions smoke test
```

## v0.3 — Interoperability

```text
MCP
CLI
portable evidence bundles
```

## v0.4 — Human Inspection

```text
read-only UI
evidence graph
timeline
gap visibility
```

## v0.5 — Multi-Provider

```text
generic adapter contract
additional AI/system adapters
```

These version numbers are planning labels only until releases are actually created.

---

# Roadmap Advancement Rule

A phase advances only when its core claim can be demonstrated.

Examples:

```text
"tamper detection"
requires an executed tamper fixture

"Ollama support"
requires a real Ollama observation

"MCP support"
requires an actual MCP client/server interaction

"independent verification"
requires verification without the original monitored system

"low overhead"
requires measurement
```

Documentation alone does not satisfy executable milestones.

---

# Roadmap Restraint Rule

Before adding a new phase, module, service, dependency, or abstraction, ask:

```text
Which PROVENANCE invariant requires this?
```

If the answer is:

```text
none
```

then the default action is:

```text
DO_NOT_ADD_IT
```

---

# Long-Term Destination

The mature system should support:

```text
tiny local programs
AI applications
MCP clients
agent systems
legal AI workflows
medical AI workflows
scientific systems
distributed services
human-in-the-loop decisions
```

using the same fundamental evidence semantics.

A user should be able to choose:

```text
core only
core + verifier
core + local store
core + adapter
core + MCP
core + UI
full deployment
```

without being forced into the entire stack.

---

# Final Roadmap Rule

Build the smallest trustworthy layer.

Prove it.

Then add the next layer.

```text
CORE BEFORE ADAPTERS.
VERIFICATION BEFORE PRESENTATION.
REAL EVIDENCE BEFORE DASHBOARDS.
MODULES BEFORE INFRASTRUCTURE.
MEASUREMENT BEFORE OPTIMIZATION.
```

And throughout:

```text
DO NOT ADD COMPLEXITY
UNLESS THAT COMPLEXITY EARNS
NEW EVIDENTIARY CAPABILITY.
```
