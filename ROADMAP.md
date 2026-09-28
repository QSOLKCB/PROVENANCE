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
- `INVARIANTS.md`
- `ARCHITECTURE.md`
- `DONORS.md`
- `LINEAGE.md`
- `ROADMAP.md`

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

Store:

```text
artifacts
events
manifests
custody records
```

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

---

# Phase 5 — Ollama Reference Adapter

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

The Ollama workflow should be separate from fast core CI.

Routine core changes should not automatically require a model download unless relevant.

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

## Exit Gate

MCP can be removed entirely without invalidating existing evidence.

---

# Phase 8 — CLI

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

## Rule

The CLI wraps existing core/verifier behavior.

It must not reimplement evidence semantics.

## Exit Gate

A user can create and independently verify a basic evidence bundle from a terminal.

---

# Phase 9 — Read-Only UI

## Goal

Make provenance understandable to humans.

The UI remains a viewer.

## Module

```text
provenance-ui
```

## Initial Technology Direction

Prefer:

```text
HTML
CSS
minimal JavaScript
```

unless requirements justify more.

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

## Exit Gate

Deleting the UI changes no evidence identity and no verification outcome.

---

# Phase 10 — Generic Adapter Interface

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

## Exit Gate

At least two structurally different providers/systems can emit evidence into the same core schema without provider-specific changes to core semantics.

---

# Phase 11 — Exportable Evidence Bundles

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

## Exit Gate

A bundle created on one machine can be moved to another and independently verified.

---

# Phase 12 — Signatures and External Anchoring

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

## Exit Gate

The verifier can distinguish:

```text
integrity verification
signature verification
external-anchor verification
```

as separate dimensions.

---

# Phase 13 — Performance Hardening

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

## Exit Gate

Measured overhead improves without weakening:

```text
invariants
test coverage
verification strength
failure visibility
```

---

# Phase 14 — Privacy and Selective Disclosure

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

## Exit Gate

An investigator can verify that a disclosed derivative corresponds to a declared source relationship without the system falsely claiming the derivative is the original artifact.

---

# Phase 15 — Distributed Custody

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

## Exit Gate

Evidence can cross independently operated systems without silently losing origin, identity, custody, or uncertainty.

---

# Phase 16 — Formal Verification

## Goal

Formalize only stable, high-value invariants.

Do not formalize architecture still changing weekly.

## Candidate Formal Targets

Potential later targets include:

```text
self-hash exclusion
append-only correction semantics
classification preservation
manifest sealing
verification purity
non-authority of presentation
event/artifact identity separation
```

## Rule

Formal verification proves the model encoded.

It does not automatically prove:

```text
runtime implementation
source data truth
adapter honesty
external system behavior
```

## Exit Gate

Formal claims are explicitly connected to corresponding runtime invariants and tests.

---

# Phase 17 — Release-Grade Trust Lane

## Goal

Create a high-assurance release process distinct from routine fast CI.

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
bundle export
independent verification
```

If formal verification exists:

```text
cold/reconstructed formal trust lane
```

remains distinguishable from cached verification.

## Exit Gate

A tagged release can produce a self-consistent release evidence record whose claims accurately describe what was actually executed.

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
