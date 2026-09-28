# PROVENANCE Architecture — v0.1

## Status

```text
BOOTSTRAP ARCHITECTURE
IMPLEMENTATION NOT YET FROZEN
```

This document defines the intended architecture of `QSOLKCB/PROVENANCE`.

It translates the project principles and invariants into a minimal system design.

Normative engineering rules remain in:

```text
AGENTS.md
INVARIANTS.md
```

Project purpose and context remain in:

```text
README.md
README4AIs.md
DONORS.md
LINEAGE.md
```

---

# 1. Architectural Objective

PROVENANCE is a framework-neutral evidence recorder and verifier.

Its primary optimization target is:

```text
MINIMUM_OVERHEAD
subject to
ZERO_UNDECLARED_LOSS_OF_EVIDENTIARY_ACCURACY
```

The system should perform no work that is unnecessary to establish the declared provenance contract.

The system must not make evidence cheaper by making evidence weaker without saying so.

---

# 2. Architectural Boundary

PROVENANCE observes systems.

It does not control them.

```text
┌─────────────────────────────────────────┐
│            MONITORED SYSTEM             │
│                                         │
│ AI / Agent / Application / Tool / API   │
└───────────────────┬─────────────────────┘
                    │
                    │ observable activity
                    ▼
┌─────────────────────────────────────────┐
│                ADAPTER                  │
│     minimal framework-specific capture  │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│              EVIDENCE CORE              │
│                                         │
│ classify · identify · relate · record   │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│              EVIDENCE STORE             │
│                                         │
│ events · artifacts · custody · indexes  │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│                VERIFIER                 │
│                                         │
│ hashes · structure · lineage · custody  │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│          EXPORT / PRESENTATION          │
│                                         │
│ bundles · reports · timelines · tools   │
└─────────────────────────────────────────┘
```

The direction of authority is one-way.

```text
MONITORED SYSTEM
      ↓
OBSERVATION
      ↓
EVIDENCE
```

Never:

```text
EVIDENCE SYSTEM
      ↓
MONITORED DECISION
```

---

# 3. No Control Plane

PROVENANCE has no decision-authority plane.

The core must not provide semantics equivalent to:

```text
allow()
deny()
approve()
block()
rewrite()
retry()
correct()
```

for monitored behavior.

It may return information such as:

```text
RECORDED
NOT_RECORDED
PARTIAL
COLLECTION_FAILED
VERIFIED
VERIFICATION_FAILED
```

What an integrating application does with that information belongs to the integrating application.

That decision is itself potentially observable evidence.

---

# 4. Core Architectural Units

The minimal architecture contains six logical responsibilities.

They do not initially require six separate services, processes, packages, or databases.

A small reference implementation may implement several responsibilities in a single process.

---

## 4.1 Adapter

An adapter observes a specific system or framework.

Examples:

```text
OpenAI API
Anthropic API
Gemini API
Grok API
Ollama
llama.cpp
agent framework
HTTP service
CLI program
filesystem workflow
custom application
```

An adapter should do as little work as practical.

Its responsibilities are:

```text
capture observable values
identify the observation source
declare observation boundaries
forward evidence to the core
report capture failure
```

An adapter must not invent fields merely because the core schema supports them.

Example:

```text
provider did not expose exact model revision
```

must remain equivalent to:

```text
exact model revision = UNKNOWN / NOT OBSERVED
```

not:

```text
exact model revision = guessed value
```

---

## 4.2 Evidence Core

The Evidence Core provides framework-neutral semantics.

It is responsible for:

```text
evidence classification
event structure
artifact references
relationships
identity
canonical representation
custody records
failure representation
```

The core should know nothing about the scientific, legal, medical, financial, or operational meaning of the monitored decision.

The core asks:

> What happened and what evidence supports the record?

It does not ask:

> Was the decision good?

---

## 4.3 Evidence Store

The Evidence Store retains evidence.

The storage technology is not part of the universal evidence contract.

Possible implementations may include:

```text
filesystem
content-addressed storage
object storage
database
append-only log
remote evidence service
```

The first implementation should prefer the simplest storage model that satisfies the invariants.

The store must distinguish:

```text
EVENT METADATA
ARTIFACT CONTENT
CUSTODY HISTORY
DERIVED INDEXES
```

Indexes are disposable.

Evidence is not.

An index may always be regenerated from evidence where the architecture claims it is derivative.

---

## 4.4 Canonicalization and Identity

Canonicalization applies to structured PROVENANCE records.

It does not alter raw artifacts.

```text
RAW ARTIFACT
     │
     ├──────────────► retained bytes
     │
     └──────────────► artifact identity

STRUCTURED RECORD
     │
     ▼
canonical representation
     │
     ▼
cryptographic identity
```

Target property:

```text
same structured evidence
+
same schema version
+
same canonicalization version
=
same canonical bytes
```

and:

```text
same canonical bytes
+
same hash algorithm
=
same digest
```

Identity algorithms must be explicit.

Example:

```text
sha256:<digest>
```

---

## 4.5 Verifier

The verifier is read-only with respect to historical evidence.

Its purpose is to recompute claims rather than trust stored claims.

Typical checks may include:

```text
schema validity
canonical representation
content digest
artifact byte count
manifest membership
event linkage
custody linkage
signature validity
checkpoint integrity
bundle closure
```

Verification must never repair evidence in place.

```text
VERIFY
    ↓
PASS / FAIL / UNKNOWN
```

not:

```text
VERIFY
    ↓
MODIFY UNTIL PASS
```

---

## 4.6 Export and Presentation

Export and presentation are derived layers.

Examples:

```text
evidence bundles
timelines
HTML reports
JSON exports
graphs
CLI inspection
legal exhibits
medical review packages
audit summaries
```

These layers have no authority to alter source evidence.

```text
PRESENTATION
!=
EVIDENCE
```

---

# 5. Fundamental Data Types

The architecture should begin with very few universal concepts.

---

## 5.1 Event

An Event represents an observed, declared, or derived occurrence.

Conceptually:

```text
Event
├── schema/version
├── identity
├── evidence class
├── actor reference
├── operation
├── time information
├── input references
├── output references
├── relationships
├── observation source
└── optional extensions
```

The exact schema remains to be defined.

---

## 5.2 Artifact

An Artifact represents retained content.

Examples:

```text
prompt
response
document
image
tool payload
API response
source file
configuration
model output
log fragment
binary
```

Conceptually:

```text
Artifact
├── content identity
├── byte count
├── media type
├── acquisition metadata
├── source metadata
└── storage reference
```

An artifact record must distinguish:

```text
CONTENT RETAINED
```

from:

```text
ONLY CONTENT IDENTITY RETAINED
```

A digest is not the artifact itself.

---

## 5.3 Relationship

Relationships describe known connections between records.

Examples:

```text
previous
parent
triggered_by
input_to
output_of
derived_from
captured_from
approved_by
supersedes
```

Relationships must not silently imply more than they state.

---

## 5.4 Custody Event

Custody is recorded as history.

Examples:

```text
captured
stored
transferred
copied
exported
redacted
encrypted
verified
signed
released
```

Custody events append.

They do not rewrite earlier custody.

---

## 5.5 Manifest

A Manifest identifies a collection of evidence.

Conceptually:

```text
ManifestCore
├── schema
├── artifact identities
├── event identities
├── custody identities
└── declared scope

        ↓ canonicalize + hash

ManifestEnvelope
├── core
└── core identity
```

The digest is calculated from the core before the envelope contains the digest.

No circular self-hashing.

---

# 6. Event Identity Versus Artifact Identity

These concepts must remain separate.

An artifact answers:

> What exact content is this?

An event answers:

> What occurrence is being recorded?

Two events may reference the same artifact.

Example:

```text
EVENT A ──► artifact sha256:X
EVENT B ──► artifact sha256:X
```

The artifact identity remains the same.

The events remain distinct.

---

# 7. Evidence Classification

The core classification model begins with:

```text
OBSERVED
DECLARED
DERIVED
```

These are provenance properties.

They are not truth scores.

```text
OBSERVED != TRUE
DECLARED != FALSE
DERIVED != SPECULATIVE
```

They describe how information entered the evidence system.

---

# 8. Observation Modes

PROVENANCE must support more than one observation topology.

---

## 8.1 Native Hook

```text
APPLICATION
    │
    ├── normal operation
    │
    └── provenance event
```

Lowest integration distance.

Potentially lowest capture ambiguity.

Requires application integration.

---

## 8.2 Middleware / Proxy

```text
APPLICATION
    ↓
PROXY
    ↓
EXTERNAL SYSTEM
```

Useful for APIs and tool traffic.

Must not silently alter payloads.

---

## 8.3 Sidecar

```text
APPLICATION ─────► normal system
     │
     └───────────► PROVENANCE
```

Allows observation logic to remain operationally separate.

---

## 8.4 External Observer

```text
SYSTEM
   │
observable external effects
   ↓
OBSERVER
```

Lowest integration requirement.

Usually weakest observation boundary.

The evidence must say so.

---

# 9. Hot-Path Rule

The capture path should perform the minimum work necessary to preserve accurate evidence.

Prefer:

```text
capture
→ assign minimal metadata
→ preserve bytes/reference
→ enqueue/store
```

Avoid placing expensive work on the monitored hot path when it can safely occur later.

Possible deferred work:

```text
index construction
report generation
visualization
search indexing
timeline generation
nonessential derived analysis
```

Cryptographic work may be streamed or deferred only where doing so does not create an undeclared integrity gap.

---

# 10. Bounded Collection

Observation machinery must be bounded.

Unbounded queues or memory growth are not acceptable merely to avoid dropping evidence.

A collector must define behavior for resource exhaustion.

Possible states include:

```text
RECORDED
PARTIALLY_RECORDED
DROPPED
COLLECTION_FAILED
EVIDENCE_GAP_OPENED
```

The implementation must never silently discard evidence while presenting uninterrupted custody.

---

# 11. Backpressure

PROVENANCE itself should not silently impose new application control semantics.

If evidence cannot be recorded fast enough, the collector should report the condition.

The host integration may choose its own declared policy.

Examples:

```text
best-effort observation
bounded buffering
synchronous capture
application-defined failure policy
```

PROVENANCE must record or expose which policy applies.

It must not secretly choose one.

---

# 12. Time and Ordering

PROVENANCE should preserve both:

```text
TIME
```

and:

```text
ORDER
```

without assuming they are equivalent.

Potential event metadata may include:

```text
capture_time
declared_event_time
monotonic_time
sequence
clock_source
clock_precision
```

A global total order must not be manufactured when only partial ordering is supported by evidence.

---

# 13. Failure Architecture

Failure is a first-class record state.

Collector failures may include:

```text
capture failure
serialization failure
storage failure
hashing failure
queue overflow
process crash
network failure
permission failure
unsupported source data
```

Failure handling follows:

```text
detect
→ preserve what is known
→ identify missing portion
→ report gap
```

Never:

```text
detect
→ invent replacement
→ hide failure
```

---

# 14. Assurance Is Multidimensional

PROVENANCE must not reduce trust to one universal Boolean.

Different properties may be independently verified.

For example:

```text
integrity
custody
signature
replay
schema
observation completeness
external anchoring
```

Possible state:

```text
integrity = VERIFIED
signature = NOT_PRESENT
replay = NOT_POSSIBLE
custody = PARTIAL
```

This may still be valid historical evidence.

A single field such as:

```text
trusted=true
```

must not erase those distinctions.

---

# 15. Replay Is Optional Evidence

Replay may strengthen some records.

Replay is not universally required.

```text
HISTORICAL OBSERVATION
```

and:

```text
LATER REPLAY
```

remain different evidence.

A legal or medical AI interaction may be impossible to reproduce because:

```text
model revision disappeared
provider changed
external source disappeared
environment no longer exists
nondeterministic behavior cannot be recreated
```

The original evidence does not become invalid merely because replay is unavailable.

---

# 16. Storage Efficiency

PROVENANCE should avoid unnecessary duplication.

Preferred approaches may include:

```text
content-addressed artifacts
streaming hashes
deduplicated immutable content
small event envelopes
artifact references
bounded metadata
```

If ten events reference the same exact retained artifact:

```text
store artifact once
reference it ten times
```

where the storage backend permits this safely.

Deduplication must be based on strong content identity, not filename similarity.

---

# 17. Optimization Rules

Optimization is subordinate to correctness.

Allowed:

```text
batching
streaming
content deduplication
proven-equivalent caching
bounded parallel verification
incremental verification
verified dependency reuse
```

Required condition:

```text
OPTIMIZED_RESULT
==
REFERENCE_RESULT
```

under the declared exactness contract.

Reuse must bind the complete effective input identity.

Failed or partial work must never become reusable authoritative state.

---

# 18. Reference Path

Where practical, the project should retain a small canonical implementation against which optimized paths can be tested.

```text
              ┌── reference path
input ────────┤
              └── optimized path

results must agree
```

The optimized implementation must not become its own correctness oracle.

---

# 19. Privacy Boundary

Evidence completeness does not mean collecting everything available.

Before retaining sensitive content, integrations must distinguish:

```text
needed for evidence contract
optional contextual material
unnecessary secret
```

Credentials and private keys are not ordinary provenance payloads.

Potential mechanisms may include:

```text
content omission
digest-only retention
encryption
redaction derivatives
access-controlled storage
retention policy
```

If content is intentionally omitted:

```text
OMITTED
```

must not become:

```text
RETAINED
```

---

# 20. Framework Neutrality

The universal evidence core must not contain provider-specific assumptions.

Correct direction:

```text
OpenAI adapter ───┐
Claude adapter ───┤
Gemini adapter ───┤
Grok adapter ─────┤
Ollama adapter ───┤
Custom adapter ───┘
                  ↓
          PROVENANCE CORE
```

Incorrect direction:

```text
PROVENANCE CORE
=
one vendor API schema
+
special cases for everyone else
```

---

# 21. Language Neutrality

The evidence contract should be independently implementable.

The reference implementation may initially use one programming language.

The architecture must not make that language's runtime-specific representation the protocol.

For example:

```text
Python dict ordering
Python repr()
Python pickle
process-local object IDs
```

must not define portable evidence identity.

---

# 22. Proposed Minimal Repository Shape

This is a direction, not a requirement to create all paths immediately.

```text
PROVENANCE/
│
├── README.md
├── README4AIs.md
├── AGENTS.md
├── INVARIANTS.md
├── ARCHITECTURE.md
├── DONORS.md
├── LINEAGE.md
│
├── schemas/
│   └── ...
│
├── provenance/
│   ├── core
│   ├── canonical
│   ├── identity
│   ├── record
│   ├── verify
│   └── adapters
│
└── tests/
    ├── fixtures
    └── ...
```

Create directories only when implementation requires them.

Do not scaffold an empty framework for appearance.

---

# 23. Minimal Initial Implementation

The first executable implementation should prove only the smallest useful evidence contract.

Suggested order:

```text
1. canonical structured bytes
2. cryptographic artifact identity
3. minimal event record
4. artifact reference
5. core/envelope separation
6. manifest creation
7. manifest verification
8. tamper fixtures
```

Only after this works should the project add:

```text
custody chains
signatures
external anchors
adapter SDKs
streaming collectors
databases
distributed storage
dashboards
formal verification
```

unless an earlier requirement demonstrates the need.

---

# 24. Reference MVP Flow

A minimal end-to-end reference should eventually demonstrate:

```text
INPUT
  ↓
OBSERVE
  ↓
EVENT RECORD
  ↓
ARTIFACT IDENTITY
  ↓
MANIFEST
  ↓
FINALIZE
  ↓
TAMPER
  ↓
VERIFY
  ↓
FAIL
```

and:

```text
INPUT
  ↓
OBSERVE
  ↓
EVENT RECORD
  ↓
ARTIFACT IDENTITY
  ↓
MANIFEST
  ↓
FINALIZE
  ↓
VERIFY
  ↓
PASS
```

That is sufficient to establish the first real PROVENANCE core.

---

# 25. Architectural Anti-Patterns

Avoid:

```text
mandatory central server
mandatory database
mandatory blockchain
mandatory cloud service
mandatory AI provider
mandatory replay
mandatory policy engine
mandatory UI
hidden normalization
opaque binary protocol
unbounded event queues
global mutable recorder state
single "trusted" Boolean
provider-specific core schema
```

None are required to prove provenance.

---

# 26. Blockchain Is Not the Architecture

External anchoring may eventually use many mechanisms.

Examples:

```text
signed release
timestamp authority
transparency log
DOI record
Git commit
external signature
append-only service
blockchain
```

PROVENANCE must not equate:

```text
CHAIN OF CUSTODY
```

with:

```text
BLOCKCHAIN
```

Cryptographic custody is an evidence problem, not a cryptocurrency requirement.

---

# 27. Deployment Model

PROVENANCE should support progressive deployment.

```text
LEVEL 0
library / local recorder

LEVEL 1
application adapter

LEVEL 2
sidecar / proxy

LEVEL 3
central evidence service

LEVEL 4
distributed / externally anchored custody
```

Higher deployment complexity is optional.

A small local application should not need infrastructure designed for a national medical network merely to record a verifiable event.

---

# 28. Dependency Direction

Preferred conceptual dependency direction:

```text
adapters
   ↓
recording API
   ↓
core evidence model
   ↓
canonicalization / identity
```

Verification should depend on evidence contracts, not adapter runtime behavior:

```text
evidence bundle
   ↓
verifier
```

Presentation depends on verified/read evidence:

```text
evidence
   ↓
presentation
```

Core evidence semantics must never depend on:

```text
dashboard
specific adapter
specific AI vendor
application policy
```

---

# 29. Architectural Success Test

A correct architecture should allow this:

```text
small CLI program
+
PROVENANCE
```

without requiring a server.

And also this:

```text
large distributed AI platform
+
PROVENANCE adapters
+
remote evidence storage
+
independent verifier
```

without changing the fundamental evidence semantics.

The scale changes.

The contract does not.

---

# 30. Five-Year Test

Assume five years have passed.

The original application no longer exists.

The AI provider no longer serves the model.

The original developers are unavailable.

An investigator possesses only:

```text
evidence artifacts
event records
custody records
manifests
public specifications
verification software
```

The architecture succeeds if the investigator can determine:

```text
what was captured
what was retained
what was declared
what was derived
what was not observed
where gaps exist
which bytes hashes identify
which relationships are supported
whether evidence changed
whether verification succeeds
what cannot be known
```

without requiring the original monitored application.

---

# Final Architecture Rule

The system should always prefer:

```text
SMALL
EXPLICIT
VERIFYABLE
FRAMEWORK-NEUTRAL
NON-INTERFERING
```

over:

```text
CLEVER
OPAQUE
CENTRALIZED
MAGICAL
```

The architectural checksum is:

```text
CAPTURE ONLY WHAT IS NEEDED.
PRESERVE EXACTLY WHAT WAS CAPTURED.
DO NOT CLAIM WHAT WAS NOT CAPTURED.
MAKE THE RESULT INDEPENDENTLY VERIFIABLE.
GET OUT OF THE MONITORED SYSTEM'S WAY.
```
