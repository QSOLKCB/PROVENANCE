# PROVENANCE Architecture — v0.2

## Status

```text
BOOTSTRAP MODULAR ARCHITECTURE
IMPLEMENTATION NOT YET FROZEN
```

This document defines the intended architecture of `QSOLKCB/PROVENANCE`.

PROVENANCE is designed as a **modular evidence system**:

```text
small core
+
independent verification
+
optional storage
+
optional adapters
+
optional interfaces
+
optional presentation
```

The modules cooperate.

They must not become inseparable.

Normative engineering law remains in:

```text
AGENTS.md
INVARIANTS.md
```

Project context and engineering ancestry remain in:

```text
README.md
README4AIs.md
DONORS.md
LINEAGE.md
```

---

# 1. Architectural Objective

PROVENANCE is a framework-neutral system for recording, preserving, relating, and independently verifying evidence about actions performed by:

```text
AI systems
agents
applications
tools
services
humans
automated workflows
distributed systems
```

Its primary optimization target is:

```text
MINIMUM_OVERHEAD
subject to
ZERO_UNDECLARED_LOSS_OF_EVIDENTIARY_ACCURACY
```

The system should perform no work that is unnecessary to establish the declared evidence contract.

Performance may reduce:

```text
latency
CPU time
memory
storage duplication
CI time
network traffic
```

It must not silently reduce:

```text
evidence fidelity
verification strength
observation honesty
custody integrity
```

---

# 2. Architectural Style

PROVENANCE follows a modular architecture inspired by systems where a stable core is surrounded by replaceable engines, interfaces, hosts, and extensions.

Conceptually:

```text
                     ┌─────────────────┐
                     │ provenance-ui   │
                     └────────┬────────┘
                              │
                    ┌─────────▼─────────┐
                    │ provenance-mcp    │
                    └─────────┬─────────┘
                              │
      ┌───────────────────────┼────────────────────────┐
      │                       │                        │
┌─────▼──────────┐    ┌───────▼────────┐      ┌────────▼────────┐
│ provenance-cli │    │ provenance-api │      │ provenance-     │
│                │    │ / embedding    │      │ adapters        │
└─────┬──────────┘    └───────┬────────┘      └────────┬────────┘
      │                       │                        │
      └───────────────────────┼────────────────────────┘
                              ▼
                     ┌─────────────────┐
                     │ provenance-core │
                     └────────┬────────┘
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
      provenance-store  provenance-verify  schemas/spec
```

No outer module may redefine core evidence semantics.

---

# 3. Monorepo First

PROVENANCE should initially remain one repository.

Module separation does **not** require separate GitHub repositories.

Preferred bootstrap structure:

```text
PROVENANCE/
│
├── provenance-core/
├── provenance-verify/
├── provenance-store/
├── provenance-mcp/
├── provenance-cli/
├── provenance-ui/
├── provenance-adapters/
│
├── schemas/
├── tests/
│
├── README.md
├── README4AIs.md
├── AGENTS.md
├── INVARIANTS.md
├── ARCHITECTURE.md
├── DONORS.md
└── LINEAGE.md
```

This shape is conceptual until implementation requires each module.

Do not create empty modules merely to make the tree look mature.

A module should exist because it has a distinct contract.

---

# 4. Module Rule

Each module must satisfy:

```text
ONE PRIMARY RESPONSIBILITY
CLEAR INPUT CONTRACT
CLEAR OUTPUT CONTRACT
NO HIDDEN AUTHORITY
REPLACEABLE WHERE PRACTICAL
```

Modules may depend downward.

Core modules must not depend upward.

Preferred direction:

```text
UI
 ↓
MCP / CLI
 ↓
Adapters / Store
 ↓
Core
 ↓
Canonical Evidence Contract
```

Verification consumes evidence independently:

```text
Evidence
   ↓
provenance-verify
```

The verifier must not require:

```text
UI
MCP
Ollama
OpenAI
database server
specific adapter
original monitored application
```

to validate a finalized evidence bundle.

---

# 5. `provenance-core`

`provenance-core` is the smallest and most protected module.

It defines the universal evidence semantics.

Its responsibilities are limited to:

```text
evidence classification
event model
artifact references
relationships
canonicalization
content identity
manifest structures
custody structures
failure/gap representation
```

It must remain:

```text
framework-neutral
provider-neutral
storage-neutral
UI-neutral
transport-neutral
policy-neutral
```

It must not contain special knowledge of:

```text
OpenAI
Claude
Gemini
Grok
Ollama
MCP
legal systems
medical systems
GitHub
databases
web browsers
```

Those belong above the core.

---

# 6. Core Data Types

The initial core should have very few universal concepts.

## 6.1 Artifact

An Artifact identifies retained content.

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
binary
log fragment
```

Conceptually:

```text
Artifact
├── schema
├── content identity
├── structured record identity
├── byte count
├── media type
├── retention state
└── optional acquisition metadata
```

The architecture must distinguish:

```text
CONTENT_RETAINED
```

from:

```text
DIGEST_ONLY
```

A cryptographic digest is not the original artifact.

---

## 6.2 Event

An Event records an occurrence.

Conceptually:

```text
Event
├── schema
├── event identity
├── evidence class
├── actor reference
├── operation
├── time information
├── input references
├── output references
├── relationships
├── observer
└── extensions
```

An event and an artifact are different things.

```text
EVENT
answers:
"What occurred?"

ARTIFACT
answers:
"What exact content is this?"
```

---

## 6.3 Relationship

Relationships connect evidence without inventing meaning.

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

Temporal adjacency does not automatically become causality.

---

## 6.4 Custody Event

Custody is append-only evidence describing handling.

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

Corrections append.

History does not rewrite.

---

## 6.5 Manifest

A Manifest identifies a collection of evidence.

Preferred shape:

```text
ManifestCore
├── schema
├── event identities
├── artifact identities
├── custody identities
└── scope

        ↓ canonicalize + hash

ManifestEnvelope
├── core
└── core identity
```

The digest is computed over the core.

The envelope may then carry the digest.

No circular self-hashing.

---

# 7. Evidence Classification

The core evidence classes begin with:

```text
OBSERVED
DECLARED
DERIVED
```

These describe provenance.

They are not truth scores.

```text
OBSERVED != TRUE
DECLARED != FALSE
DERIVED != SPECULATIVE
```

Example:

An Ollama adapter directly receiving a response body may classify those received bytes as:

```text
OBSERVED
```

The model name supplied by Ollama may be:

```text
DECLARED
```

A SHA-256 digest calculated by PROVENANCE is:

```text
DERIVED
```

---

# 8. Canonicalization

Canonicalization belongs in `provenance-core`.

It applies only to structured PROVENANCE records.

It must not modify raw evidence.

```text
RAW ARTIFACT
     │
     ├── retained bytes
     └── content digest

STRUCTURED RECORD
     │
     ▼
canonical bytes
     │
     ▼
record digest
```

Target property:

```text
same evidence values
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

---

# 9. Content Identity and Domain Separation

Raw artifact content uses ordinary algorithm-qualified cryptographic identity:

```text
sha256:<SHA-256 of exact artifact bytes>
```

Raw artifact hashes are deliberately **not** domain-separated so that ordinary forensic and cryptographic tools can independently reproduce them.

Structured PROVENANCE record identities should use explicit semantic domains where appropriate:

```text
PROVENANCE/ARTIFACT-RECORD/v1
PROVENANCE/EVENT/v1
PROVENANCE/MANIFEST/v1
PROVENANCE/CUSTODY/v1
PROVENANCE/CHECKPOINT/v1
```

This prevents identical structured canonical bytes used in different semantic roles from being accidentally treated as the same kind of record while preserving standard content identity for source artifacts.

---

# 10. `provenance-verify`

`provenance-verify` is an independent verification engine.

Its rule is:

```text
RECOMPUTE
NOT TRUST
```

It consumes evidence.

It does not modify it.

The Phase 2 physical bundle contract is defined in [BUNDLE.md](BUNDLE.md). The bootstrap verifier validates canonical manifest/event/artifact records, exact physical membership, retained-content byte counts and SHA-256 identities, self-hash exclusion, and internal reference closure.

Typical verification operations include:

```text
canonical form
content hashes
byte counts
manifest membership
event links
custody links
signatures
external anchors
bundle closure
schema validity
```

Output may include:

```text
VERIFIED
FAILED
UNKNOWN
NOT_PRESENT
NOT_APPLICABLE
```

Verification must never perform:

```text
repair
rewrite
normalization-in-place
historical correction
```

---

# 11. Verification Is Multidimensional

PROVENANCE must not collapse all assurance into one Boolean.

Example:

```text
integrity = VERIFIED
schema = VERIFIED
custody = PARTIAL
signature = NOT_PRESENT
replay = NOT_POSSIBLE
anchor = NOT_PRESENT
```

This is more honest than:

```text
trusted=true
```

or:

```text
trusted=false
```

A valid historical record does not require every possible assurance dimension.

---

# 12. `provenance-store`

`provenance-store` handles persistence.

Storage is an implementation concern.

It must not define evidence meaning.

Possible backends include:

```text
filesystem
content-addressed directory
SQLite
database
object storage
append-only service
remote custody store
```

The first backend should be simple.

A local filesystem or similarly lightweight store is preferred initially.

The Phase 3 reference backend is implemented in `provenance_store` and documented in [STORE.md](STORE.md). It keeps mutable store state separate from verifier-compatible immutable snapshots. Content-addressed objects are published without overwrite; snapshots are independently verified before the mutable `HEAD` pointer advances.

---

# 13. Storage Model

The store should distinguish:

```text
ARTIFACT CONTENT
ARTIFACT RECORDS
EVENT RECORDS
MANIFESTS / SNAPSHOTS
FUTURE CUSTODY RECORDS
DERIVED INDEXES
```

The Phase 3 reference store does not yet create custody records. Custody semantics belong to Phase 4.

Indexes are disposable.

Evidence is not.

If an index can be rebuilt, it should not become authoritative merely because querying it is faster.

---

# 14. Content Deduplication

Exact content may be stored once and referenced many times.

Example:

```text
EVENT 1 ───┐
EVENT 2 ───┼──► sha256:X
EVENT 3 ───┘
```

Preferred:

```text
store artifact X once
reference X three times
```

Deduplication must use strong content identity.

Never:

```text
same filename
→ assume same artifact
```

---

# 15. `provenance-adapters`

Adapters connect monitored systems to the core.

Adapters are optional modules.

Potential adapters include:

```text
ollama
openai
anthropic
gemini
grok
llama.cpp
generic HTTP
CLI/process
filesystem
agent framework
custom application
```

Each adapter must declare:

```text
what it observes
what it does not observe
what values are declared externally
what values PROVENANCE derives
failure behavior
```

---

# 16. Adapter Rule

Adapters translate.

They do not invent.

Example:

```text
provider did not expose immutable model revision
```

must remain:

```text
immutable model revision = NOT_OBSERVED
```

not:

```text
immutable model revision = guessed
```

Provider-specific metadata may be retained through extensions.

It must not reshape the universal core schema around one vendor.

---

# 16A. POSIX-First Local Portability

The local reference implementation should remain usable on ordinary Unix-like systems without requiring a desktop environment or network service.

Baseline principles:

```text
terminal-native
POSIX-style filesystem semantics
POSIX advisory record locks
same-process mutexes around process-owned POSIX lock files
integer evidentiary time arithmetic
no Bash requirement
no systemd requirement
no GNU-command requirement
no Node requirement
no automatic network dependency
```

Host-specific tools are optional observers.

For example:

```text
chronyc present
→ inspect existing host clock discipline

chronyc absent
→ use local system clock

explicit operator diagnostic
→ ntpdate -q <server>
```

PROVENANCE should execute subprocesses through explicit argv vectors, never by interpolating evidence into shell command strings.

Because classic POSIX record locks are process-owned, a record lock alone is not sufficient for multiple threads or instances in one process. Lock-file open/close operations must be serialized by the same process-local mutex used around acquisition of the POSIX record lock.

Presentation may use RFC3339/base-60 clock notation, but custody time calculations remain integer-only.

---

# 17. Ollama Reference Adapter

The first AI adapter is Ollama.

Reasons:

```text
local
open integration surface
no cloud dependency
reproducible CI setup
easy request/response capture
small models available
```

The Phase 5 reference implementation is:

```text
provenance_adapters.OllamaAdapter
adapter id = provenance-adapter:ollama/v1
transport = loopback HTTP only
endpoint = /api/generate
stream = false
dependencies = Python standard library + existing PROVENANCE modules
```

It retains the exact request bytes prepared by the adapter before transport and retains any HTTP response body bytes before parsing.

The transport boundary is enforced by an adapter-owned urllib opener with environment proxies disabled and redirects rejected. The documented localhost spelling is canonicalized to a literal loopback address to avoid DNS.

Prepared request evidence does not independently prove peer receipt. Transport and parse failures are recorded with COLLECTION_FAILED events and finalized evidence rather than silently disappearing.

Phase 5 uses one fresh evidence store/custody pair per exchange. This prevents deterministic event identities from collapsing repeated byte-identical calls until the core has an evidence-supported occurrence discriminator.

Adapter-retained HTTP payload bytes use one role-neutral artifact media type. Transport role is represented by events/custody so identical bytes can legitimately appear as both prepared request and observed response without rebinding content identity metadata.

Every finalized failure binds a canonical failure-detail artifact containing a stable adapter category, optional observed HTTP status, and diagnostic detail. Zero-length observed HTTP bodies remain distinct from no observed body.

The response model field is treated as a declaration by Ollama. It is not promoted into independently verified model provenance, and it is not used as the custody actor.

Capture times are expressed through custody observations rather than by adding provider-specific timestamp fields to the universal event core.

The Ollama adapter exists primarily to test the evidence architecture.

It must not define AI provenance semantics for every other provider.

Ollama's OpenAI-compatible endpoints are intentionally not used to redefine Phase 5. OpenAI-compatible HTTP remains a later generic interoperability surface behind the adapter boundary.

---

# 18. Ollama CI Contract

The initial real-model lane uses a GitHub Actions matrix with separate clean runners. Each matrix job starts its own Ollama server and pulls one small reference model.

Current reference matrix:

```text
qwen2.5:0.5b
qwen2:0.5b
```

The Ollama runtime is version-pinned in the workflow and its downloaded installer script is checksum-verified before execution.

A real inference test should verify the chain rather than exact generated language.

Example flow:

```text
PROMPT
  ↓
OLLAMA REQUEST
  ↓
MODEL EXECUTION
  ↓
OLLAMA RESPONSE
  ↓
PROVENANCE EVENTS
  ↓
ARTIFACT HASHES
  ↓
MANIFEST
  ↓
VERIFY
```

Assertions should cover:

```text
prepared request retained
successful or error response bytes retained when observed
failure evidence finalized on transport/parse failure
request identity recomputes
response identity recomputes
adapter identity recorded
model metadata classification correct
event relationships valid
manifest valid
verification passes
```

Then mutate retained evidence:

```text
change one byte
↓
verification fails
```

Do not require:

```text
prompt X always produces exact string Y
```

Model output is the observed evidence.

It is not the regression oracle.

---

# 19. `provenance-mcp`

`provenance-mcp` exposes PROVENANCE through the Model Context Protocol.

MCP is an interface.

It is not part of the evidence core.

Initial tools may include:

```text
provenance.record
provenance.inspect
provenance.verify
provenance.finalize
provenance.export
```

Potential resources:

```text
provenance://event/<id>
provenance://artifact/<identity>
provenance://manifest/<id>
provenance://custody/<id>
provenance://schema/<version>
```

---

# 20. MCP Evidence Boundary

An AI calling:

```text
provenance.record(...)
```

does not make every supplied value independently observed.

If an AI says:

```text
"I called tool X because Y"
```

through MCP, that information is normally:

```text
DECLARED
```

unless PROVENANCE independently observed the relevant action or rationale.

The MCP server must not upgrade self-report into observation.

---

# 21. MCP Transport

Initial implementation should prefer the lowest-complexity useful transport.

Likely progression:

```text
stdio
  ↓
local integration proven
  ↓
optional remote transport
```

Remote transport must not become mandatory for local evidence recording.

A local application should be able to use PROVENANCE without operating a network service.

---

# 22. `provenance-cli`

The CLI is the simplest human and automation interface.

The preferred interactive implementation direction is a Rust TUI with keyboard-first slash-command discovery. Typing `/` should open/filter a compact command palette rather than requiring users to memorize flags for common interactive operations.

Initial commands may conceptually include:

```text
provenance record
provenance verify
provenance inspect
provenance finalize
provenance export
```

The CLI should expose core functionality directly.

It should not contain a second implementation of verification semantics.

Provider authentication belongs behind an interface boundary. Supported modes may include API keys, OAuth device authorization, OAuth browser/loopback authorization, or no authentication for local endpoints. Tokens and credentials are operational secrets, not ordinary evidence payloads.

OpenAI-compatible API surfaces may be supported as a generic interoperability adapter because many providers and local/open-source systems implement similar request/response shapes. That compatibility must remain outside the universal evidence core.

---

# 23. `provenance-ui`

The UI is an evidence viewer.

It has no evidentiary authority.

The initial viewer should be served by a tiny local HTTP server bound to loopback by default and implemented with pure HTML/CSS plus minimal vanilla JavaScript. No frontend framework or Node runtime is required unless a later concrete requirement earns that complexity.

Its job is to make the chain understandable.

Primary views should include:

```text
timeline
event graph
artifact inspector
custody history
verification status
evidence gaps
```

The UI consumes existing evidence.

It does not define evidence.

Network exposure is explicit:

```text
default = 127.0.0.1
LAN/public = operator opt-in
```

Do not expose unrelated inetd-style utility services as part of the viewer.

---

# 24. UI Evidence Graph

The central visual model should be the evidence chain.

Example:

```text
USER INPUT
    │
    ▼
PROMPT ARTIFACT
sha256:...
    │
    ▼
MODEL INVOCATION
    │
    ├────► TOOL CALL
    │         │
    │         ▼
    │      TOOL RESULT
    │
    ▼
MODEL RESPONSE
sha256:...
    │
    ▼
APPLICATION ACTION
    │
    ▼
HUMAN REVIEW
```

Selecting a node should expose:

```text
WHO
WHAT
WHEN
WHERE
HOW
WHY-EVIDENCE
CLASSIFICATION
IDENTITY
CUSTODY
VERIFICATION
```

---

# 25. Evidence Gaps in the UI

Evidence gaps must be visually explicit.

Never quietly connect:

```text
EVENT 15
   ↓
EVENT 16
```

when collection was interrupted.

Instead:

```text
EVENT 15
   │
   ▼
██████████████████████
█  EVIDENCE GAP      █
█ collection failed █
██████████████████████
   │
   ▼
EVENT 16
```

A missing record is not evidence that nothing happened.

---

# 26. UI Technology

The initial UI should remain lightweight.

Preferred direction:

```text
HTML
CSS
minimal JavaScript
```

unless requirements later justify something heavier.

Avoid introducing a large application framework merely to display evidence graphs and metadata.

The UI should be replaceable without affecting:

```text
recording
storage
verification
evidence identity
```

---

# 27. Observation Topologies

Adapters may observe systems through several topologies.

## Native Hook

```text
APPLICATION
    ├── normal operation
    └── provenance observation
```

## Middleware / Proxy

```text
APPLICATION
    ↓
PROXY
    ↓
EXTERNAL SYSTEM
```

## Sidecar

```text
APPLICATION ─────► normal system
     │
     └───────────► PROVENANCE
```

## External Observer

```text
SYSTEM
   ↓
observable external effects
   ↓
PROVENANCE
```

Each has a different observation boundary.

PROVENANCE must preserve that distinction.

---

# 28. Non-Interference

No PROVENANCE module may silently alter monitored behavior.

Forbidden hidden operations include:

```text
rewrite prompt
rewrite response
change model settings
retry request
suppress tool call
change tool output
change decision
reorder monitored action
```

An integrating application may explicitly choose such behavior.

That application decision then belongs to the monitored system, not PROVENANCE.

---

# 29. Hot-Path Architecture

The monitored hot path should perform the minimum work required for accurate capture.

Preferred:

```text
observe
→ capture bytes/reference
→ minimal metadata
→ enqueue/store
→ return
```

Move nonessential work off the hot path:

```text
indexing
search
timeline construction
visualization
report generation
derived analysis
```

Cryptographic operations may be streamed or deferred only when doing so does not create an undeclared integrity gap.

---

# 30. Bounded Collection

PROVENANCE must not use unbounded memory merely to avoid admitting that evidence was lost.

Collectors need explicit bounded behavior.

Possible outcomes:

```text
RECORDED
PARTIALLY_RECORDED
DROPPED
COLLECTION_FAILED
EVIDENCE_GAP_OPENED
```

Silently dropping evidence while presenting continuity is forbidden.

---

# 31. Backpressure

PROVENANCE should not secretly become application flow control.

Possible integration policies include:

```text
best effort
bounded buffer
synchronous evidence capture
application-defined fail closed
application-defined fail open
```

The host chooses the policy.

PROVENANCE records or exposes which policy applies.

---

# 32. Failure Architecture

Failure is evidence.

Examples:

```text
capture failure
serialization failure
storage failure
hash failure
queue overflow
network failure
permission failure
unsupported field
process termination
```

Correct behavior:

```text
DETECT
  ↓
PRESERVE WHAT IS KNOWN
  ↓
MARK UNKNOWN / MISSING PORTION
  ↓
REPORT GAP
```

Never:

```text
FAILURE
  ↓
INVENT REPLACEMENT
```

---

# 33. Time and Ordering

PROVENANCE should retain both time and ordering information without treating them as identical.

Possible fields:

```text
capture_time
declared_event_time
monotonic_time
sequence
clock_source
clock_precision
```

Do not manufacture a global total order when evidence supports only partial ordering.

---

# 34. Replay

Replay is optional evidence.

It is not a universal validity requirement.

```text
HISTORICAL OBSERVATION
!=
LATER REPLAY
```

Replay may be:

```text
VERIFIED
FAILED
NOT_POSSIBLE
NOT_ATTEMPTED
```

The inability to replay an old model or external system does not invalidate authentic historical evidence.

---

# 35. Reference and Optimized Paths

Where practical, important operations should retain a straightforward reference path.

Example:

```text
                 ┌── reference verifier
evidence ────────┤
                 └── optimized verifier

results must agree
```

Allowed optimization mechanisms include:

```text
streaming
deduplication
incremental verification
proven-equivalent caching
bounded parallelism
verified dependency reuse
```

Required condition:

```text
OPTIMIZED SEMANTICS
==
REFERENCE SEMANTICS
```

---

# 36. Caching

Cache entries are not trusted merely because they exist.

Reuse requires:

```text
COMPLETE EFFECTIVE INPUT IDENTITY
+
VALIDATED OUTPUT IDENTITY
+
SUCCESSFUL PRIOR GENERATION
+
PRESERVED SEMANTIC CONTRACT
```

A failed or interrupted operation must never publish authoritative reusable state.

For cheap cryptographic verification:

```text
prefer recomputation
```

over complicated caching.

---

# 37. Module Independence Test

Each optional module should be removable.

Deleting:

```text
provenance-ui
```

must not invalidate evidence.

Deleting:

```text
provenance-mcp
```

must not invalidate evidence.

Deleting:

```text
provenance-adapters/ollama
```

must not break the verifier.

Replacing:

```text
provenance-store
```

must not change core evidence semantics.

This is a central architectural test.

---

# 38. Interface Consistency

All interfaces should ultimately use the same core contracts.

```text
CLI ─────┐
MCP ─────┤
UI ──────┤
SDK ─────┤
Adapters ┘
         ↓
   provenance-core
```

There must not be:

```text
MCP evidence format
UI evidence format
CLI evidence format
```

with subtly different meanings.

One evidence contract.

Many interfaces.

---

# 39. Privacy

Evidence completeness does not require collecting everything.

An adapter should distinguish:

```text
required evidence
optional context
unnecessary sensitive data
secret material
```

Credentials and private keys must not become ordinary evidence payloads.

Supported strategies may include:

```text
digest-only retention
encryption
redaction derivative
content omission
access-controlled storage
retention policies
```

If content is omitted, that fact must remain explicit.

---

# 40. Framework Neutrality

The architecture must support:

```text
OpenAI
Anthropic
Google
xAI
Ollama
llama.cpp
future unknown providers
non-AI systems
```

without changing the universal evidence semantics.

Correct:

```text
provider
   ↓
adapter
   ↓
PROVENANCE CORE
```

Wrong:

```text
PROVENANCE CORE
=
one provider schema
+
patches for everyone else
```

---

# 41. Language Neutrality

The reference implementation may initially use one language.

The evidence contract must not depend on language-specific object representation.

Forbidden protocol authority includes:

```text
Python repr()
pickle
process object IDs
dict insertion accidents
runtime hash()
```

Independent implementations must eventually be possible.

---

# 42. Dependency Direction

Hard direction:

```text
provenance-ui
      ↓
provenance-mcp / provenance-cli
      ↓
provenance-adapters / provenance-store
      ↓
provenance-core
```

Independent branch:

```text
evidence
   ↓
provenance-verify
   ↓
verification report
```

Forbidden dependency direction:

```text
provenance-core
      ↓
provenance-ui
```

or:

```text
provenance-verify
      ↓
Ollama adapter
```

---

# 43. Bootstrap Module Order

Do not build every module immediately.

Preferred implementation order:

```text
PHASE 1
provenance-core
    canonical bytes
    artifact identity
    event
    manifest

PHASE 2
provenance-verify
    manifest verification
    tamper detection
    fixtures

PHASE 3
provenance-store
    simple local storage
    content deduplication

PHASE 4
provenance-adapters/ollama
    real AI observation
    GitHub Actions integration

PHASE 5
provenance-mcp
    stdio tools/resources

PHASE 6
provenance-cli
    inspection and verification

PHASE 7
provenance-ui
    evidence graph
    timeline
    gaps
    artifact inspection

PHASE 8
additional adapters
    OpenAI
    Claude
    Gemini
    Grok
    generic HTTP
```

Signatures, external anchoring, distributed custody, and formal verification come later unless a concrete requirement pulls them forward.

---

# 44. CI Architecture

CI should also remain modular.

```text
core.yml
    canonicalization
    identity
    manifests
    tamper fixtures

verify.yml
    verifier contract
    malformed evidence
    integrity failures

ollama.yml
    real local model smoke test

mcp.yml
    MCP protocol surface

ui.yml
    lightweight presentation tests

full.yml
    integration / release-grade validation
```

Path filtering or equivalent selective execution may reduce routine CI cost once module boundaries stabilize.

Invariant-sensitive changes must still escalate appropriately.

---

# 45. Ollama CI Principle

The Ollama test validates PROVENANCE.

It does not validate Ollama's intelligence.

Do not assert:

```text
PROMPT X
→ EXACT RESPONSE Y
```

Assert:

```text
REQUEST OBSERVED
RESPONSE OBSERVED
ARTIFACT IDENTITIES VALID
EVENT RELATIONSHIPS VALID
MANIFEST VALID
VERIFY PASS
```

Then:

```text
TAMPER WITH ONE BYTE
→ VERIFY FAIL
```

---

# 46. MCP Self-Demonstration

A useful integration test is:

```text
AI / client
   ↓
calls PROVENANCE through MCP
   ↓
PROVENANCE records interaction
   ↓
client requests evidence chain
   ↓
PROVENANCE returns verifiable record
```

This demonstrates the system using its own public integration surface.

Self-observation must still preserve evidence classification boundaries.

---

# 47. Deployment Model

The same modules should support several deployment sizes.

## Minimal

```text
application
+
provenance-core
+
local store
```

## Developer / AI

```text
application
+
adapter
+
core
+
store
+
MCP
```

## Investigator

```text
evidence bundle
+
provenance-verify
+
CLI/UI
```

## Large deployment

```text
many adapters
+
core-compatible evidence service
+
remote storage
+
MCP/API
+
UI
+
external anchors
```

Scale changes.

Evidence semantics do not.

---

# 48. Architectural Anti-Patterns

Avoid making any of the following mandatory:

```text
central server
database cluster
cloud account
AI provider
MCP
UI
blockchain
message broker
container platform
replay
formal prover
JavaScript framework
```

Optional infrastructure must remain optional.

---

# 49. No Mandatory Blockchain

Chain of custody is not synonymous with blockchain.

External anchoring may use:

```text
digital signature
Git commit
signed release
timestamp service
transparency log
DOI record
append-only service
blockchain
```

PROVENANCE defines the evidence.

Anchoring mechanisms are replaceable.

---

# 50. Architectural Success Tests

The architecture succeeds if all of these are possible:

### Tiny integration

```text
small CLI
+
provenance-core
+
local files
```

### Local AI integration

```text
Ollama
+
adapter
+
core
+
store
```

### MCP integration

```text
AI client
+
provenance-mcp
+
core
```

### Human investigation

```text
old evidence bundle
+
provenance-verify
+
UI
```

### Large platform

```text
many systems
+
many adapters
+
shared store
+
same evidence contract
```

---

# 51. Five-Year Test

Assume five years have passed.

The monitored application no longer exists.

The AI model is unavailable.

The original developers are gone.

The UI has been completely rewritten.

The MCP protocol implementation has changed.

An investigator still possesses:

```text
artifacts
events
custody records
manifests
schemas
public specifications
```

A current independent verifier should still be able to determine:

```text
what was captured
what was retained
what was declared
what was derived
which bytes were hashed
which identities recompute
where gaps exist
which relationships are supported
what changed
what verifies
what cannot be known
```

If preserving evidence requires resurrecting the old UI, MCP server, Ollama adapter, or original application:

```text
ARCHITECTURE FAILED
```

---

# Final Architecture Law

PROVENANCE should resemble a collection of small cooperating instruments:

```text
CORE
VERIFY
STORE
ADAPTERS
MCP
CLI
UI
```

rather than one monolithic application.

Each module should know only what it needs to know.

Each optional surface should remain replaceable.

The core must remain boring.

That is a feature.

```text
SMALL CORE
CLEAR MODULES
ONE EVIDENCE CONTRACT
OPTIONAL INTEGRATIONS
INDEPENDENT VERIFICATION
MINIMUM OBSERVER EFFECT
```

Architectural checksum:

```text
CAPTURE ONLY WHAT THE CONTRACT REQUIRES.

PRESERVE EXACTLY WHAT WAS CAPTURED.

KEEP THE CORE INDEPENDENT OF THE INTERFACES.

MAKE EVERY OPTIONAL MODULE REPLACEABLE.

MAKE THE EVIDENCE SURVIVE THE SOFTWARE THAT CREATED IT.

GET OUT OF THE MONITORED SYSTEM'S WAY.
```
