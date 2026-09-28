# README4AIs.md

```text
PROJECT=PROVENANCE
REPOSITORY=QSOLKCB/PROVENANCE
PURPOSE=FRAMEWORK_AGNOSTIC_CRYPTOGRAPHIC_CHAIN_OF_CUSTODY
STATUS=BOOTSTRAP_SPECIFICATION
PRIMARY_CONSTITUTION=AGENTS.md
HUMAN_OVERVIEW=README.md
LICENSE=MPL-2.0
```

# MACHINE ENTRYPOINT

This file is intended primarily for AI agents, coding agents, automated reviewers, and machine-assisted development systems.

Before modifying this repository:

```text
READ AGENTS.md
READ README.md
READ relevant implementation/specification files
INSPECT current repository state
THEN reason about changes
```

Priority:

```text
AGENTS.md
    >
explicit repository contracts/specifications
    >
tests/fixtures
    >
README4AIs.md
    >
README.md explanatory material
    >
agent assumptions
```

If an assumption conflicts with repository evidence:

```text
REPOSITORY_WINS
```

If uncertainty remains:

```text
DO_NOT_INVENT
REPORT_UNCERTAINTY
```

---

# PROJECT MISSION

PROVENANCE records verifiable evidence describing:

```text
WHO
WHAT
WHEN
WHERE
WHY
HOW
```

for actions performed by:

```text
AI systems
LLMs
agents
software
tools
services
humans
automated workflows
distributed systems
```

Primary objective:

```text
CAPTURE
IDENTIFY
BIND
PRESERVE
VERIFY
PRESENT
```

PROVENANCE is:

```text
OBSERVER
RECORDER
EVIDENCE SYSTEM
CHAIN-OF-CUSTODY SYSTEM
VERIFICATION SYSTEM
```

PROVENANCE is NOT:

```text
CONTROLLER
POLICY ENGINE
GUARDRAIL
TRUTH ORACLE
JUDGE
LIABILITY ENGINE
MODEL ALIGNMENT SYSTEM
AUTOMATIC INTERPRETER
```

---

# PRIMARY INVARIANT

```text
MONITORED_SYSTEM_BEHAVIOUR
        |
        v
OBSERVATION
        |
        v
EVIDENCE
```

MUST NOT become:

```text
MONITORED_SYSTEM_BEHAVIOUR
        |
        v
OBSERVATION
        |
        v
MODIFICATION
        |
        v
DIFFERENT_SYSTEM_BEHAVIOUR
```

Rule:

```text
MONITORING != CONTROL
```

---

# NON-INTERFERENCE

PROVENANCE MUST NOT silently modify:

```text
prompts
responses
tool inputs
tool outputs
model parameters
execution order
application state
decisions
external actions
retry behaviour
failure behaviour
success behaviour
```

Observation overhead may exist.

Observation overhead MUST NOT be represented as nonexistent if materially relevant.

Collectors MUST report failure rather than modify monitored behaviour to preserve apparent continuity.

---

# EVIDENCE CLASSES

Minimum classes:

```text
OBSERVED
DECLARED
DERIVED
```

## OBSERVED

Directly captured by an observation mechanism.

Examples:

```text
request bytes
response bytes
tool invocation
tool result
file bytes
process status
API response
runtime event
```

Meaning:

```text
PROVENANCE_OBSERVED_VALUE
```

NOT necessarily:

```text
VALUE_IS_TRUE
```

---

## DECLARED

Asserted by an external actor/system.

Examples:

```text
reported model identifier
reported user identifier
provider metadata
operator-entered case ID
declared runtime version
model-supplied rationale
```

Rule:

```text
DECLARED != INDEPENDENTLY_VERIFIED
```

Never silently promote DECLARED to OBSERVED or VERIFIED.

---

## DERIVED

Calculated from retained evidence.

Examples:

```text
hash
Merkle root
elapsed duration
timeline
verification result
dependency relation
replay comparison
report
```

Requirement:

```text
DERIVED -> SOURCE_EVIDENCE_REFERENCE_REQUIRED
```

---

# RAW EVIDENCE

Original evidence MUST remain distinguishable from derivatives.

```text
RAW
 |
 +-> canonical representation
 +-> normalized derivative
 +-> index
 +-> timeline
 +-> report
 +-> visualization
 +-> analysis
```

Forbidden:

```text
overwrite raw evidence
repair raw evidence in place
normalize raw evidence destructively
remove inconvenient fields
rewrite history
replace malformed source with corrected source
```

Correction model:

```text
ORIGINAL
   +
CORRECTION_EVENT
   =
NEW_DERIVATIVE
```

Original remains retained.

---

# EVIDENCE GAPS

These are distinct states:

```text
NO_EVENT_OCCURRED
NO_EVENT_OBSERVED
COLLECTION_FAILED
EVIDENCE_MISSING
EVENT_MAY_HAVE_OCCURRED_DURING_GAP
UNKNOWN
```

Never collapse them.

Critical identities:

```text
UNKNOWN != ABSENT
NOT_OBSERVED != DID_NOT_HAPPEN
```

A complete-looking false timeline is invalid.

An incomplete but honest timeline is valid.

---

# WHY SEMANTICS

`WHY` means observable causal/contextual evidence.

Potential evidence:

```text
instructions
user inputs
retrieved context
source documents
application state
model configuration
model identifier
available tools
tool calls
tool results
policy results
validation results
decision codes
previous events
human approvals
explicit rationale
```

Forbidden:

```text
fabricated chain-of-thought
invented hidden reasoning
post-hoc explanation represented as historical rationale
```

Valid:

```text
RATIONALE_NOT_OBSERVED
```

Never replace missing reasoning with generated reasoning.

---

# AI PROVIDER NEUTRALITY

Core contracts MUST NOT depend on a specific vendor.

Examples of potentially monitored systems include:

```text
OpenAI / ChatGPT / Codex
Anthropic / Claude
Google / Gemini
xAI / Grok
Meta / Llama
Mistral
DeepSeek
Ollama
llama.cpp
LM Studio
local inference systems
future unknown providers
```

Vendor adapters MAY contain vendor-specific logic.

Core evidence semantics MUST remain vendor-neutral.

Rule:

```text
ADAPTER_SPECIFICITY
        !=
CORE_SCHEMA_SPECIFICITY
```

Do not design universal evidence contracts around one provider's API shape.

---

# FRAMEWORK NEUTRALITY

Potential integration targets:

```text
LLM APIs
agent frameworks
RAG systems
local inference
CLI software
desktop applications
servers
microservices
databases
robotics
scientific workflows
human-in-the-loop workflows
distributed systems
```

Possible integration modes:

```text
SDK
adapter
middleware
hook
sidecar
proxy
event bridge
external observer
```

Every integration MUST declare its observation boundary.

---

# OBSERVATION BOUNDARY

Never claim visibility beyond collector capability.

Examples:

```text
API_ADAPTER
observes:
    request
    response
    metadata supplied by provider

does_not_observe:
    provider internal execution
    hidden infrastructure
    undocumented internal reasoning
```

An observation boundary is evidence metadata.

It is not documentation trivia.

---

# IDENTITY

Identity MUST be evidence-backed.

Never silently infer:

```text
IP -> person
API key -> legal identity
hostname -> physical device
model alias -> immutable model version
repository name -> source revision
process name -> executable identity
username -> human identity
```

If inference is performed:

```text
CLASS=DERIVED
SOURCE_REFERENCES=REQUIRED
METHOD=REQUIRED
```

Cryptographic content identity SHOULD use explicit algorithm labels:

```text
sha256:<digest>
```

not:

```text
<unlabeled-digest>
```

---

# HASHING

Hash semantics MUST define exact bytes.

Requirements:

```text
explicit algorithm
explicit canonicalization
explicit encoding
explicit excluded fields
reproducible computation
no hidden normalization
```

Self-referential digest fields MUST NOT participate in their own hash input.

A mismatch MUST remain a mismatch.

Never automatically repair evidence until hashes pass.

---

# CANONICALIZATION

Canonicalization applies to PROVENANCE evidence representation.

It does NOT imply that monitored systems are deterministic.

Required eventual specification:

```text
encoding
object ordering
numeric representation
string representation
escaping
whitespace
null representation
binary references
extension semantics
self-hash exclusion
schema version
```

Canonicalization MUST be versioned when semantics stabilize.

Do not create incompatible per-adapter canonical formats.

---

# DETERMINISM

Required:

```text
same canonical evidence
-> same canonical bytes
-> same cryptographic identity
-> same verification result
```

NOT required:

```text
same monitored input
-> same monitored output
```

PROVENANCE MUST support observation of nondeterministic systems.

Do not convert nondeterministic historical behaviour into deterministic reconstructed behaviour.

---

# TIME

Timestamp evidence SHOULD identify relevant source/semantics.

Potential fields/concepts:

```text
event time
capture time
remote declared time
wall-clock time
monotonic time
clock source
precision
timezone
sequence number
```

Rule:

```text
WALL_CLOCK_ORDER != NECESSARILY_CAUSAL_ORDER
```

Do not manufacture total ordering for concurrent/distributed events.

If ordering is uncertain:

```text
ORDERING=UNCERTAIN
```

or equivalent explicit representation.

---

# CAUSALITY

Temporal adjacency does not prove causality.

Valid relationship vocabulary may include:

```text
previous
parent
triggered_by
input_to
output_of
derived_from
captured_from
approved_by
overrides
supersedes
```

Relationships require supporting evidence.

Forbidden inference:

```text
A_BEFORE_B
therefore
A_CAUSED_B
```

unless contract/evidence supports it.

---

# CHAIN OF CUSTODY

The system SHOULD make it possible to establish:

```text
WHAT captured
SOURCE
CAPTURE_TIME
CAPTURE_METHOD
CAPTURING_ACTOR
ARTIFACT_IDENTITY
TRANSFER_HISTORY
TRANSFORMATIONS
HANDLERS
VERIFICATION_STATUS
```

Custody history is append-only.

Corrections append.

Corrections do not erase.

---

# APPEND-ONLY HISTORY

Valid:

```text
EVENT_A
EVENT_B
EVENT_C
CORRECTION_OF_EVENT_B
```

Invalid:

```text
EVENT_A
REWRITTEN_EVENT_B
EVENT_C
```

where original `EVENT_B` disappears.

Allowed:

```text
supersession
correction
annotation
new derived evidence
```

Forbidden:

```text
silent historical replacement
```

---

# NO RETROACTIVE PROVENANCE

Historical evidence cannot be manufactured after the event.

Later reconstruction MUST be explicitly classified.

Example:

```text
TYPE=DERIVED
METHOD=RECONSTRUCTION
CREATED_AT=<reconstruction-time>
SOURCES=[...]
```

Never label a later reconstruction as contemporaneous evidence.

---

# REPRODUCTION

Replay/reproduction can establish:

```text
CURRENT_REPRODUCTION_RESULT
```

It cannot automatically establish:

```text
HISTORICAL_EXECUTION_RESULT
```

Maintain distinction:

```text
HISTORICAL_OBSERVATION
vs
LATER_REPRODUCTION
```

---

# SIGNATURES

A valid digital signature may demonstrate:

```text
holder_of_private_key_signed_exact_bytes
```

It does NOT independently demonstrate:

```text
legal identity
human intent
truth
correctness
physical location
authorization
```

Do not overclaim signature semantics.

---

# PRIVACY

Evidence integrity and evidence confidentiality are independent.

Potentially sensitive evidence:

```text
medical information
legal information
personal identifiers
credentials
API keys
prompts
source code
private documents
model responses
business data
```

Rule:

```text
OBSERVABLE != SHOULD_STORE
```

Do not collect credentials merely because they are technically observable.

Separate:

```text
integrity
identity
custody
confidentiality
authorization
retention
presentation
```

---

# PRESENTATION

Presentation is derivative.

Examples:

```text
reports
timelines
dashboards
graphs
summaries
legal exhibits
medical review interfaces
audit views
```

Presentation MUST NOT mutate source evidence.

Human-readable claims SHOULD resolve to supporting evidence where practical.

Concept:

```text
CLAIM
  ->
EVENTS
  ->
ARTIFACTS
  ->
CRYPTOGRAPHIC_IDENTITIES
```

---

# INTERPRETATION BOUNDARY

PROVENANCE MAY report:

```text
HASH_MISMATCH
SIGNATURE_INVALID
EVENT_MISSING
CHAIN_BREAK
SCHEMA_INVALID
EVIDENCE_GAP
```

PROVENANCE MUST NOT automatically convert these into:

```text
FRAUD
NEGLIGENCE
MALPRACTICE
GUILT
LIABILITY
INTENT
DECEPTION
```

Those require downstream interpretation.

Evidence first.

Interpretation downstream.

---

# TRUST MODEL

Do not assume:

```text
MONITORED_SYSTEM_TRUSTED
COLLECTOR_INFALLIBLE
PROVIDER_METADATA_TRUE
CLOCK_PERFECT
NETWORK_COMPLETE
STORAGE_PERMANENT
MODEL_SELF_REPORT_ACCURATE
HUMAN_DECLARATION_CORRECT
```

Do not assume the opposite either.

Record what evidence supports.

---

# SCHEMA EVOLUTION

Stable schema semantics MUST NOT change silently.

Potential breaking surfaces:

```text
field meaning
canonicalization
hash input
validation semantics
identity semantics
ordering semantics
extension handling
signature semantics
```

Breaking semantic changes require explicit version transition.

Unknown fields MUST follow defined extension rules.

Do not guess unknown semantics.

---

# VERSIONING

Long-lived evidence SHOULD contain sufficient metadata to interpret later.

Potential required versions:

```text
schema
canonicalization
hash algorithm
signature algorithm
adapter
recorder
verifier
```

Five-years-later verification is a primary design target.

---

# VERIFICATION

Target property:

```text
EVIDENCE_BUNDLE
+
PUBLIC_SPECIFICATION
+
INDEPENDENT_CRYPTOGRAPHIC_IMPLEMENTATION
=
VERIFIABLE_RESULT
```

PROVENANCE MUST NOT require circular trust:

```text
"PROVENANCE says PROVENANCE evidence is valid"
```

Independent verification is preferred.

---

# MANIFESTS

Manifest rules:

```text
immutable after finalization
versioned
canonical
hash-verifiable
explicit artifact references
explicit algorithms
explicit omissions
```

Never claim retention of a missing artifact.

Never claim verification not actually executed.

---

# FAILURE

Failure is evidence.

Examples:

```text
timeout
crash
disk full
collector failure
parse failure
partial write
service unavailable
signature rejection
hash mismatch
dropped event
schema mismatch
```

Never hide failure to make the evidence chain aesthetically clean.

---

# REPOSITORY DEVELOPMENT ORDER

Preferred evolution:

```text
1 evidence semantics
2 invariants
3 schemas
4 canonicalization
5 reference implementation
6 verifier
7 fixtures
8 adapters
9 presentation
```

Do not reverse this merely to obtain an impressive demo.

Do not build all future directories preemptively.

---

# CONCEPTUAL COMPONENTS

Future architecture may include:

```text
adapters/
core/
canonical/
crypto/
custody/
store/
verify/
export/
presentation/
tests/
```

These names are conceptual until implemented.

DO_NOT_CREATE_SPECULATIVE_STRUCTURE.

---

# CHANGE DISCIPLINE

Preferred patch:

```text
SMALLEST_CORRECT_CHANGE
```

Avoid:

```text
refactor noise
unrelated formatting
mass renaming
dependency churn
premature abstraction
speculative architecture
large generated rewrites
```

Five correct lines are preferable to fifty unnecessary ones.

---

# RESOURCE DISCIPLINE

Use reasoning before compute.

Prefer:

```text
targeted inspection
narrow search
specific reproduction
focused test
minimal patch
```

Avoid:

```text
speculative CI loops
repeated expensive agent runs
multi-agent loops without need
broad repository regeneration
re-running tests without new hypothesis
```

Compute expenditure is not evidence of correctness.

---

# AGENT CHANGE PROTOCOL

Before editing:

```text
1 READ AGENTS.md
2 INSPECT target files
3 IDENTIFY affected invariant(s)
4 IDENTIFY existing tests/contracts
5 DETERMINE smallest correct change
```

During editing:

```text
6 PRESERVE unrelated behaviour
7 DO NOT fabricate repository state
8 DO NOT introduce speculative abstractions
9 ADD/UPDATE focused tests where required
```

After editing:

```text
10 RUN applicable validation
11 INSPECT exact diff
12 RE-EVALUATE invariant impact
13 REPORT executed validation exactly
14 REPORT remaining uncertainty
```

---

# VALIDATION CLASSIFICATION

Agents MUST distinguish:

```text
EXECUTED
STATICALLY_INSPECTED
NOT_VALIDATED
```

Never say:

```text
tests pass
```

unless tests were executed and passed.

Never say:

```text
CI green
```

unless CI state was actually observed.

Never say:

```text
verified
```

when only static reasoning occurred.

---

# VALIDATION ESCALATION

Full relevant validation is required when modifying:

```text
canonicalization
hashing
identity
schema semantics
chain of custody
append-only history
event ordering
causality
signatures
manifests
observation boundaries
non-interference
verification
```

Validation intensity is based on:

```text
INVARIANT_IMPACT
```

not:

```text
LINES_CHANGED
```

---

# REVIEW PROTOCOL

Correctness findings SHOULD contain:

```text
REPRODUCTION
EXPECTED
ACTUAL
AFFECTED_INVARIANT
AFFECTED_LOCATION
VALIDATION_MODE=EXECUTED|STATIC
```

Prefer actionable defects.

Keep architectural suggestions separate from correctness failures.

Do not repeat fixed findings without a new failing case.

---

# CRITICAL AGENT PROHIBITIONS

```text
MUST_NOT fabricate evidence
MUST_NOT fabricate tests
MUST_NOT fabricate CI status
MUST_NOT fabricate model identity
MUST_NOT fabricate rationale
MUST_NOT fabricate timestamps
MUST_NOT fabricate causal links
MUST_NOT fabricate custody
MUST_NOT fabricate missing events
MUST_NOT silently repair evidence
MUST_NOT silently normalize raw evidence
MUST_NOT infer certainty from missing data
MUST_NOT convert declarations into verified fact
MUST_NOT rewrite history
MUST_NOT turn monitoring into control
```

---

# MACHINE DECISION TABLE

```text
IF evidence missing:
    REPORT MISSING

IF observation failed:
    REPORT FAILURE

IF value declared externally:
    CLASSIFY DECLARED

IF value directly captured:
    CLASSIFY OBSERVED

IF value computed:
    CLASSIFY DERIVED
    LINK SOURCES

IF rationale unavailable:
    RECORD NOT_OBSERVED

IF ordering uncertain:
    PRESERVE UNCERTAINTY

IF identity uncertain:
    PRESERVE UNCERTAINTY

IF canonicalization ambiguous:
    STOP CLAIMING CANONICAL COMPATIBILITY

IF hash mismatch:
    REPORT MISMATCH
    DO_NOT_REPAIR_HISTORY

IF monitored system behaves unexpectedly:
    RECORD BEHAVIOUR
    DO_NOT_CORRECT_IT THROUGH OBSERVER

IF repository contract conflicts with agent preference:
    FOLLOW REPOSITORY CONTRACT

IF unsure:
    DO_NOT_INVENT
```

---

# CURRENT BOOTSTRAP STATE

At the time this machine guidance was introduced, PROVENANCE is in early specification/bootstrap development.

Agents MUST inspect current repository state rather than assuming this section remains complete.

Foundational documents:

```text
README.md
AGENTS.md
README4AIs.md
LICENSE
```

`README.md`:

```text
human-facing project purpose and architecture
```

`AGENTS.md`:

```text
normative AI-assisted engineering constitution
```

`README4AIs.md`:

```text
machine-oriented operational digest
```

If this file conflicts with `AGENTS.md`:

```text
AGENTS.md WINS
```

---

# LONG-TERM ACCEPTANCE TEST

Assume:

```text
INCIDENT_AGE=5_YEARS
ORIGINAL_DEVELOPERS=UNAVAILABLE
ORIGINAL_MACHINE=DESTROYED
AI_PROVIDER=POSSIBLY_GONE
MONITORED_APPLICATION=POSSIBLY_UNRUNNABLE
```

Independent investigator receives retained evidence.

Architecture should permit determination of:

```text
WHAT was retained
WHAT was observed
WHAT was declared
WHAT was derived
WHAT bytes were hashed
WHAT identities are supported
WHAT identities remain uncertain
WHAT events can be ordered
WHAT events cannot be ordered
WHERE gaps exist
WHAT transformations occurred
WHO/WHAT handled evidence
WHETHER integrity verifies
WHAT PROVENANCE could observe
WHAT PROVENANCE could not observe
```

If a design decision makes these harder to answer:

```text
RECONSIDER_DESIGN
```

---

# FINAL MACHINE RULES

```text
EVIDENCE > STORY
FACT > INFERENCE
EXPLICIT_UNKNOWN > INVENTED_CERTAINTY
RAW > RECONSTRUCTED
APPEND > REWRITE
OBSERVE > INTERFERE
VERIFY > TRUST
MINIMAL > SPECULATIVE
```

Final invariant:

```text
IF_WE_DO_NOT_KNOW:
    RECORD_THAT_WE_DO_NOT_KNOW
```

Project maxim:

```text
HERE_IS_THE_EVIDENCE
WE_KNOW_EXACTLY_WHAT_YOU_DID
TELL_IT_TO_THE_JUDGE
```
