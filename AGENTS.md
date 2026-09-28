# PROVENANCE Agent Constitution

## Canonical Engineering Constitution — v0.1

This document governs **all AI-assisted engineering activity** inside the `QSOLKCB/PROVENANCE` repository.

It applies to:

- ChatGPT;
- Codex;
- Claude;
- Gemini;
- local models;
- coding agents;
- automated refactoring systems;
- generated patches; and
- human operators accepting AI-generated changes.

This is the **constitutional layer of the repository**.

All code generation, testing, refactoring, schema design, release preparation, commits, adapters, cryptographic structures, and architectural decisions must obey this file.

This is not a collection of suggestions.

This is the project contract.

---

# Core Mission

PROVENANCE exists to answer:

```text
WHO
did WHAT
WHEN
WHERE
WHY
and HOW
```

using retained, independently verifiable evidence.

Its purpose is to record the behaviour of other systems without silently changing that behaviour.

The central boundary is:

```text
observe
→ record
→ bind
→ preserve
→ verify
→ present
```

Never:

```text
observe
→ reinterpret
→ modify
→ control
→ rewrite history
```

---

# Core System Principle

For evidence under PROVENANCE control:

```text
same canonical evidence
→ same canonical bytes
→ same cryptographic identity
→ same verification result
```

This requirement applies to **PROVENANCE evidence representation**.

It does **not** require the monitored system itself to be deterministic.

PROVENANCE must be capable of recording:

- nondeterministic systems;
- asynchronous systems;
- concurrent systems;
- stochastic AI models;
- distributed systems;
- human decisions;
- external services;
- partial failures; and
- incomplete observations.

without rewriting them into deterministic fiction.

---

# Core Values

In priority order:

1. Evidence Fidelity
2. Non-Interference
3. Chain of Custody
4. Cryptographic Integrity
5. Explicit Observation Boundaries
6. Deterministic Evidence Representation
7. Independent Verification
8. Framework Neutrality
9. Minimal Complexity
10. Reproducibility
11. Privacy Separation
12. Scientific Transparency

If convenience conflicts with evidence fidelity:

**evidence fidelity wins.**

---

# 0. Operating Model

## Rules

All changes must be:

- minimal;
- single-purpose;
- reviewable;
- testable where applicable;
- explicit about invariant impact.

Do not perform unrelated refactors while implementing another change.

Do not introduce infrastructure merely because it may become useful later.

Do not build speculative abstractions before the evidence contract requires them.

Do not assume:

- direct commits to `main`;
- feature branches;
- pull-request-first development;
- release cadence;
- deployment topology.

Follow the workflow explicitly requested by the repository owner or established by repository configuration.

---

# 1. Primary Architectural Boundary — HARD INVARIANT

PROVENANCE is an observer.

The monitored system is the subject.

These roles must never silently collapse.

Conceptually:

```text
MONITORED SYSTEM
      │
      │ observable activity
      ▼
   ADAPTER
      │
      ▼
  RECORDER
      │
      ▼
EVIDENCE STORE
      │
      ▼
  VERIFIER
      │
      ▼
PRESENTATION
```

Each layer must remain separable.

## Fundamental rule

```text
evidence collection != system control
```

---

# 2. Non-Interference Law

PROVENANCE MUST NOT intentionally alter the semantic behaviour of the system it observes.

## Forbidden

Instrumentation must not silently:

- rewrite prompts;
- rewrite model outputs;
- modify tool arguments;
- modify tool results;
- change model parameters;
- reorder monitored operations;
- retry failed monitored operations merely to obtain cleaner evidence;
- suppress monitored actions;
- inject policy decisions;
- replace application decisions;
- change external side effects;
- convert failure into success;
- convert success into failure;
- manufacture missing events;
- manufacture missing metadata;
- normalize raw evidence destructively.

PROVENANCE may incur unavoidable observation overhead.

That overhead must never be misrepresented as zero-cost observation.

Where measurable, significant observer effects should themselves be recordable.

---

# 3. Evidence Classification Law

All meaningful information must be classified according to how it entered the evidence system.

The minimum evidence classes are:

```text
OBSERVED
DECLARED
DERIVED
```

## OBSERVED

Directly captured from the monitored environment.

Examples:

- request bytes;
- response bytes;
- tool invocation;
- process exit status;
- network response;
- file contents;
- model output;
- runtime event;
- operating-system metadata.

Observed does not automatically mean true.

It means PROVENANCE directly observed the value presented by the source.

---

## DECLARED

Information asserted by another actor or system.

Examples:

- a provider declaring a model name;
- a user supplying an identity;
- an application supplying a case number;
- an API reporting its own version;
- a model supplying an explanation;
- an operator supplying a location.

A declaration MUST NOT silently become an independently verified fact.

---

## DERIVED

Information calculated from other retained evidence.

Examples:

- SHA-256 digests;
- canonical record hashes;
- Merkle roots;
- elapsed durations;
- verification results;
- dependency graphs;
- reconstructed timelines;
- replay comparisons.

Derived evidence MUST identify its source evidence.

---

# 4. Raw Evidence Law

Original evidence must remain distinguishable from every transformation performed upon it.

## Required distinction

```text
raw artifact
     │
     ├── normalized derivative
     ├── canonical record
     ├── index
     ├── report
     ├── visualization
     └── analysis
```

A transformation creates a derivative.

It does not replace its source.

## Forbidden

Never silently:

- rewrite raw evidence;
- prettify raw evidence in place;
- normalize line endings in the original;
- reorder original fields;
- remove inconvenient fields;
- repair malformed evidence;
- replace invalid evidence with corrected evidence.

If correction is necessary:

```text
original evidence
        ↓
correction record
        ↓
new derivative
```

The original remains retained and identifiable.

---

# 5. Chain-of-Custody Law

Evidence custody is part of the evidence.

Where applicable, PROVENANCE should make it possible to determine:

1. what was captured;
2. where it originated;
3. when capture occurred;
4. how capture occurred;
5. who or what performed capture;
6. which artifact was retained;
7. how that artifact was identified;
8. where it moved;
9. which transformations occurred;
10. who or what performed those transformations;
11. whether integrity still verifies.

Custody events are append-only historical facts.

A later event must never rewrite an earlier custody event.

---

# 6. Cryptographic Identity Law

Cryptographic identity must refer to exact evidence representations.

## Rules

- content hashes identify content;
- event identifiers and content hashes are distinct concepts;
- cryptographic identities must be reproducible;
- algorithms must be explicitly identified;
- hashes must be calculated over precisely defined bytes;
- self-referential hash fields must be excluded from their own digest computation;
- hash mismatches must never be silently ignored;
- identifiers must never be reconstructed from insufficient information.

Example:

```text
sha256:<digest>
```

is preferable to an unlabeled digest whose algorithm must be guessed.

---

# 7. Canonicalization Law

Canonicalization is part of the evidence contract.

It must never be an implementation accident.

## Required

Canonicalization rules must eventually define, at minimum:

- encoding;
- object-key ordering;
- numeric representation;
- string representation;
- escaping;
- whitespace;
- null handling;
- binary artifact references;
- extension handling;
- self-hash exclusion;
- schema version.

## Critical rule

Do not create an ad hoc canonical format independently inside individual adapters.

There must be one project-defined canonicalization contract per schema version.

Until that contract is formally frozen:

**do not claim cross-language canonical compatibility.**

---

# 8. Identity Must Not Be Inferred

Identity is evidence.

Do not reconstruct actor identity from convenient surrounding information unless the reconstruction itself is explicitly represented as DERIVED evidence.

Examples of prohibited silent inference:

```text
IP address → human identity
API key → legal person
process name → software version
model alias → immutable model revision
repository path → exact source revision
hostname → physical machine
```

If the source only proves:

```text
api_key_id = X
```

record exactly that.

Do not upgrade it to:

```text
human_actor = Alice
```

without separate evidence.

---

# 9. Time Law

Time is evidence and must be treated as such.

A timestamp without a source is incomplete provenance.

Where relevant, records should distinguish:

- wall-clock timestamp;
- clock source;
- timezone or UTC representation;
- precision;
- monotonic time;
- process-local sequence;
- remote timestamp;
- externally declared timestamp;
- capture timestamp;
- event timestamp.

## Critical rule

Wall-clock time alone must not automatically define causal order.

Distributed systems may contain:

- skew;
- drift;
- latency;
- concurrent events;
- reordered delivery.

Where exact ordering cannot be proven, PROVENANCE must not manufacture an exact ordering.

---

# 10. Causality Law

Temporal proximity is not automatically causality.

Events may explicitly relate through fields equivalent to:

```text
parent
previous
triggered_by
input_to
output_of
derived_from
captured_from
approved_by
overrides
supersedes
```

Such relationships must be supported by evidence.

Do not infer:

```text
A happened before B
```

therefore:

```text
A caused B
```

unless the evidence contract supports that relationship.

---

# 11. “Why” Law

PROVENANCE does not possess magical access to hidden reasoning.

For AI systems, “why” means the observable causal and contextual evidence available around an action.

This may include:

- instructions;
- prompts;
- retrieved documents;
- application state;
- model configuration;
- model identity;
- tool availability;
- tool calls;
- tool results;
- policy results;
- validation results;
- explicit decision codes;
- prior events;
- human approval;
- explicit rationale exposed by the monitored system.

## Absolute prohibition

Never manufacture hidden chain-of-thought.

Never create a post-hoc rationale and represent it as the reason an AI acted.

If a system supplies a rationale, record it as supplied evidence.

If no rationale was exposed:

```text
rationale not observed
```

is valid evidence.

Inventing one is not.

---

# 12. Observation Boundary Law

Every integration has limits.

Those limits must be explicit.

An adapter may observe:

```text
application-level requests
```

while being unable to observe:

```text
provider-internal execution
```

Another collector may observe:

```text
operating-system process activity
```

while being unable to observe:

```text
encrypted request contents
```

Do not claim visibility beyond the actual collection boundary.

## Required principle

```text
unknown != absent
```

and:

```text
not observed != did not happen
```

---

# 13. Evidence Gap Law

A trustworthy evidence system must preserve uncertainty.

The following states are different:

```text
NO EVENT OCCURRED
```

```text
NO EVENT WAS OBSERVED
```

```text
COLLECTION FAILED
```

```text
EVIDENCE IS MISSING
```

```text
EVENT MAY HAVE OCCURRED DURING A KNOWN GAP
```

They must never be silently collapsed.

Collector failures, dropped events, unavailable sources, corrupted artifacts, interrupted streams, and unverifiable intervals must remain visible.

A clean-looking timeline is not more important than an honest timeline.

---

# 14. Failure Law

Failure is evidence.

Where observable, retain facts such as:

- process crash;
- timeout;
- collector failure;
- parse failure;
- partial write;
- disk-full condition;
- unavailable service;
- rejected signature;
- hash mismatch;
- incomplete event;
- dropped message;
- schema incompatibility.

Do not repair history merely to make verification pass.

---

# 15. Framework Neutrality Law

The core evidence model must not depend on one vendor or AI framework.

Adapters may support framework-specific concepts.

The canonical evidence contract must remain framework-neutral.

Potential integrations include:

- OpenAI;
- Anthropic;
- Google;
- xAI;
- Ollama;
- llama.cpp;
- local inference engines;
- agent frameworks;
- RAG pipelines;
- conventional software;
- operating-system processes;
- APIs;
- databases;
- robotics;
- scientific workflows.

Vendor-specific fields may be retained.

They must not dictate the universal schema unnecessarily.

---

# 16. Adapter Law

Adapters translate observable framework behaviour into PROVENANCE records.

They do not redefine the behaviour they observe.

## Adapter responsibilities

An adapter may:

- capture events;
- identify sources;
- retain raw provider payloads;
- map known fields;
- produce canonical event envelopes;
- report unsupported information;
- report collection failures.

An adapter must not:

- invent missing fields;
- fabricate exact model revisions;
- guess identities;
- manufacture tool results;
- convert uncertain observations into certain claims;
- remove inconvenient provider data merely to fit the canonical schema.

When provider-specific data does not map cleanly:

**retain it rather than silently discard it.**

---

# 17. Presentation Separation Law

Evidence and presentation are separate layers.

A report may say:

```text
The model called tool X three times.
```

But that statement is a derived presentation of underlying events.

The report is not the original evidence.

Likewise:

- timelines;
- dashboards;
- graphs;
- summaries;
- legal exhibits;
- medical reviews;
- audit reports;
- human-readable explanations

must remain distinguishable from source evidence.

---

# 18. Interpretation Law

PROVENANCE records evidence.

It does not automatically decide:

- negligence;
- malpractice;
- guilt;
- innocence;
- liability;
- compliance;
- truth;
- intent;
- correctness;
- ethical acceptability.

Those judgments belong downstream.

A verifier may correctly state:

```text
artifact hash mismatch
```

It must not silently transform that into:

```text
fraud occurred
```

The first is evidence.

The second requires interpretation.

---

# 19. Privacy Law

Integrity and confidentiality are different properties.

A cryptographic hash does not make sensitive information safe to publish.

Evidence may contain:

- medical records;
- legal communications;
- personal identifiers;
- source code;
- credentials;
- API keys;
- confidential prompts;
- proprietary documents;
- private model outputs.

## Rules

Do not introduce unnecessary sensitive information into evidence records.

Do not log credentials merely because they are observable.

Do not confuse:

```text
evidence completeness
```

with:

```text
collect absolutely everything
```

The system must eventually support separation of:

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

# 20. Schema Law

Schemas are evidence contracts.

Once a schema version is declared stable:

- fields must not silently change meaning;
- canonicalization must not silently change;
- validation semantics must not silently change;
- hashing semantics must not silently change;
- incompatible changes require a new schema version.

Unknown extension fields must be handled according to explicit schema rules.

Never guess schema semantics from field names.

---

# 21. Version Law

Every evidence format capable of long-term retention must carry sufficient version information to determine how it should be interpreted.

This may include:

- schema version;
- canonicalization version;
- hashing algorithm;
- signature algorithm;
- adapter version;
- recorder version;
- verifier version.

Do not assume the verifier used five years from now will share today's implementation behaviour.

---

# 22. Verification Law

Verification must be independently reproducible wherever practical.

A verification result should be derived from evidence.

It must not depend upon hidden application state.

Target principle:

```text
evidence bundle
+
public specification
+
ordinary cryptographic implementation
=
independent verification
```

The long-term goal is that an investigator should not need to trust PROVENANCE merely because PROVENANCE says its own evidence is valid.

---

# 23. Receipt and Manifest Law

Receipts and manifests are evidence artifacts.

When implemented, they must be:

- immutable once finalized;
- schema-versioned;
- canonically representable;
- cryptographically verifiable;
- explicit about referenced artifacts;
- explicit about algorithms;
- explicit about missing artifacts.

A manifest must never claim possession of an artifact that was not actually retained.

A receipt must never claim verification that was not actually performed.

---

# 24. Signature Law

Digital signatures may establish that a holder of a particular signing key signed particular bytes.

They do not automatically establish:

- legal identity;
- human intent;
- truth of signed statements;
- correctness of evidence;
- physical location.

Do not overstate what a signature proves.

Key identity and legal identity must remain separate unless independently bound by evidence.

---

# 25. Append-Only History Law

Historical corrections must append.

They must not rewrite.

Conceptually:

```text
EVENT A
EVENT B
EVENT C
CORRECTION OF B
```

not:

```text
EVENT A
NEW-B
EVENT C
```

with the original `B` silently erased.

Supersession is allowed.

Erasure of history masquerading as correction is not.

---

# 26. Minimal Diff Discipline

Every patch should be the smallest viable change that satisfies its purpose.

## Required

- no refactor noise;
- no unrelated formatting;
- no speculative restructuring;
- no dependency churn without need;
- no mass renaming without explicit purpose;
- no architecture astronautics.

If five lines solve the problem correctly, do not build a framework around them.

---

# 27. Dependency Law

Prefer:

```text
standard library
→ small established dependency
→ custom dependency
```

in that order where practical.

Dependencies affecting:

- canonicalization;
- hashing;
- signatures;
- serialization;
- evidence storage;
- verification

require particular scrutiny because they can become part of the long-term evidence contract.

Dependencies must not silently define protocol semantics.

---

# 28. Resource Discipline

Do not substitute brute-force agent activity for engineering judgment.

Prefer:

- targeted file inspection;
- narrow searches;
- local reasoning;
- focused tests;
- exact reproductions;
- minimal patches.

Avoid:

- repeated speculative CI runs;
- broad rewrites;
- unnecessary multi-agent loops;
- regenerating large files to change small details;
- repeatedly re-running expensive tooling without a new hypothesis.

Compute expenditure is not evidence of engineering quality.

---

# 29. Test Discipline

Tests should target observable invariants.

Important classes include:

- canonicalization tests;
- hash-stability tests;
- evidence-preservation tests;
- tamper-detection tests;
- chain-continuity tests;
- schema validation tests;
- adapter fidelity tests;
- observation-boundary tests;
- evidence-gap tests;
- non-interference tests;
- replay tests where replay is meaningful;
- cross-language fixtures where portability is claimed.

Tests must not merely test that the implementation agrees with itself.

Where possible, use fixed independent fixtures.

---

# 30. Validation Escalation Law

Validation requirements are determined by **invariant impact**, not by patch size.

A one-line change to hashing may be more significant than a thousand-line documentation patch.

## Full validation is mandatory when changing:

### Canonicalization

- canonical JSON;
- serialization;
- normalization;
- byte representation.

### Identity

- event identity;
- artifact identity;
- hash inputs;
- identity derivation.

### Cryptography

- hashing;
- signatures;
- manifests;
- Merkle structures;
- verification.

### Chain of Custody

- custody events;
- lineage;
- transformations;
- append-only semantics.

### Schema

- evidence fields;
- field semantics;
- compatibility;
- versioning.

### Ordering

- event ordering;
- sequence handling;
- causality;
- concurrency representation.

### Non-Interference

- adapters;
- instrumentation;
- interception;
- proxies;
- middleware behaviour.

### Verification

- integrity checks;
- receipt verification;
- bundle validation.

---

# 31. Validation Honesty Law

Never claim tests were executed unless they were executed.

Distinguish:

```text
EXECUTED
```

from:

```text
STATICALLY INSPECTED
```

from:

```text
NOT VALIDATED
```

If a required test suite does not yet exist, state that fact.

Do not fabricate green CI.

Do not fabricate test output.

Do not convert:

```text
I see no obvious problem
```

into:

```text
validated
```

---

# 32. Bootstrap Validation Rule

During the repository's early specification phase, some validation infrastructure may not yet exist.

Agents must not invent commands merely to satisfy this document.

For documentation-only changes:

- inspect the exact diff;
- check internal consistency;
- check referenced file names;
- check terminology;
- check Markdown structure;
- verify that normative language does not contradict existing constitutional rules.

As executable code appears, validation commands must become repository-defined and reproducible.

---

# 33. Security Boundary

PROVENANCE is an evidence system.

It must not gradually become a covert security-policy engine merely because enforcement appears convenient.

Security controls may protect:

- evidence storage;
- signing keys;
- confidential artifacts;
- access to evidence;
- verifier integrity.

Those protections must remain conceptually separate from controlling the monitored system.

---

# 34. Monitored-System Trust Law

Never assume the monitored system is trustworthy.

Never assume it is malicious either.

PROVENANCE should record what can be demonstrated.

The monitored system may:

- lie;
- crash;
- omit data;
- report stale metadata;
- expose inconsistent identifiers;
- behave incorrectly.

Such behaviour is itself potentially relevant evidence.

Do not silently “repair” it.

---

# 35. Collector Trust Law

Never assume the collector is infallible.

Evidence records should eventually allow investigators to reason about:

- collector version;
- collector configuration;
- collector identity;
- collection boundaries;
- collection failures;
- known limitations.

PROVENANCE must be capable of documenting uncertainty about its own observations.

---

# 36. Evidence Versus Claim Law

Every important claim should ultimately be reducible to evidence.

Conceptually:

```text
claim
  ↓
supporting event(s)
  ↓
artifact(s)
  ↓
cryptographic identity
```

If that chain cannot be established, the claim must not masquerade as cryptographically proven fact.

---

# 37. Human Actions Are Events Too

Humans must not become invisible simply because the project focuses on AI.

Where observable and appropriate, provenance may include:

- approval;
- rejection;
- override;
- edit;
- submission;
- review;
- acknowledgement;
- release authorization.

Do not attribute an automated decision to a human merely because a human was somewhere in the workflow.

Likewise, do not attribute a human decision to the AI merely because an AI produced preceding material.

---

# 38. Reproduction Law

Reproduction can strengthen evidence.

It does not replace historical evidence.

A later replay demonstrating:

```text
the same input currently produces X
```

does not prove:

```text
the historical system produced X
```

unless historical evidence establishes that connection.

Always distinguish:

```text
historical observation
```

from:

```text
later reproduction
```

---

# 39. No Retroactive Provenance

PROVENANCE must never manufacture historical evidence after the fact and present it as contemporaneous evidence.

Later reconstruction is allowed only when clearly labeled as:

```text
DERIVED
```

or equivalent.

A reconstruction must identify its source material and reconstruction time.

---

# 40. No Silent Data Loss

If information cannot be represented in a canonical event without loss:

retain the source artifact and reference it.

Do not truncate evidence merely to make the schema convenient.

Lossy transformation must be explicit.

---

# 41. Repository Evolution Rule

Do not create large architecture prematurely.

The project should evolve in this order:

```text
evidence semantics
→ invariants
→ schemas
→ canonicalization
→ reference implementation
→ verifier
→ fixtures
→ adapters
→ presentation
```

Do not reverse this ordering merely because UI or framework integrations are easier to demonstrate.

The evidence contract comes first.

---

# 42. Proposed Architectural Direction

Until replaced by implemented repository structure, development should conceptually preserve these responsibilities:

```text
adapters/
    framework-specific observation

core/
    event and evidence semantics

canonical/
    deterministic representation

crypto/
    hashes, signatures, cryptographic bindings

custody/
    chain-of-custody records

store/
    evidence persistence

verify/
    independent validation

export/
    evidence bundles and manifests

presentation/
    human-readable derived views

tests/
    invariant and compatibility fixtures
```

This is architectural direction, not permission to create all directories immediately.

Create components only when required by the current phase.

---

# 43. Escalation Rule

If a proposed change alters any of the following:

- evidence meaning;
- observed/declared/derived classification;
- canonicalization;
- hashing semantics;
- identity;
- custody;
- append-only history;
- timestamp semantics;
- causal ordering;
- signatures;
- schema compatibility;
- observation boundaries;
- non-interference guarantees;
- verification semantics;

the agent must explicitly identify the invariant being changed before broad implementation proceeds.

These are constitutional surfaces.

They must never drift accidentally.

---

# 44. Agent Behaviour Law

When operating inside this repository, an AI agent must:

1. inspect before editing;
2. distinguish fact from inference;
3. preserve existing contracts;
4. avoid invented repository state;
5. make the smallest sufficient change;
6. report validation accurately;
7. retain uncertainty where uncertainty exists;
8. avoid speculative infrastructure;
9. never fabricate evidence;
10. never rewrite inconvenient history.

If the repository contradicts an assumption:

**the repository wins.**

---

# 45. Review Standard

Reviews should focus first on correctness defects affecting:

- evidence fidelity;
- non-interference;
- custody;
- cryptographic identity;
- canonicalization;
- verification;
- schema compatibility;
- observation boundaries;
- historical integrity.

Architectural suggestions should remain separate from correctness defects.

A review finding should preferably state:

```text
reproduction
expected behaviour
actual behaviour
affected invariant
affected lines
executed or statically inferred
```

Do not repeatedly report previously fixed findings without a new failing case.

---

# 46. Release Integrity

A release claiming a particular evidence contract must bind that claim to an exact repository state.

Where releases eventually contain normative schemas or protocol behaviour, releases should identify:

- exact version;
- source revision;
- schema versions;
- canonicalization versions;
- verification behaviour;
- compatibility status.

Tags must not be treated as sufficient evidence when the exact commit can also be recorded.

---

# 47. Long-Term Test

Every major architectural decision should survive this thought experiment:

```text
An incident occurred five years ago.

The original developers are unavailable.
The original machine no longer exists.
The AI provider may no longer exist.
The monitored application may no longer run.

An independent investigator receives
the retained PROVENANCE evidence.
```

Can the investigator determine:

- what was actually retained;
- what was merely declared;
- what was derived later;
- which bytes were hashed;
- which events can be ordered;
- which events cannot be ordered;
- which actors can be identified;
- which identities remain uncertain;
- where evidence gaps exist;
- which transformations occurred;
- whether artifacts changed;
- whether verification succeeds;
- what PROVENANCE itself could and could not observe?

If the architecture makes those questions harder to answer, reconsider it.

---

# Final Law

PROVENANCE does not exist to produce a persuasive story.

It exists to preserve a defensible record.

Therefore:

```text
Do not clean the evidence.
Do not improve the evidence.
Do not complete the evidence.
Do not reinterpret the evidence.
Do not invent the evidence.

Capture it.
Identify it.
Bind it.
Preserve it.
Verify it.
Present it honestly.
```

And above all:

```text
If we do not know,
the record must say that we do not know.
```

---

# Project Maxim

> **Here's the evidence. We know exactly what you did. Tell it to the judge.**
