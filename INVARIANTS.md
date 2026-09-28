# PROVENANCE System Invariants — v0.1

Formal invariants governing the `QSOLKCB/PROVENANCE` evidence, chain-of-custody, and verification system.

Every implementation, adapter, recorder, verifier, evidence store, export format, and presentation layer must preserve these invariants.

Violation of any mandatory invariant constitutes a system-level defect.

These invariants govern **PROVENANCE itself**.

They do not require the system being observed to be deterministic, correct, truthful, safe, reproducible, or well behaved.

---

# 1. Evidence Fidelity

**INV-EVD-1 — Evidence is never silently rewritten.**

Original retained evidence must remain distinguishable from every transformation, normalization, correction, summary, report, or derivative created from it.

---

**INV-EVD-2 — Raw evidence is immutable after finalization.**

Once an artifact has been finalized and assigned a cryptographic content identity, that artifact must not be modified in place.

A changed artifact is a new artifact.

---

**INV-EVD-3 — Corrections append.**

Corrections, annotations, supersessions, and clarifications must create new records.

They must not erase or replace the historical record they correct.

---

**INV-EVD-4 — Missing evidence remains missing.**

Missing content must not be reconstructed, guessed, interpolated, regenerated, or synthesized and then represented as original evidence.

---

**INV-EVD-5 — Evidence presentation never changes evidence semantics.**

Rendering evidence as a report, timeline, graph, dashboard, exhibit, summary, or other presentation must not modify the meaning or identity of the underlying evidence.

---

# 2. Evidence Classification

Every meaningful evidence assertion must have a provenance class.

Minimum classes are:

```text
OBSERVED
DECLARED
DERIVED
```

---

**INV-CLS-1 — Every evidentiary assertion has a class.**

A factual value represented by PROVENANCE must be attributable to one of:

```text
OBSERVED
DECLARED
DERIVED
```

unless a later schema version explicitly defines another class.

---

**INV-CLS-2 — OBSERVED means directly captured.**

An `OBSERVED` value must have been directly captured by the stated observation mechanism.

Observed does not mean independently true.

It means that PROVENANCE observed that value being presented or produced.

---

**INV-CLS-3 — DECLARED is never silently promoted.**

Externally asserted metadata must remain `DECLARED` unless independent evidence establishes another classification.

Example:

```text
provider reports model = X
```

does not automatically mean:

```text
PROVENANCE independently verified model = X
```

---

**INV-CLS-4 — DERIVED evidence identifies its inputs.**

Every derived artifact or assertion must identify the evidence from which it was derived.

---

**INV-CLS-5 — Classification is preserved through export.**

Evidence classification must survive serialization, storage, bundling, transfer, verification, and presentation.

---

# 3. Non-Interference

PROVENANCE is an observer.

It is not a hidden controller.

---

**INV-NIF-1 — Observation does not intentionally alter monitored semantics.**

PROVENANCE instrumentation must not intentionally change the semantic inputs, outputs, decisions, or side effects of the monitored system.

---

**INV-NIF-2 — Monitoring failure must not silently become control flow.**

Collector failure must not silently:

- retry monitored operations;
- suppress monitored operations;
- modify monitored operations;
- substitute outputs;
- convert failure into success; or
- convert success into failure.

Any such behavior must originate from the monitored system or be explicitly declared as part of the integration contract.

---

**INV-NIF-3 — PROVENANCE does not become a policy authority.**

The monitored system must not be required to obtain permission from PROVENANCE merely because PROVENANCE observes it.

---

**INV-NIF-4 — Observer effects are not denied.**

If instrumentation measurably affects timing, latency, resource use, ordering, or other observable properties, the implementation must not falsely claim zero observer effect.

---

# 4. Observation Boundaries

Every collector has limits.

Those limits are evidence.

---

**INV-OBS-1 — Observation scope is explicit.**

Every adapter or collector must have an identifiable observation boundary.

---

**INV-OBS-2 — No observation beyond capability.**

PROVENANCE must not claim direct observation of information inaccessible to the collector.

---

**INV-OBS-3 — Unknown is distinct from absent.**

```text
UNKNOWN != ABSENT
```

---

**INV-OBS-4 — Not observed is distinct from did not occur.**

```text
NOT_OBSERVED != DID_NOT_OCCUR
```

---

**INV-OBS-5 — Collector limitations remain attributable.**

Evidence must remain capable of being associated with the collector, adapter, or observation mechanism that produced it.

---

# 5. Evidence Gaps

A trustworthy record preserves its gaps.

---

**INV-GAP-1 — Gap states remain distinct.**

At minimum, the following states must never be silently collapsed:

```text
NO_EVENT_OCCURRED
NO_EVENT_OBSERVED
COLLECTION_FAILED
EVIDENCE_MISSING
UNKNOWN
EVENT_MAY_HAVE_OCCURRED_DURING_GAP
```

---

**INV-GAP-2 — Collection failure is evidence.**

If collection fails and that failure is observable, the failure must remain representable as part of the record.

---

**INV-GAP-3 — Continuity must not be manufactured.**

An event chain must not imply uninterrupted observation across a known or suspected evidence gap.

---

**INV-GAP-4 — Partial evidence remains partial.**

A partially observed event must not be represented as completely observed.

---

# 6. Cryptographic Identity

Cryptographic identity binds exact representations.

---

**INV-ID-1 — Content identity identifies exact content.**

A content hash must correspond to precisely defined bytes.

---

**INV-ID-2 — Hash algorithms are explicit.**

Cryptographic identities must identify the algorithm used.

Preferred form:

```text
sha256:<digest>
```

rather than an unlabeled digest.

---

**INV-ID-3 — Identity does not depend on mutable naming.**

Filename, path, display label, database row number, or UI identifier alone must not serve as cryptographic content identity.

---

**INV-ID-4 — Identity is never silently inferred.**

Identity claims unsupported by direct evidence must be represented as derived or declared rather than silently asserted as verified identity.

---

**INV-ID-5 — Content change produces identity change.**

If bytes covered by a content identity change, the cryptographic identity must change.

---

# 7. Canonicalization

Canonicalization defines evidence representation.

It does not rewrite raw evidence.

---

**INV-CAN-1 — Canonicalization is versioned.**

Every stable canonicalization contract must have an identifiable version.

---

**INV-CAN-2 — Same canonical evidence produces the same canonical bytes.**

Given the same:

```text
schema version
canonicalization version
evidence values
```

the canonical representation must be byte-identical.

---

**INV-CAN-3 — Canonicalization rules are explicit.**

Canonicalization semantics must define applicable rules for:

```text
encoding
object-key ordering
numbers
strings
escaping
whitespace
nulls
extensions
binary references
excluded fields
```

---

**INV-CAN-4 — Raw artifacts are not destructively canonicalized.**

Canonical representation creates a canonical derivative or envelope.

It must not overwrite the raw artifact.

---

**INV-CAN-5 — Adapter-specific canonicalization cannot redefine the core contract.**

Adapters may map provider-specific data into the canonical model.

They must not silently create incompatible canonical semantics.

---

# 8. Hashing Integrity

---

**INV-HSH-1 — Same canonical bytes produce the same digest.**

For a fixed cryptographic algorithm:

```text
same bytes
→ same digest
```

---

**INV-HSH-2 — Self-referential hash fields are excluded.**

A field containing an artifact's own digest must not participate in computing that digest unless an explicitly defined non-self-referential scheme exists.

---

**INV-HSH-3 — Hash mismatch remains a mismatch.**

A failed digest comparison must not trigger silent mutation of evidence until verification succeeds.

---

**INV-HSH-4 — Hash input is reproducible.**

An independent verifier must be able to determine exactly which bytes were hashed.

---

# 9. Chain of Custody

Custody history is evidence.

---

**INV-CUS-1 — Custody history is append-only.**

Existing custody events cannot be silently replaced or reordered.

---

**INV-CUS-2 — Transformations create lineage.**

Any transformation of evidence must retain a relationship to its source artifact.

---

**INV-CUS-3 — Transfer does not erase origin.**

Moving evidence between:

```text
processes
hosts
stores
systems
organizations
formats
```

must not destroy its known origin information.

---

**INV-CUS-4 — Custody claims require evidence.**

A record must not claim that an actor possessed, handled, transferred, or verified evidence unless the claim is supported by retained evidence or clearly marked as declared.

---

**INV-CUS-5 — Custody uncertainty remains uncertainty.**

Unknown handlers or missing custody intervals must not be silently filled.

---

# 10. Historical Integrity

---

**INV-HIS-1 — No retroactive provenance.**

Evidence created after an event must not be represented as evidence captured contemporaneously with that event.

---

**INV-HIS-2 — Reconstruction is DERIVED.**

Later reconstruction of historical activity must be classified as derived evidence and identify:

```text
reconstruction time
source evidence
method
```

---

**INV-HIS-3 — Original history remains available after correction.**

A correction may supersede an earlier claim.

It must not erase the existence of the earlier claim.

---

**INV-HIS-4 — Historical artifacts retain their historical identities.**

Re-serialization or migration must not silently replace the identity of historical source artifacts.

---

# 11. Time

Time itself has provenance.

---

**INV-TIM-1 — Timestamps have identifiable semantics.**

Where a timestamp affects interpretation, its role must be distinguishable.

Examples:

```text
EVENT_TIME
CAPTURE_TIME
REMOTE_DECLARED_TIME
RECEIPT_TIME
```

---

**INV-TIM-2 — Time source must not be silently assumed.**

A timestamp supplied by an external system must not automatically be represented as locally observed clock time.

---

**INV-TIM-3 — Wall-clock order does not prove causality.**

```text
A.timestamp < B.timestamp
```

does not independently prove:

```text
A caused B
```

---

**INV-TIM-4 — Uncertain ordering remains uncertain.**

Concurrent, distributed, skewed, or partially ordered events must not be forced into a false total order.

---

**INV-TIM-5 — Sequence and time are distinct concepts.**

A sequence number must not automatically be interpreted as wall-clock time, and wall-clock time must not automatically be interpreted as sequence.

---

# 12. Causality

---

**INV-CAU-1 — Causal relationships require evidence.**

Relationships such as:

```text
triggered_by
input_to
output_of
derived_from
approved_by
supersedes
```

must have evidentiary support.

---

**INV-CAU-2 — Temporal adjacency is insufficient.**

```text
A occurred before B
```

does not by itself establish:

```text
A caused B
```

---

**INV-CAU-3 — Causal uncertainty must remain representable.**

If evidence establishes possible but not definitive causation, the system must not upgrade that relationship into certainty.

---

# 13. Rationale and “Why”

PROVENANCE records observable explanatory evidence.

It does not invent hidden reasoning.

---

**INV-WHY-1 — No fabricated chain-of-thought.**

PROVENANCE must never generate hidden reasoning and represent it as historical reasoning performed by the monitored AI.

---

**INV-WHY-2 — Exposed rationale is evidence, not privileged truth.**

If a system supplies an explicit rationale, that rationale is recorded according to its actual provenance class.

It is not automatically treated as a faithful description of hidden internal computation.

---

**INV-WHY-3 — Missing rationale remains missing.**

If no rationale was observed, the record must preserve a state equivalent to:

```text
RATIONALE_NOT_OBSERVED
```

---

**INV-WHY-4 — Observable causes remain distinguishable from explanations.**

Inputs, prompts, retrieved documents, policies, tool results, and prior state may provide causal context.

They must not automatically be transformed into a narrative explanation attributed to the model.

---

# 14. Framework Neutrality

---

**INV-FWK-1 — Core evidence semantics are provider-independent.**

The core evidence contract must not require one specific:

```text
AI vendor
model provider
agent framework
programming language
runtime
deployment topology
```

---

**INV-FWK-2 — Vendor-specific data may be retained without redefining universal semantics.**

Provider-specific fields may exist in adapters or extensions.

They must not silently redefine core fields.

---

**INV-FWK-3 — Unknown future systems must remain representable.**

The core design must not assume that all future observed actors are LLMs.

---

# 15. Adapter Fidelity

---

**INV-ADP-1 — Adapters translate; they do not invent.**

An adapter must not manufacture values required only because the core schema makes them convenient.

---

**INV-ADP-2 — Unsupported values remain unsupported.**

If the source does not expose required information, the adapter must represent absence or uncertainty instead of guessing.

---

**INV-ADP-3 — Source-specific evidence may be retained losslessly.**

If source material cannot be fully represented in normalized fields, the original source artifact must remain retainable and referenceable.

---

**INV-ADP-4 — Adapter transformation is attributable.**

Canonical records created by an adapter must remain attributable to the adapter or transformation responsible.

---

# 16. Losslessness

---

**INV-LOS-1 — No silent data loss.**

Information discarded during transformation must be either:

```text
provably irrelevant under the contract
```

or:

```text
explicitly identified as omitted/lost
```

---

**INV-LOS-2 — Unrepresentable source evidence remains retainable.**

If the canonical schema cannot represent source information losslessly, the source artifact must remain referenceable.

---

**INV-LOS-3 — Redaction creates a derivative.**

Redaction must not silently replace the original artifact.

The redacted result is a derivative with explicit lineage.

---

# 17. Manifest Integrity

---

**INV-MAN-1 — A manifest describes exactly what it claims to contain.**

A finalized manifest must not claim that an artifact is retained when that artifact is absent.

---

**INV-MAN-2 — Manifest references are cryptographically bound where required.**

Artifacts represented as cryptographically identified must resolve to matching content.

---

**INV-MAN-3 — Missing artifacts are explicit.**

A missing artifact must be represented as missing rather than silently omitted where its absence affects completeness.

---

**INV-MAN-4 — Finalized manifests are immutable.**

Changing a finalized manifest produces a new manifest identity.

---

# 18. Signature Semantics

---

**INV-SIG-1 — Signatures bind bytes to keys.**

A valid digital signature establishes only what the defined signature scheme actually proves.

At minimum:

```text
specific bytes
were signed
using a key corresponding to
the verifying public key
```

---

**INV-SIG-2 — Signatures do not automatically prove legal identity.**

A cryptographic key must not automatically be equated with:

```text
human identity
organization identity
legal authority
physical location
```

---

**INV-SIG-3 — Signatures do not prove truth.**

A valid signature over a false statement remains a valid signature over a false statement.

---

**INV-SIG-4 — Signature verification results are reproducible.**

Given the same:

```text
signed bytes
signature
public key
algorithm
```

verification must produce the same result.

---

# 19. Verification

---

**INV-VER-1 — Verification depends only on declared inputs and published rules.**

A verification result must not depend on hidden mutable state.

---

**INV-VER-2 — Verification is reproducible.**

Given identical evidence, schema versions, canonicalization rules, algorithms, and verifier semantics:

```text
same verification result
```

must be produced.

---

**INV-VER-3 — Verification failure is not interpretation.**

The verifier may report:

```text
HASH_MISMATCH
INVALID_SIGNATURE
MISSING_ARTIFACT
BROKEN_CHAIN
INVALID_SCHEMA
```

It must not silently transform these into conclusions such as:

```text
FRAUD
NEGLIGENCE
DECEPTION
MALPRACTICE
GUILT
```

---

**INV-VER-4 — Independent verification must be possible where claimed.**

If the project claims that a format is independently verifiable, the verification contract must not require proprietary hidden state.

---

**INV-VER-5 — Verification claims accurately describe execution.**

A record or report must not state that verification occurred unless verification was actually executed.

---

# 20. Reproduction

---

**INV-REP-1 — Historical observation and later reproduction are distinct.**

A replay performed later must never silently replace an original historical observation.

---

**INV-REP-2 — Reproduction proves only reproduction results.**

A later run demonstrating:

```text
input X currently produces output Y
```

does not independently prove:

```text
historical execution produced Y
```

---

**INV-REP-3 — Reproduction context is identifiable.**

Where reproduction is used as evidence, its:

```text
software version
configuration
environment
inputs
time
```

must remain distinguishable from the historical system.

---

# 21. Human Action Attribution

---

**INV-HUM-1 — Human actions are not inferred from workflow presence.**

A human appearing in a workflow does not automatically mean that the human approved every subsequent action.

---

**INV-HUM-2 — AI actions are not silently attributed to humans.**

An automated action must not be represented as a human action without supporting evidence.

---

**INV-HUM-3 — Human actions may be evidence events.**

Observable human:

```text
approval
rejection
override
edit
submission
acknowledgement
authorization
```

may be represented as events with the same evidence discipline applied to machine actors.

---

# 22. Privacy and Sensitive Evidence

---

**INV-PRV-1 — Integrity does not imply disclosure.**

Evidence may be cryptographically verifiable without being publicly readable.

---

**INV-PRV-2 — Observable does not imply collectable.**

The fact that data can technically be observed does not require PROVENANCE to retain it.

---

**INV-PRV-3 — Credentials are not ordinary evidence fields.**

Secrets such as:

```text
passwords
private keys
API tokens
session secrets
```

must not be captured merely for completeness.

---

**INV-PRV-4 — Privacy transformations preserve lineage.**

Encryption, redaction, tokenization, or access-controlled derivation must not erase known evidence lineage.

---

# 23. Schema Stability

---

**INV-SCH-1 — Stable field meanings do not silently change.**

Once a schema version is declared stable, its existing field semantics remain stable.

---

**INV-SCH-2 — Breaking semantic changes require version change.**

Changes affecting:

```text
field meaning
hash semantics
canonicalization
identity semantics
ordering semantics
verification semantics
```

must not occur invisibly within the same stable schema version.

---

**INV-SCH-3 — Unknown extensions follow explicit rules.**

Unknown fields or extensions must never be interpreted through undocumented guessing.

---

# 24. Version Attribution

---

**INV-VRS-1 — Long-lived evidence contains sufficient interpretation metadata.**

Evidence formats intended for long-term retention must identify applicable versions of relevant contracts such as:

```text
schema
canonicalization
hash algorithm
signature algorithm
adapter
recorder
```

where necessary for later interpretation.

---

**INV-VRS-2 — Version aliases do not replace exact identity where exact identity exists.**

Mutable labels such as:

```text
latest
stable
production
main
```

must not silently substitute for exact immutable version information where exact identity is required.

---

# 25. Presentation and Interpretation

---

**INV-PRS-1 — Presentation is DERIVED.**

Timelines, reports, graphs, dashboards, summaries, and exhibits are derived views of evidence.

---

**INV-PRS-2 — Presentation must resolve to source evidence.**

Where a presentation makes a factual evidentiary claim, the supporting evidence should remain identifiable.

---

**INV-PRS-3 — Interpretation remains downstream.**

PROVENANCE must not automatically determine:

```text
guilt
innocence
liability
malpractice
negligence
intent
truth
ethical correctness
legal compliance
```

from raw technical evidence alone.

---

# 26. Trust Model

---

**INV-TRU-1 — Monitored systems are not presumed truthful.**

Statements made by the monitored system retain their actual provenance classification.

---

**INV-TRU-2 — Monitored systems are not presumed malicious.**

Unexpected behavior must be recorded without automatically attributing malicious intent.

---

**INV-TRU-3 — Collectors are not presumed infallible.**

PROVENANCE must permit evidence of:

```text
collector failure
collector version
collector configuration
collector limitations
```

---

**INV-TRU-4 — Self-verification is insufficient when independent verification is claimed.**

PROVENANCE saying:

```text
PROVENANCE evidence is valid
```

is not by itself independent verification.

---

# 27. Deterministic Evidence Representation

The monitored system may be nondeterministic.

The evidence representation must not be.

---

**INV-DET-1 — Same canonical record produces identical bytes.**

For fixed schema and canonicalization versions:

```text
same canonical evidence
→ same canonical bytes
```

---

**INV-DET-2 — Same canonical bytes produce identical cryptographic identity.**

For the same declared hash algorithm:

```text
same canonical bytes
→ same digest
```

---

**INV-DET-3 — Verification ordering is deterministic where ordering is defined.**

Verifier behavior must not depend on:

```text
hash-map iteration order
filesystem enumeration order
thread scheduling
implicit locale
unspecified ordering
```

where those would affect verification results.

---

**INV-DET-4 — Determinism stops at the evidence boundary.**

PROVENANCE must not require:

```text
same monitored input
→ same monitored output
```

unless the monitored system independently guarantees that property.

---

# 28. Failure Honesty

---

**INV-FAL-1 — Failure remains visible.**

Observable failures must not be converted into successful-looking records.

---

**INV-FAL-2 — Partial writes are not finalized evidence.**

An incompletely written artifact must not be represented as a successfully finalized artifact.

---

**INV-FAL-3 — Verification status is explicit.**

Evidence must not be represented as verified merely because it was successfully parsed or stored.

---

**INV-FAL-4 — Unknown failure cause remains unknown.**

A collector must not invent a root cause simply because an operation failed.

---

# 29. Claim Traceability

---

**INV-CLM-1 — Cryptographic claims resolve to cryptographic evidence.**

A claim of integrity must ultimately resolve to the exact artifact or canonical bytes whose integrity is asserted.

---

**INV-CLM-2 — Derived factual claims resolve to supporting evidence.**

Conceptually:

```text
CLAIM
  ↓
DERIVATION
  ↓
EVENT(S)
  ↓
ARTIFACT(S)
  ↓
IDENTITY
```

---

**INV-CLM-3 — Unsupported claims remain unsupported.**

A claim lacking sufficient evidence must not be marked proven merely because it appears plausible.

---

# 30. Repository Evolution

---

**INV-ARC-1 — Evidence semantics precede framework convenience.**

Core evidence semantics must not be weakened merely to simplify a particular adapter.

---

**INV-ARC-2 — Core verification does not depend on presentation.**

A verifier must not need the dashboard, report generator, visualization system, or other presentation layer to verify core evidence.

---

**INV-ARC-3 — Presentation does not define evidence truth.**

A report or UI state is not authoritative over the evidence it presents.

---

**INV-ARC-4 — Adapters do not define universal truth.**

Provider-specific behavior must remain subordinate to the core evidence contract.

---

# Verification

Every stable invariant must eventually be enforced by at least one appropriate mechanism.

Possible enforcement classes:

```text
SCHEMA
UNIT_TEST
FIXTURE
PROPERTY_TEST
STRUCTURAL_CHECK
RUNTIME_ASSERTION
CRYPTOGRAPHIC_VERIFICATION
CROSS_IMPLEMENTATION_TEST
STATIC_VALIDATION
MANUAL_PROTOCOL_REVIEW
```

The preferred rule is:

```text
IF_AN_INVARIANT_CAN_BE_MACHINE_VERIFIED
THEN_EVENTUALLY_MACHINE_VERIFY_IT
```

Documentation alone is not sufficient enforcement for a machine-verifiable invariant.

---

# Invariant Registry Requirement

As the implementation matures, each invariant should become traceable to its enforcement mechanism.

Target form:

| Invariant | Enforcement | Status |
|---|---|---|
| `INV-EVD-2` | immutable artifact fixture | planned |
| `INV-CLS-4` | schema + validator | planned |
| `INV-NIF-1` | adapter non-interference tests | planned |
| `INV-ID-5` | hash mutation fixture | planned |
| `INV-CAN-2` | canonical byte fixtures | planned |
| `INV-HSH-3` | tamper fixture | planned |
| `INV-CUS-1` | append-only custody tests | planned |
| `INV-GAP-1` | schema/fixture validation | planned |
| `INV-WHY-1` | schema + adapter contract | planned |
| `INV-VER-2` | verifier replay fixtures | planned |

This table is illustrative during bootstrap.

It must not claim enforcement that does not yet exist.

---

# Invariant Change Law

Changes to an invariant are constitutional changes.

An invariant must not be weakened, reinterpreted, renumbered, or removed merely to make an implementation pass.

If implementation and invariant conflict:

```text
1. determine whether implementation is defective;
2. determine whether invariant is incorrectly specified;
3. document the reasoning;
4. change exactly one deliberately.
```

Never silently change both until tests become green.

---

# Bootstrap Status

At repository bootstrap:

```text
INVARIANTS_DEFINED
IMPLEMENTATION_INCOMPLETE
ENFORCEMENT_PARTIAL_OR_NOT_YET_PRESENT
```

This is valid.

The repository must not pretend that an invariant is technically enforced before an enforcement mechanism exists.

Distinguish:

```text
SPECIFIED
IMPLEMENTED
TESTED
ENFORCED
VERIFIED
```

These are different states.

---

# Final Invariant

**INV-ULT-1 — The record must not claim more than the evidence supports.**

Formally:

```text
SUPPORTED_CLAIM ⊆ AVAILABLE_EVIDENCE
```

If PROVENANCE knows:

```text
X
```

it may record:

```text
X
```

If PROVENANCE knows only:

```text
possibly X
```

it must not record:

```text
certainly X
```

If PROVENANCE does not know:

```text
UNKNOWN
```

is the correct result.

---

# Final Law

```text
DO_NOT_IMPROVE_HISTORY
DO_NOT_COMPLETE_HISTORY
DO_NOT_INVENT_HISTORY
DO_NOT_HIDE_GAPS
DO_NOT_UPGRADE_UNCERTAINTY
DO_NOT_OVERSTATE_CRYPTOGRAPHY
DO_NOT_CONFUSE_OBSERVATION_WITH_TRUTH
DO_NOT_CONFUSE_VERIFICATION_WITH_JUDGMENT
```

Preserve exactly what can be supported.

Nothing more.

Nothing less.

---

# Project Maxim

> **Here's the evidence. We know exactly what you did. Tell it to the judge.**
