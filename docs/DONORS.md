# PROVENANCE Donor Registry

This file records repositories whose engineering patterns inform `QSOLKCB/PROVENANCE`.

The purpose is **traceability, not inheritance**.

PROVENANCE should copy only mechanisms that serve its evidence contract.

```text
DONOR IDEA
    ↓
REMOVE DOMAIN-SPECIFIC SEMANTICS
    ↓
ADAPT TO PROVENANCE INVARIANTS
    ↓
TEST IN PROVENANCE
```

A donor implementation is never authoritative merely because it worked elsewhere.

---

## Selection Rule

Prefer the smallest mechanism that preserves:

```text
accuracy
evidence fidelity
non-interference
chain of custody
independent verification
```

Performance improvements are welcome only when they preserve the same contract.

```text
LESS OVERHEAD
!=
LESS EVIDENCE
```

---

# 1. QSOLKCB/QEC

Repository:

https://github.com/QSOLKCB/QEC

Initial donor-inspection snapshot:

```text
2c94351e667bc05aba26fe101dcf41fa8d4c9735
```

License:

```text
Mozilla Public License 2.0
```

## Useful donor concepts

- invariant-driven engineering;
- deterministic canonical representation;
- content-based identity;
- canonical hashing;
- exact receipts;
- immutable proof artifacts;
- recompute-not-trust verification;
- explicit self-hash exclusion;
- deterministic reference paths;
- equivalence-gated reuse;
- validation escalation based on invariant impact.

## Adaptation boundary

QEC is a deterministic scientific system.

PROVENANCE is not.

Do **not** transplant requirements that the monitored system itself be deterministic.

PROVENANCE adopts:

```text
same canonical evidence
→ same canonical bytes
→ same identity
→ same verification result
```

It does not require:

```text
same monitored input
→ same monitored output
```

## Explicit non-donors

Do not import:

- QEC decoder architecture;
- quantum-error-correction domain logic;
- scientific control semantics;
- QEC-specific message protocols;
- QEC-specific convergence rules;
- domain-specific receipt fields.

---

# 2. QSOLKCB/UFF

Repository:

https://github.com/QSOLKCB/UFF

Initial donor-inspection snapshot:

```text
596cd732df61587aa1a9801cad1ec13483b1347f
```

License:

```text
Apache License 2.0
```

## Useful donor concepts

UFF currently provides the strongest implementation examples for:

- canonical JSON validation;
- duplicate-key rejection;
- non-finite JSON rejection;
- exact artifact manifests;
- closed evidence bundles;
- artifact byte counts;
- SHA-256 identities;
- safe relative artifact paths;
- symlink rejection;
- child-before-root verification;
- manifest-core/envelope separation;
- self-hash exclusion;
- exact deterministic receipts;
- external trust anchors;
- pre-observation identity witnesses;
- domain-separated commitments;
- explicit proof-scope boundaries;
- source-acquisition manifests;
- read-only telemetry with zero evidence-admission authority.

Particularly relevant donor files include:

```text
uff/qec_gate.py
uff/spectral_witness.py
uff/audit_events.py
formal/lean/UFF/Manifest.lean
docs/INDEPENDENT_ASSESSMENT_SOURCE_MANIFEST_2026-08-07.md
```

## Adaptation boundary

UFF uses replay as part of scientific admission.

PROVENANCE must not make replay a universal evidence requirement.

Historical evidence may remain valid even when replay is impossible.

PROVENANCE should distinguish independently:

```text
INTEGRITY_VERIFIED
CUSTODY_VERIFIED
SIGNATURE_VERIFIED
REPLAY_VERIFIED
```

None automatically implies the others.

## Explicit non-donors

Do not import:

- SLFA semantics;
- Sheridan semantics;
- catalogue rules;
- support-grid rules;
- astrophysical claims;
- null-model requirements;
- scientific admission decisions;
- UFF-specific schemas.

---

# 3. QSOLKCB/OPT

Repository:

https://github.com/QSOLKCB/OPT

Initial donor-inspection snapshot:

```text
3441c6ceacd4a6ca43ec46de758e2d5bc23d8ca7
```

License:

```text
Apache License 2.0
```

## Purpose in PROVENANCE

OPT is primarily a **performance and CI donor**.

It must not define PROVENANCE evidence semantics.

Relevant patterns include:

### Deterministic test execution

From:

```text
OPT-PY-001
```

Use:

- smallest fixtures that still test the invariant;
- removal of redundant deterministic work;
- immutable reusable intermediates;
- focused profiling before optimization.

Never reduce semantic coverage merely to reduce CI time.

---

### Invariant-driven reuse

From:

```text
OPT-INV-001
```

Reuse only when equivalence is itself explicit and tested.

```text
PROVEN_EQUIVALENCE
+
VALID_RESULT
=
REUSE_ALLOWED
```

---

### Signature-bound incremental execution

From:

```text
OPT-INC-001
```

Reusable state must bind:

```text
complete effective input identity
+
validated output identity
+
successful generation
```

Failed or interrupted execution must never publish reusable state.

---

### Deterministic parallel execution

From:

```text
OPT-PAR-001
```

Optimized/parallel execution must preserve the reference result.

```text
PARALLEL_RESULT == REFERENCE_RESULT
```

Requested concurrency is not evidence that concurrency actually occurred.

---

### Trust-preserving formal CI

From:

```text
OPT-LEAN-001
```

If formal verification is introduced later:

- routine CI may reuse independently validated dependency artifacts;
- current project source must still be rebuilt;
- cache reuse must be identified honestly;
- release-grade cold reconstruction remains a distinct claim.

---

# Donor Extraction Rules

## Rule 1 — Concepts before code

Prefer reimplementation from the invariant unless literal reuse provides a clear benefit.

---

## Rule 2 — No donor constants

Do not blindly copy:

```text
worker counts
timeouts
cache sizes
buffer sizes
thresholds
benchmark targets
fixture sizes
retry counts
```

Measure them in PROVENANCE.

---

## Rule 3 — No inherited authority

A donor test proves something about the donor.

It does not prove PROVENANCE.

Every imported mechanism requires PROVENANCE-native validation.

---

## Rule 4 — Preserve licensing provenance

If literal source code is copied or substantially adapted, retain the applicable copyright, attribution, notice, and license requirements.

Current relevant repository licenses:

```text
QEC         MPL-2.0
UFF         Apache-2.0
OPT         Apache-2.0
PROVENANCE  MPL-2.0
```

Conceptual influence and literal source reuse must not be confused.

---

## Rule 5 — Prefer deletion

If a donor mechanism is not needed to preserve a PROVENANCE invariant:

```text
DO_NOT_IMPORT_IT
```

Complexity itself creates verification cost.

---

# Final Rule

The donor repositories provide:

```text
patterns
evidence
lessons
failure modes
```

They do not provide unquestionable architecture.

PROVENANCE remains responsible for proving its own behavior.
