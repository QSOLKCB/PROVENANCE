# PROVENANCE Engineering Lineage

PROVENANCE did not begin from an empty design space.

Several earlier QSOL projects developed pieces of the engineering discipline that this repository generalizes into a framework-neutral chain-of-custody system.

This file records that lineage.

It is historical and architectural context.

It does not make donor repositories normative dependencies.

---

# Lineage

```text
QEC
│
│  deterministic identity
│  canonical representation
│  invariant discipline
│  receipts
│  recompute-not-trust
│
▼
UFF
│
│  closed evidence bundles
│  source manifests
│  precommit witnesses
│  trust boundaries
│  self-hash exclusion
│  external anchors
│  read-only observation
│  explicit proof scope
│
▼
PROVENANCE
   framework-neutral
   forensic chain of custody
   for AI, software, tools,
   humans and automated systems
```

Alongside this lineage:

```text
OPT
 │
 └──────► efficient implementation and CI
          without weakening correctness
```

---

# QEC Contribution

`QSOLKCB/QEC` established recurring engineering patterns around:

```text
canonical identity
deterministic serialization
cryptographic receipts
immutable artifacts
invariant-driven validation
recompute-not-trust
```

PROVENANCE retains those ideas at the **evidence layer**.

It deliberately does not inherit QEC's requirement that the observed system itself be deterministic.

---

# UFF Contribution

`QSOLKCB/UFF` moved several of those patterns into concrete evidence workflows:

```text
source
  ↓
identity commitment
  ↓
execution
  ↓
artifacts
  ↓
manifest
  ↓
closed bundle
  ↓
verification
  ↓
receipt / anchor
```

UFF also established an important boundary:

```text
technical integrity
!=
scientific truth
```

PROVENANCE generalizes that principle:

```text
valid evidence
!=
correct decision

valid signature
!=
true statement

valid chain of custody
!=
legal conclusion
```

PROVENANCE records evidence.

Interpretation remains downstream.

---

# OPT Contribution

`QSOLKCB/OPT` contributes the rule that optimization must preserve the contract it accelerates.

For PROVENANCE:

```text
FAST
```

is acceptable only when:

```text
FAST_RESULT == REFERENCE_RESULT
```

under the applicable exactness contract.

Useful inherited disciplines include:

```text
measure before optimizing
reuse only under proven identity
publish cache state only after success
keep a reference path
bound parallelism
test equivalence directly
do not weaken validation to improve timing
```

---

# PROVENANCE Divergence

PROVENANCE is not QEC, UFF, or OPT combined.

Its purpose is narrower:

> Preserve enough trustworthy evidence to determine what happened, how the record was produced, and where certainty ends.

The core system therefore prioritizes:

```text
Evidence Fidelity
Non-Interference
Chain of Custody
Cryptographic Integrity
Observation Boundaries
Independent Verification
Framework Neutrality
Low Overhead
```

---

# Design Direction

The intended evolution is:

```text
evidence semantics
    ↓
invariants
    ↓
minimal schemas
    ↓
canonical representation
    ↓
artifact identity
    ↓
event recording
    ↓
custody
    ↓
verification
    ↓
adapters
    ↓
presentation
```

Performance work happens around that contract.

It does not redefine it.

---

# Minimalism Rule

PROVENANCE should not become a collection of every mechanism developed elsewhere.

The preferred architecture is:

```text
small core
+
strict contracts
+
optional adapters
```

not:

```text
large framework
+
mandatory middleware
+
hidden runtime machinery
```

Every additional operation performed during monitoring creates:

```text
latency
failure surface
complexity
observer effect
verification burden
```

Therefore:

> **Collect the minimum evidence necessary to preserve the required claim accurately.**

Minimalism must never justify omission of evidence required by the declared provenance contract.

---

# Historical Snapshot

Initial donor inspection for the PROVENANCE bootstrap used:

```text
QEC
2c94351e667bc05aba26fe101dcf41fa8d4c9735

UFF
596cd732df61587aa1a9801cad1ec13483b1347f

OPT
3441c6ceacd4a6ca43ec46de758e2d5bc23d8ca7
```

These hashes identify the repository states examined during initial architecture work.

They do not freeze the donor repositories or require PROVENANCE to track future donor changes.

---

# Final Principle

The lineage can be summarized as:

```text
QEC taught us to bind the result.

UFF taught us to bind the evidence.

OPT taught us not to waste cycles doing it.

PROVENANCE makes the chain general.
```

Or more formally:

```text
MINIMUM_OVERHEAD
subject to
ZERO_UNDECLARED_LOSS_OF_EVIDENTIARY_ACCURACY
```
