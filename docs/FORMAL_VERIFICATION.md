# Phase 18 Formal Verification

## Status

```text
FORMAL PROOF SET IMPLEMENTED
FINAL ARCHIVAL TAG / ZENODO PUBLICATION PENDING
```

This document defines the formal-verification boundary for PROVENANCE Phase 18.

The formal target is immutable:

```text
tag:        v1.0.0
commit:     0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742
Lean:       leanprover/lean4:v4.34.1
DOI:        10.5281/zenodo.23043860
```

The Lean sources prove properties of an explicit model of selected stable invariants. They do **not** constitute whole-program verification of the Python/Rust runtime.

The target declaration is machine-readable in `formal/TARGET.json`.

---

## Proof set

| Claim | Project invariant | Lean theorem(s) | Frozen runtime bridge | Frozen regression evidence |
|---|---|---|---|---|
| `FV-01` Self-hash exclusion | `INV-HSH-2` | `selfHashExclusion`, `storedIdentityDoesNotAffectRecomputation` | `provenance_core.identity.event_identity/custody_identity/manifest_identity`; envelope `seal()` methods hash only `core.to_dict()` | `tests.test_core.test_self_hash_fields_are_outside_hashed_core`; `test_event_envelope_rejects_identity_substitution` |
| `FV-02` Append-only history extension | `INV-CUS-1`, `INV-EVD-3` | `appendOnlyPrefix`, `priorRecordSurvivesAppend` | `LocalCustodyLedger.append()` and `ensure_action_sequence()` publish new immutable records linked to prior tips | `tests.test_custody.test_append_reopen_and_verify_chain`; `test_same_process_instances_serialize_appends_without_fork` |
| `FV-03` Classification non-promotion | `INV-CLS-3`, `INV-CLS-5` | `callerDeclarationRemainsDeclared`, `callerDeclarationIsNotObserved`, `operationChangePreservesClassification` | MCP/CLI caller assertions enter through DECLARED evidence paths; observation receipts are separate OBSERVED events | `tests.test_mcp.test_modern_stdio_self_demonstration_preserves_classification`; `test_record_rejects_caller_evidence_class_override` |
| `FV-04` Presentation non-interference | `INV-EVD-5`, `INV-ARC-3` | `presentationPreservesSource` | `provenance_ui.viewer.build_view()` reads finalized evidence and produces a projection without mutation authority | `tests.test_ui.test_projection_is_read_only_and_separates_verification_dimensions`; `test_http_surface_is_get_head_only_and_does_not_mutate_evidence` |

The bridge is intentionally explicit rather than implied.

---

## What the proofs establish

### FV-01 — Self-hash exclusion

The formal envelope model stores:

```text
core
stored identity
```

but recomputation depends only on the core.

The theorem proves that changing only the stored self-identity cannot affect the recomputed identity.

This corresponds to the frozen runtime contract in which Event, Manifest, and Custody envelope identities are computed from their core representations and the envelope identifies the self-hash field separately.

### FV-02 — Append-only history extension

The formal history operation is:

```text
history ++ [new_record]
```

The proofs establish:

1. the old history remains a prefix of the new history; and
2. every prior member remains present after append.

This models the constitutional append-only property, not filesystem durability or locking.

### FV-03 — Classification non-promotion

The formal declaration path always constructs:

```text
EvidenceClass.declared
```

and a transformation of an unrelated field preserves the class.

This proves the model cannot silently convert a caller declaration into OBSERVED evidence.

The runtime bridge is the separate DECLARED assertion / OBSERVED invocation-receipt design in MCP and CLI.

### FV-04 — Presentation non-interference

The formal presentation function receives evidence as an input and returns:

```text
(original source, rendered view)
```

The theorem proves that projection preserves the source component exactly.

This models the read-only presentation boundary enforced by the Phase 9 viewer and its filesystem-fingerprint tests.

---

## Proof boundary

The formal proof claim is exactly:

```text
THE ENCODED MODEL
SATISFIES
FV-01 .. FV-04
```

It is **not**:

```text
THE ENTIRE PYTHON/RUST PROGRAM IS FORMALLY VERIFIED
```

The bridge from model to runtime consists of:

- frozen code inspection;
- named runtime types/functions;
- executed frozen regression tests;
- the immutable target SHA;
- this documented correspondence.

The proofs do not independently establish:

```text
cryptographic collision resistance
operating-system correctness
filesystem durability
lock implementation correctness
Python interpreter correctness
Rust compiler correctness
GitHub Actions correctness
external provider behavior
source-data truth
human/legal identity
legal or factual truth
```

---

## Known non-modeled maintenance issue

After `v1.0.0` was frozen, the tag-triggered transfer workflow exposed a first-construction race in custody-format marker publication.

That runtime concurrency defect is fixed on post-release `main` by PR #18.

The immutable `v1.0.0` target remains unchanged.

None of `FV-01` through `FV-04` claims to prove custody-format filesystem initialization or concurrent first-construction safety. The archival record should retain this distinction rather than implying that the formal proof covers the later maintenance defect.

---

## Reproduction

From the proof directory:

```bash
cd formal
lake build
```

The CI lane additionally runs independent proof checking through the pinned `leanprover/lean-action` integration:

```text
Lean build
leanchecker
nanoda with sorry disallowed
axiom audit
```

GitHub caching is disabled for this lane.

The formal workflow also verifies that:

```text
v1.0.0
→
0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742
```

before proof execution.

---

## Proof-source identity

`scripts/phase18_manifest.py` generates:

```text
provenance.phase18-formal-evidence.v1
```

containing:

- frozen tag;
- frozen commit SHA;
- DOI;
- Lean toolchain;
- proof commit;
- formal claim registry;
- SHA-256 and byte count of every proof/archive source file;
- verification contract.

The resulting manifest is retained as a workflow artifact together with frozen source and formal-source archives.

---

## Restart rule

If formalization exposes a defect that requires changing the frozen implementation contract:

```text
DO NOT REINTERPRET v1.0.0
DO NOT PATCH THE FROZEN TAG

return to release-candidate engineering
establish a new immutable candidate
restart formal verification
```

Documentation or proof-source corrections that do not change the frozen implementation may proceed without redefining `v1.0.0`.
