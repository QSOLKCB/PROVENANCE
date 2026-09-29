# Usage Instructions

This guide covers the current PROVENANCE reference implementation through **Phase 16**.

Deep semantics remain in the subsystem specifications. This document focuses on operating the implemented interfaces without weakening the evidence contract.

## Core workflow

```text
observe / declare
    ↓
record artifacts + events
    ↓
append custody
    ↓
finalize immutable snapshot
    ↓
independently verify
    ↓
inspect / export / package
    ↓
optional sign / redact / transfer
```

## Evidence classes

| Class | Meaning |
|---|---|
| `OBSERVED` | Directly captured at the declared observation boundary |
| `DECLARED` | Supplied or asserted by a caller, provider, or operator |
| `DERIVED` | Computed from identified source evidence |

Do not promote declarations into observations merely because an adapter, CLI, or MCP server parsed them.

See [INVARIANTS.md](INVARIANTS.md).

---

# Rust CLI

Build:

```bash
cargo build --manifest-path provenance-cli/Cargo.toml --locked
```

Development binary:

```text
./provenance-cli/target/debug/provenance
```

Current commands:

```text
record
inspect
verify
finalize
export
package
sign-package
anchor-payload
anchor-git
verify-assurance
redact-disclosure
verify-disclosure
transfer-create
transfer-receive
verify-transfer
verify-receipt
tui
```

The Rust binary delegates evidence operations to the existing PROVENANCE contracts. It is an interface, not an alternate evidence implementation.

## Record text

```bash
./provenance-cli/target/debug/provenance record \
  --store /path/to/store \
  --custody /path/to/custody \
  --text "evidence" \
  --actor "operator:alice" \
  --operation "example.capture"
```

## Record a file

```bash
./provenance-cli/target/debug/provenance record \
  --store /path/to/store \
  --custody /path/to/custody \
  --file ./artifact.bin \
  --actor "operator:alice" \
  --operation "example.file-capture" \
  --media-type application/octet-stream
```

Add `--digest-only` when identity and metadata should be retained without retaining source bytes.

Operator-supplied content is DECLARED. Successful CLI record calls also retain separate OBSERVED occurrence evidence.

## Inspect

```bash
./provenance-cli/target/debug/provenance inspect \
  --store /path/to/store \
  --custody /path/to/custody
```

Use `--identity sha256:<digest>` for a known evidence identity.

## Finalize

```bash
./provenance-cli/target/debug/provenance finalize \
  --store /path/to/store \
  --custody /path/to/custody \
  --scope closed
```

Use `--scope open` when collection gaps or ongoing collection must remain explicit.

Finalization never authorizes rewriting earlier records.

## Verify

```bash
./provenance-cli/target/debug/provenance verify \
  --store /path/to/store \
  --custody /path/to/custody
```

Verification recomputes evidence rather than trusting stored success claims.

## Export versus package

`export` creates the historical verified snapshot copy:

```bash
./provenance-cli/target/debug/provenance export \
  --store /path/to/store \
  --custody /path/to/custody \
  --destination /path/to/snapshot-copy
```

`package` creates the Phase 11 portable forensic envelope:

```bash
./provenance-cli/target/debug/provenance package \
  --store /path/to/store \
  --custody /path/to/custody \
  --destination /path/to/forensic-package
```

A forensic package binds its physical members by path, content identity, and byte count and carries the finalized evidence, custody snapshot, schema/version metadata, verification metadata, and declared gaps.

See [PACKAGE.md](PACKAGE.md).

## TUI

```bash
./provenance-cli/target/debug/provenance tui \
  --store /path/to/store \
  --custody /path/to/custody
```

The keyboard-first palette exposes the working-store commands:

```text
record
inspect
verify
finalize
export
package
```

The TUI does not add new evidence semantics.

See [CLI.md](CLI.md).

---

# Optional authenticity: signatures and Git anchors

Phase 12 adds detached trust records without changing package identity.

Generate an Ed25519 signing key:

```bash
ssh-keygen -t ed25519 -f ./provenance-signing-key
```

Create a detached SSHSIG record:

```bash
./provenance-cli/target/debug/provenance sign-package \
  --package /path/to/forensic-package \
  --key ./provenance-signing-key \
  --output ./package.signature.json
```

Create a Git anchor payload:

```bash
./provenance-cli/target/debug/provenance anchor-payload \
  --package /path/to/forensic-package \
  --output /path/to/repo/package.provenance
```

Commit that payload, then bind the package to the existing commit:

```bash
./provenance-cli/target/debug/provenance anchor-git \
  --package /path/to/forensic-package \
  --git-repo /path/to/repo \
  --commit HEAD \
  --path package.provenance \
  --output ./package.git-anchor.json
```

Verify integrity, signature, and anchor as separate dimensions:

```bash
./provenance-cli/target/debug/provenance verify-assurance \
  --package /path/to/forensic-package \
  --signature ./package.signature.json \
  --anchor ./package.git-anchor.json \
  --git-repo /path/to/repo
```

A valid key signature proves that the corresponding key signed the bytes. It does not automatically prove legal identity, organizational authority, intent, or truth.

See [TRUST.md](TRUST.md).

---

# Read-only UI

```bash
python3 -m provenance_ui \
  --store /path/to/store \
  --custody /path/to/custody
```

Default bind:

```text
127.0.0.1:8765
```

Non-loopback binding requires explicit operator action.

The UI consumes finalized evidence and immutable custody records. It has no evidentiary authority and is tested for non-interference.

See [UI.md](UI.md).

---

# MCP

Start the dependency-free stdio interface:

```bash
python3 -m provenance_mcp \
  --store /path/to/store \
  --custody /path/to/custody
```

Current tools:

```text
provenance.record
provenance.inspect
provenance.verify
provenance.finalize
provenance.export
provenance.package
```

Values supplied through `provenance.record` remain DECLARED. The MCP invocation occurrence is recorded separately as OBSERVED evidence.

MCP and CLI share the same hardened operational working-state journal so pending evidence cannot silently diverge between interfaces.

See [MCP.md](MCP.md).

---

# Adapters

Implemented reference observation paths include:

```text
local Ollama
generic HTTP/HTTPS
local process / CLI
```

Provider-specific metadata remains behind the generic adapter boundary.

The Ollama reference path retains exact request/response bytes and preserves the distinction between directly observed transport bytes and provider/model declarations.

See [ADAPTERS.md](ADAPTERS.md) and [OLLAMA.md](OLLAMA.md).

---

# Python verification APIs

Verify an evidence bundle:

```python
from pathlib import Path
from provenance_verify import verify_bundle

report = verify_bundle(Path("/path/to/bundle"))
print(report.integrity_verified)
print(report.errors)
```

Verify a portable forensic package:

```python
from provenance_verify import verify_forensic_package

report = verify_forensic_package("/path/to/forensic-package")
print(report.integrity_verified)
print(report.package_identity)
print(report.errors)
```

Where a serial reference API exists, it is retained for semantic comparison with the optimized verifier.

---

# Phase 13: reference and optimized verification

Normal verification uses bounded deterministic parallelism where allowed.

Reference APIs remain available for conformance/debugging:

```python
from provenance_verify import (
    verify_bundle_reference,
    verify_forensic_package_reference,
)
```

The required invariant is:

```text
OPTIMIZED REPORT
==
REFERENCE REPORT
```

including deterministic check/error ordering for stable evidence inputs.

Run the benchmark:

```bash
python3 scripts/benchmark_phase13.py \
  --artifact-count 32 \
  --artifact-bytes 1048576 \
  --repetitions 5
```

Benchmark results are environment-scoped. Re-measure on a different host.

See [PERFORMANCE.md](PERFORMANCE.md).

---

# Phase 14: selective disclosure

Create a deterministic redacted derivative from a retained source artifact:

```bash
./provenance-cli/target/debug/provenance redact-disclosure \
  --package /path/to/forensic-package \
  --source sha256:<source-digest> \
  --range 17:29 \
  --output /path/to/disclosure
```

Verify disclosed lineage without the source package:

```bash
./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure /path/to/disclosure
```

When the original package is available, recompute the transform:

```bash
./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure /path/to/disclosure \
  --source-package /path/to/forensic-package
```

The source bytes are not silently relabeled. The disclosure retains source identity/metadata while the redacted content is a new DERIVED artifact.

See [PRIVACY.md](PRIVACY.md).

---

# Phase 15: distributed custody handoff

Create a signed sender bundle:

```bash
./provenance-cli/target/debug/provenance transfer-create \
  --package /path/to/source-package \
  --source-system org-a/system-1 \
  --destination-system org-b/system-9 \
  --sender-key /path/to/sender-key \
  --output /path/to/transfer
```

Verify sender-side transfer integrity:

```bash
./provenance-cli/target/debug/provenance verify-transfer \
  --transfer /path/to/transfer
```

Move the transfer directory through the chosen offline/store-and-forward channel.

Receiver acceptance requires a sender fingerprint supplied independently of the transfer being accepted:

```bash
./provenance-cli/target/debug/provenance transfer-receive \
  --transfer /path/to/transfer \
  --package-destination /receiver/package \
  --receipt /receiver/receipt \
  --custody /receiver/custody \
  --receiver-system org-b/system-9 \
  --receiver-key /path/to/receiver-key \
  --expected-sender-fingerprint 'SHA256:<trusted-sender-fingerprint>'
```

Verify the receiver acknowledgement:

```bash
./provenance-cli/target/debug/provenance verify-receipt \
  --receipt /receiver/receipt \
  --transfer /path/to/transfer \
  --package /receiver/package
```

Important boundaries:

- sender and receiver clocks remain independent;
- wall-clock comparison does not manufacture global order;
- completed duplicate delivery is idempotent;
- receiver custody is local and append-only;
- signing-key possession does not automatically establish legal/organizational identity;
- acceptance fails closed when the independently supplied sender fingerprint does not match.

See [TRANSFER.md](TRANSFER.md).

---

# Focused validation lanes

Fast development validation remains modular.

Python suites:

```bash
python3 -m unittest tests.test_core -v
python3 -m unittest tests.test_verify -v
python3 -m unittest tests.test_store -v
python3 -m unittest tests.test_custody -v
python3 -m unittest tests.test_ollama_adapter tests.test_ollama_transport -v
python3 -m unittest tests.test_mcp -v
python3 -m unittest tests.test_cli -v
python3 -m unittest tests.test_ui -v
python3 -m unittest tests.test_generic_adapters -v
python3 -m unittest tests.test_package -v
python3 -m unittest tests.test_trust -v
python3 -m unittest tests.test_performance -v
python3 -m unittest tests.test_privacy -v
python3 -m unittest tests.test_transfer -v
```

Rust CLI:

```bash
cargo build --manifest-path provenance-cli/Cargo.toml --locked
cargo test --manifest-path provenance-cli/Cargo.toml --locked
```

Complete local Python discovery:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

The real Ollama smoke lane additionally requires Ollama/model downloads and is normally exercised in GitHub Actions.

---

# Phase 16: release-grade trust lane

Routine focused workflows are for development feedback.

The release-grade `full` workflow is the gate for a candidate intended for freeze.

It requires:

```text
fresh checkout
pinned Python toolchain
pinned Rust toolchain
complete Python invariant/tamper/integration suite
Rust CLI build + unit tests
canonical core/verifier cross-seed recheck
clean source tree
real Ollama qwen2.5:0.5b lane
real Ollama qwen2:0.5b lane
tamper detection in both real-model lanes
release-gate aggregation
```

The reference pins and exact assurance boundary are documented in [RELEASE.md](RELEASE.md).

A green run qualifies only the exact commit it tested.

```text
COMMIT CHANGES
→
QUALIFICATION MUST RUN AGAIN
```

Do not substitute a collection of green focused workflows for the final `release-gate`.

---

# Phase 17: tagging the immutable candidate

The next roadmap step is the candidate freeze.

For the exact commit you intend to tag:

1. merge all intended implementation and documentation changes;
2. update local `main` and record the exact SHA;
3. run or confirm the `full` workflow against that exact SHA;
4. require `release-suite`, both real Ollama jobs, and `release-gate` to succeed;
5. record the workflow run and commit SHA;
6. create the tag on that exact SHA.

Local SHA check:

```bash
git checkout main
git pull --ff-only
git rev-parse HEAD
```

If the tag is being used as the Phase 17 freeze target, the following become frozen:

```text
implementation
schema semantics
verifier semantics
evidence-contract semantics
```

A defect requiring implementation change invalidates that freeze target. Return to Phase 16, fix it, run the release lane again, and create a new candidate tag.

Phase 17 itself does not prove correctness. It identifies the immutable implementation that Phase 18 formalization will target.

---

# Operational rules

- Do not put credentials or private keys into ordinary evidence payloads unless retention is explicitly intended.
- Do not put secrets into evidence-bearing URLs, argv, prompts, or artifacts merely for convenience.
- Treat `DIGEST_ONLY`, `MISSING`, open scope, and incomplete custody as evidence states—not defects to hide.
- Do not edit finalized evidence to make verification pass.
- Preserve exact identities when transferring evidence.
- Obtain trusted sender fingerprints independently of untrusted transfer bundles.
- Prefer the independent verifier over producer, UI, or adapter success claims.
- A signature proves key possession over bytes, not legal truth.
- A green release lane is engineering assurance, not formal proof.

## Deep reference

[Architecture](ARCHITECTURE.md) ·
[Invariants](INVARIANTS.md) ·
[Store](STORE.md) ·
[Custody](CUSTODY.md) ·
[Bundle](BUNDLE.md) ·
[Package](PACKAGE.md) ·
[Trust](TRUST.md) ·
[Performance](PERFORMANCE.md) ·
[Privacy](PRIVACY.md) ·
[Transfer](TRANSFER.md) ·
[Release](RELEASE.md) ·
[CLI](CLI.md) ·
[MCP](MCP.md) ·
[UI](UI.md) ·
[Adapters](ADAPTERS.md) ·
[Ollama](OLLAMA.md) ·
[Roadmap](ROADMAP.md)
