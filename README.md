# PROVENANCE

> **Cryptographic chain of custody for LLMs, software, agents, tools, and automated systems.**

PROVENANCE records **who did what, when, where, why, and how — backed by evidence**. It captures actions, binds artifacts and events to cryptographic identities, preserves append-only custody, supports signed offline handoff between systems, and independently verifies the resulting record.

The project is implemented through **Phase 16**. The immutable implementation baseline is now **`v1.0.0`**, which points exactly to **`0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742`**. That tag is the fixed implementation target for subsequent formal-verification and archival work.

**Start here:** [Getting Started](docs/GETTING_STARTED.md) · [Usage Instructions](docs/INSTRUCTIONS.md) · [Release Trust Lane](docs/RELEASE.md) · [Documentation](docs/README.md) · [Roadmap](docs/ROADMAP.md)

[![Version](https://img.shields.io/badge/version-v1.0.0-4c1.svg)](https://github.com/QSOLKCB/PROVENANCE/releases/tag/v1.0.0)
[![Phase](https://img.shields.io/badge/roadmap-Phase%2018%20in%20progress-f59e0b.svg)](docs/ROADMAP.md)
[![Core CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/core.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/core.yml)
[![Verify CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/verify.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/verify.yml)
[![Package CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/package.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/package.yml)
[![Trust CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/trust.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/trust.yml)
[![Performance CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/performance.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/performance.yml)
[![Privacy CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/privacy.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/privacy.yml)
[![Transfer CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/transfer.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/transfer.yml)
[![Full Release Lane](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/full.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/full.yml)
[![Formal Verification](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/formal.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/formal.yml)
[![Determinism](https://img.shields.io/badge/determinism-canonical%20SHA--256-0969da.svg)](docs/INVARIANTS.md)
[![Verification](https://img.shields.io/badge/verification-independent-6f42c1.svg)](docs/BUNDLE.md)
[![Custody](https://img.shields.io/badge/custody-append--only-b60205.svg)](docs/CUSTODY.md)
[![Platform](https://img.shields.io/badge/platform-POSIX--first-555.svg)](docs/ARCHITECTURE.md)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

## What it provides

- **Deterministic evidence identities** — raw artifacts use SHA-256; structured records use canonical bytes and domain-separated identities.
- **Evidence classes** — `OBSERVED`, `DECLARED`, and `DERIVED` remain distinct.
- **Independent verification** — recompute integrity without trusting the monitored system or producer.
- **Append-only custody** — immutable, identity-bound history with explicit clock assurance.
- **Local-first storage** — content-addressed filesystem reference backend; no database service required.
- **Real observation paths** — Ollama, generic HTTP, and local process adapters.
- **Operator surfaces** — Rust CLI/TUI, stdio MCP, and read-only localhost UI.
- **Portable forensic packages** — evidence + custody + schemas + verification metadata + declared gaps.
- **Optional authenticity** — detached Ed25519 SSHSIG signatures and independently verifiable Git commit anchors.
- **Exact performance hardening** — bounded deterministic parallel verification with retained serial reference paths.
- **Selective disclosure** — redacted DERIVED artifacts with source digest lineage and optional source-bound transform recomputation.
- **Distributed custody handoff** — signed offline transfer offers/receipts with receiver-local custody and explicit partial ordering.
- **Release-grade trust lane** — fresh-checkout, pinned-toolchain full validation with complete tests and real Ollama integration.
- **Formal proof set** — Lean 4.34.1 models four frozen invariants with an explicit runtime bridge and independent proof checks.
- **Explicit uncertainty** — missing, digest-only, open-collection, and custody-gap states remain visible.

## Quick lifecycle

```text
OBSERVE / DECLARE
      ↓
ARTIFACTS + EVENTS
      ↓
APPEND-ONLY CUSTODY
      ↓
FINALIZED SNAPSHOT
      ↓
INDEPENDENT VERIFY
      ↓
INSPECT / EXPORT / PACKAGE
      ↓
OPTIONAL SIGN / REDACT / TRANSFER
```

Quick CLI example:

```bash
cargo build --manifest-path provenance-cli/Cargo.toml --locked
mkdir -p .demo

./provenance-cli/target/debug/provenance record \
  --store .demo/store --custody .demo/custody \
  --text "Hello from PROVENANCE" \
  --actor "operator:demo" --operation "demo.capture"

./provenance-cli/target/debug/provenance finalize \
  --store .demo/store --custody .demo/custody --scope closed

./provenance-cli/target/debug/provenance verify \
  --store .demo/store --custody .demo/custody

./provenance-cli/target/debug/provenance package \
  --store .demo/store --custody .demo/custody \
  --destination .demo/forensic-package
```

See [Getting Started](docs/GETTING_STARTED.md) for the walkthrough and [Usage Instructions](docs/INSTRUCTIONS.md) for the full interface guide.

## Architecture

```text
provenance-ui
      ↓
provenance-mcp / provenance-cli
      ↓
provenance-adapters / provenance-store / provenance-export
      ↓
provenance-core

evidence
   ↓
provenance-verify
```

The core remains provider- and interface-neutral. Verification consumes finalized evidence independently.

## Status

Implemented through **Phase 16**:

```text
canonical evidence core
independent verifier
local content-addressed store
append-only custody
Ollama reference observation + real-model CI
stdio MCP
Rust CLI/TUI
read-only localhost UI
generic HTTP/process adapters
portable forensic packages
detached Ed25519 signatures + Git anchors
bounded deterministic parallel verification
selective redacted disclosures
signed offline distributed custody
release-grade full trust lane
```

### Immutable implementation baseline

The frozen implementation baseline is:

```text
tag:    v1.0.0
commit: 0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742
```

The published GitHub release is immutable and the tag points directly to that commit.

For formalization and archival claims, **`v1.0.0` / `0b1a2eea…` is the implementation authority**. Later documentation, proof sources, archival metadata, and release-support material may advance on `main`, but they do not change the frozen implementation target.

Any future implementation, schema-semantic, verifier-semantic, or evidence-contract change must be treated as a new candidate rather than silently redefining `v1.0.0`.

Phase 17 is complete.

Phase 18 is now **in progress**. The initial Lean proof set formalizes four narrow claims against the frozen baseline:

```text
FV-01 self-hash exclusion
FV-02 append-only history extension
FV-03 classification non-promotion
FV-04 presentation non-interference
```

The proof toolchain is pinned to **Lean 4.34.1**, and the archival DOI is **10.5281/zenodo.23043860**.

The proof does not claim whole-program verification. See [Formal Verification](docs/FORMAL_VERIFICATION.md), [Archival Release](docs/ARCHIVAL_RELEASE.md), [Release Trust Lane](docs/RELEASE.md), and [Roadmap](docs/ROADMAP.md).

## Documentation

| Area | Document |
|---|---|
| Quick start | [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) |
| Detailed usage | [docs/INSTRUCTIONS.md](docs/INSTRUCTIONS.md) |
| Documentation index | [docs/README.md](docs/README.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Invariants | [docs/INVARIANTS.md](docs/INVARIANTS.md) |
| Roadmap | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Bundle | [docs/BUNDLE.md](docs/BUNDLE.md) |
| Store | [docs/STORE.md](docs/STORE.md) |
| Custody | [docs/CUSTODY.md](docs/CUSTODY.md) |
| Portable package | [docs/PACKAGE.md](docs/PACKAGE.md) |
| Signatures & anchors | [docs/TRUST.md](docs/TRUST.md) |
| Performance hardening | [docs/PERFORMANCE.md](docs/PERFORMANCE.md) |
| Privacy & selective disclosure | [docs/PRIVACY.md](docs/PRIVACY.md) |
| Distributed custody | [docs/TRANSFER.md](docs/TRANSFER.md) |
| Release-grade trust lane | [docs/RELEASE.md](docs/RELEASE.md) |
| Formal verification | [docs/FORMAL_VERIFICATION.md](docs/FORMAL_VERIFICATION.md) |
| Archival release | [docs/ARCHIVAL_RELEASE.md](docs/ARCHIVAL_RELEASE.md) |
| CLI/TUI | [docs/CLI.md](docs/CLI.md) |
| MCP | [docs/MCP.md](docs/MCP.md) |
| Read-only UI | [docs/UI.md](docs/UI.md) |
| Generic adapters | [docs/ADAPTERS.md](docs/ADAPTERS.md) |
| Ollama | [docs/OLLAMA.md](docs/OLLAMA.md) |
| Lineage | [docs/LINEAGE.md](docs/LINEAGE.md) |
| Donors | [docs/DONORS.md](docs/DONORS.md) |

Machine and contributor guidance stays at the root: [README4AIs.md](README4AIs.md) · [AGENTS.md](AGENTS.md).

## Boundaries

PROVENANCE does **not** invent hidden reasoning, infer provider-internal execution, silently repair gaps, or turn declarations into observations. Integrity verification does not by itself establish legal truth, intent, negligence, or scientific validity.

## Design law

```text
RECOMPUTE.
DO NOT TRUST STORED CLAIMS WHEN THEY CAN BE RECOMPUTED.
DO NOT REWRITE HISTORY.
DO NOT HIDE EVIDENCE GAPS.
```

> **Observe. Record. Bind. Verify. Never rewrite history.**

## License

Mozilla Public License 2.0 — [LICENSE](LICENSE).

**QSOL-IMC / QSOLKCB**
