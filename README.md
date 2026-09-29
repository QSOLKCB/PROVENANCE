# PROVENANCE

> **Cryptographic chain of custody for LLMs, software, agents, tools, and automated systems.**

PROVENANCE records **who did what, when, where, why, and how — backed by evidence**. It captures actions, binds artifacts and events to cryptographic identities, preserves append-only custody, and independently verifies the resulting record.

**Start here:** [Getting Started](docs/GETTING_STARTED.md) · [Usage Instructions](docs/INSTRUCTIONS.md) · [Documentation](docs/README.md) · [Roadmap](docs/ROADMAP.md)

[![Version](https://img.shields.io/badge/version-v0.1--dev-4c1.svg)](docs/ROADMAP.md)
[![Phase](https://img.shields.io/badge/roadmap-Phase%2012%20implemented-2ea44f.svg)](docs/ROADMAP.md)
[![Core CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/core.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/core.yml)
[![Verify CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/verify.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/verify.yml)
[![Package CI](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/package.yml/badge.svg)](https://github.com/QSOLKCB/PROVENANCE/actions/workflows/package.yml)
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

Implemented through **Phase 12**: canonical core, verifier, local store, custody, Ollama + real-model CI, MCP, Rust CLI/TUI, read-only UI, generic adapters, portable forensic packages, and detached signatures/Git anchors.

Next: **Phase 13 — performance hardening**. See [the roadmap](docs/ROADMAP.md).

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
