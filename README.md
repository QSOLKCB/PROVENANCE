# PROVENANCE

**Cryptographic Chain of Custody for LLMs, Systems & Software**

> **Who did what, when, where, why, and how — backed by evidence.**

PROVENANCE is a framework-agnostic evidence and observability system for recording the actions of AI systems, software, agents, tools, and automated workflows.

Its purpose is simple:

**Record what happened well enough that somebody else can independently reconstruct and verify it later.**

If an AI system makes a medical recommendation, a legal analysis, executes a tool, modifies a file, calls an API, retrieves a document, selects an action, or causes another system to act, PROVENANCE is intended to preserve the chain of events that led there.

It does **not** decide whether the action was correct.

It preserves the evidence.

---

## The Core Principle

PROVENANCE is an **observer**, not a controller.

It must not silently alter:

- prompts;
- model responses;
- tool inputs;
- tool outputs;
- application state;
- decisions;
- execution order;
- external actions; or
- the behaviour of the system being observed.

The monitored system remains the system of record for its own behaviour.

PROVENANCE records that behaviour from the outside or through minimally invasive instrumentation.

> **Observe. Record. Bind. Verify. Never rewrite history.**

---

## Run the tests

From the repository root, run the complete dependency-free test suite with:

```bash
cd ~/PROVENANCE
python3 -m unittest discover -s tests -v
```

If you cloned PROVENANCE somewhere else, change the `cd` path accordingly.

This runs all current module tests. GitHub Actions uses narrower module-specific lanes for speed, but the full local command above is the simplest way to reproduce the complete suite.

## MCP stdio interface

Phase 7 adds a dependency-free MCP server over stdio:

```bash
python3 -m provenance_mcp \
  --store /path/to/store \
  --custody /path/to/custody
```

The initial tool surface is:

```text
provenance.record
provenance.inspect
provenance.verify
provenance.finalize
provenance.export
```

Caller assertions sent through `provenance.record` remain **DECLARED**. The server separately records an **OBSERVED** per-call receipt so repeated identical declarations do not erase evidence that multiple MCP calls occurred.

See `MCP.md` for the transport, resource, compatibility, and evidence-boundary contract.

---

## Why PROVENANCE Exists

Modern AI systems rarely perform a single isolated operation.

A seemingly simple answer may involve:

```text
User Input
    ↓
Application Logic
    ↓
System / Developer Instructions
    ↓
Model Invocation
    ↓
Retrieval
    ↓
External Documents
    ↓
Tool Calls
    ↓
APIs
    ↓
Intermediate State
    ↓
Model Output
    ↓
Policy / Validation Logic
    ↓
External Action
    ↓
Human Review
```

When something goes wrong, a final output alone is often insufficient.

The important questions become:

| Question | Evidence required |
|---|---|
| **Who?** | Which human, service, model, agent, process, or identity acted? |
| **What?** | What operation, decision, request, response, mutation, or action occurred? |
| **When?** | When was it observed, produced, transferred, or executed? |
| **Where?** | Which host, runtime, service, repository, jurisdiction, device, or execution context was involved? |
| **Why?** | What observable inputs, rules, context, evidence, or declared rationale preceded the action? |
| **How?** | Which model, software, configuration, tools, parameters, dependencies, and execution path produced it? |

PROVENANCE exists to preserve those answers.

---

## Evidence, Not Interpretation

PROVENANCE should distinguish between different kinds of information.

### Observed evidence

Information directly captured from the monitored system.

Examples:

- a request;
- a response;
- a file hash;
- a tool invocation;
- a retrieved document;
- a model identifier;
- an API result;
- a process exit code;
- a timestamp;
- a state transition.

### Declared evidence

Information asserted by another component.

Examples:

- a model reporting its own identifier;
- an application supplying a session ID;
- an operator declaring a case number;
- an external service supplying metadata.

Declared evidence is recorded **as a declaration**, not silently promoted into independently verified fact.

### Derived evidence

Information calculated from existing evidence.

Examples:

- SHA-256 digests;
- canonical record hashes;
- Merkle roots;
- elapsed time;
- dependency graphs;
- verification results;
- replay comparisons.

Derived evidence must identify what it was derived from.

These categories should never be silently collapsed into one another.

---

## What “Why” Means

PROVENANCE does **not** claim access to hidden model reasoning.

It does not invent explanations for an AI after the fact.

For AI systems, the evidence behind **why** an action occurred may include observable material such as:

- system and application instructions;
- user input;
- retrieved context;
- source documents;
- model and provider identity;
- model configuration;
- tool availability;
- tool calls and results;
- policy or validation decisions;
- application state;
- prior events;
- explicit machine-readable decision codes;
- explicit rationale supplied by the monitored system;
- human approvals or overrides.

If the system did not expose a reason, PROVENANCE records that fact.

**Absence of evidence must not be replaced with an invented explanation.**

---

# Chain of Custody

PROVENANCE treats recorded events as evidence.

That means custody matters.

A useful record must establish more than:

> “Here is a JSON file saying something happened.”

It should make it possible to determine:

1. what was captured;
2. where it originated;
3. when it was captured;
4. how it entered the evidence system;
5. whether it changed;
6. what other events preceded it;
7. what events followed it;
8. who or what handled it;
9. which transformations were performed;
10. whether those transformations can be independently reproduced or verified.

Cryptographic hashes bind evidence to its recorded representation.

Linked events bind individual observations into a history.

Digital signatures may bind records to identities.

Manifests bind collections of evidence into verifiable units.

The result is intended to behave more like a **forensic evidence trail** than an ordinary application log.

---

## Evidence Must Remain Evidence

PROVENANCE follows a simple rule:

> **Never modify the original evidence in order to make it easier to explain.**

Presentation and evidence are separate layers.

For example:

```text
Raw Observation
       │
       ├── Cryptographic Identity
       │
       ├── Custody Record
       │
       └── Canonical Evidence Record
                    │
                    ├── Index
                    ├── Timeline
                    ├── Search
                    ├── Visualization
                    ├── Report
                    └── Derived Analysis
```

Reports may summarize evidence.

Interfaces may visualize evidence.

Indexes may reorganize references to evidence.

Analysis may derive conclusions from evidence.

But none of those operations should silently replace the underlying record.

If evidence must be redacted, transformed, normalized, exported, or summarized, the resulting artifact should be treated as a **new derivative artifact** linked back to its source.

---

# Cryptographic Integrity

PROVENANCE is intended to support cryptographically verifiable records.

Potential primitives include:

- SHA-256 content identities;
- canonical serialization;
- event hashes;
- previous-event links;
- manifests;
- Merkle structures;
- digital signatures;
- signed checkpoints;
- immutable evidence bundles.

An event chain can conceptually resemble:

```text
EVENT 0001
hash: A91F...
previous: null

    ↓

EVENT 0002
hash: 38C2...
previous: A91F...

    ↓

EVENT 0003
hash: F742...
previous: 38C2...

    ↓

CHECKPOINT
root: 991A...
events: 0001..0003
```

Changing historical evidence should therefore produce a verifiable inconsistency rather than silently changing history.

---

# Event Model

The exact schema is still under development.

A future PROVENANCE event may conceptually contain information similar to:

```json
{
  "schema": "provenance.event.v0",
  "event_id": "018f...",
  "timestamp": "2026-09-28T14:00:00Z",

  "actor": {
    "type": "ai-model",
    "id": "provider:model:version"
  },

  "operation": {
    "type": "tool_call",
    "name": "example.operation"
  },

  "inputs": [
    {
      "sha256": "..."
    }
  ],

  "outputs": [
    {
      "sha256": "..."
    }
  ],

  "context": {
    "session": "...",
    "runtime": "...",
    "adapter": "..."
  },

  "previous_event_hash": "sha256:...",
  "event_hash": "sha256:..."
}
```

This example is **illustrative, not normative**.

The eventual schema should be minimal, deterministic, versioned, extensible, and independently implementable.

---

# Non-Interference

An evidence system becomes dangerous if observing a system changes the system being observed.

PROVENANCE therefore aims for **non-interference by design**.

Instrumentation should:

- avoid modifying application inputs or outputs;
- avoid influencing model selection or model sampling;
- avoid changing application decisions;
- avoid introducing hidden control logic;
- avoid becoming a required decision authority;
- keep monitoring work outside latency-sensitive execution where practical;
- make collection failures visible rather than silently altering application behaviour.

The monitored application should not need to ask PROVENANCE:

> “Am I allowed to do this?”

PROVENANCE should instead be capable of answering:

> “This is what the application did.”

---

# Framework Agnostic

PROVENANCE is not intended to belong to one AI vendor, model provider, orchestration library, programming language, or deployment model.

The same evidence model should be usable with:

- hosted LLM APIs;
- local LLMs;
- agent frameworks;
- RAG systems;
- autonomous tools;
- traditional software;
- microservices;
- command-line programs;
- desktop applications;
- servers;
- embedded systems;
- human-in-the-loop workflows;
- mixed human/AI systems.

Integration may eventually occur through:

```text
Native SDK
    │
Adapter
    │
Middleware Hook
    │
Sidecar
    │
Proxy
    │
Event Bridge
    │
External Observer
```

Different integrations may observe different layers of a system.

PROVENANCE should make those observation boundaries explicit rather than pretending every integration has perfect visibility.

---

# A Typical AI Evidence Trail

Consider an AI-assisted medical system.

A decision might involve:

```text
Patient / Operator Request
          ↓
Application Version
          ↓
Prompt Template
          ↓
Model + Configuration
          ↓
Retrieved Medical References
          ↓
Tool Invocation
          ↓
Tool Result
          ↓
Model Response
          ↓
Application Rule
          ↓
Human Review
          ↓
Final Action
```

If the final action later becomes disputed, PROVENANCE should make it possible to determine which parts of that sequence can actually be demonstrated from retained evidence.

It should not conclude:

> “The AI committed malpractice.”

It should be capable of demonstrating facts such as:

> This input was submitted.

> This model and configuration were invoked.

> These documents were supplied as context.

> This tool returned this result.

> This response was produced.

> This validation rule returned this result.

> This human approved, rejected, modified, or did not review the action.

> These records cryptographically correspond to the evidence retained at the time.

The interpretation belongs to investigators, auditors, operators, experts, courts, regulators, researchers, and other authorised humans.

PROVENANCE supplies the evidence.

---

# Not Just AI

Although AI accountability is an important use case, the architecture should not depend on AI.

The same approach can record:

- software build provenance;
- scientific computational workflows;
- autonomous infrastructure;
- financial systems;
- robotic actions;
- security events;
- deployment pipelines;
- document transformations;
- API workflows;
- data-processing systems;
- administrative decisions;
- distributed systems.

AI is simply one particularly important producer of events.

---

# PROVENANCE Is Not

PROVENANCE is **not** intended to become:

- an AI alignment system;
- a content moderation system;
- a policy engine;
- a permission system;
- a behavioural guardrail;
- a model evaluator;
- a truth oracle;
- a liability engine;
- an automatic judge;
- a replacement for human investigation;
- a system for manufacturing explanations.

It records evidence.

That boundary is intentional.

---

# Failure Must Also Leave Evidence

A monitoring system cannot promise that every observation will always succeed.

Processes crash.

Networks disappear.

Disks fill.

Collectors fail.

Machines lose power.

Applications terminate unexpectedly.

A trustworthy provenance system must therefore distinguish:

```text
"No event occurred"
```

from:

```text
"No event was observed"
```

and from:

```text
"An event may have occurred during an identified evidence gap"
```

Missing evidence is itself important evidence about the limits of the record.

PROVENANCE should never silently manufacture continuity where continuity cannot be demonstrated.

---

# Privacy and Sensitive Evidence

Provenance records may contain extremely sensitive material.

Examples include:

- medical information;
- legal documents;
- personal identifiers;
- proprietary prompts;
- source code;
- credentials;
- confidential business information;
- model inputs and outputs.

Cryptographic integrity does **not** imply that all evidence should be publicly visible.

The architecture should separate:

```text
Integrity
Custody
Identity
Confidentiality
Authorization
Presentation
```

An investigator may be able to prove that an artifact is unchanged without necessarily being permitted to read that artifact.

Data minimization, encryption, access control, retention policy, and jurisdictional requirements remain responsibilities of deployments using PROVENANCE.

---

# Design Principles

PROVENANCE begins with the following principles:

### 1. Evidence before interpretation

Record what happened before attempting to explain what it means.

### 2. Original evidence is immutable

Corrections create new records. They do not rewrite old ones.

### 3. Derived information identifies its sources

A conclusion must not masquerade as a direct observation.

### 4. Cryptographic identity over filenames

Evidence should be identifiable by content, not merely by mutable paths or labels.

### 5. Custody is part of the evidence

Capture, transfer, storage, transformation, export, and verification should be traceable.

### 6. Observation boundaries are explicit

Never claim visibility that the collector did not possess.

### 7. Missing evidence remains missing

Do not infer missing events merely to produce a complete-looking timeline.

### 8. No manufactured rationale

Observable causes may be recorded. Hidden reasoning must not be invented.

### 9. Monitoring must not become control

PROVENANCE observes systems. It does not secretly govern them.

### 10. Verification should not require trust in PROVENANCE

Where practical, evidence bundles and cryptographic claims should be independently verifiable using documented formats and ordinary cryptographic tools.

---

# Modular Architecture

PROVENANCE is being built as a **modular monorepo** with one evidence contract and replaceable surfaces.

```text
provenance-ui
      ↓
provenance-mcp / provenance-cli
      ↓
provenance-adapters / provenance-store
      ↓
provenance-core

evidence
   ↓
provenance-verify
```

The core must remain independent of UI, transport, provider, storage backend, and application policy.

The logical modules are:

| Module | Responsibility |
|---|---|
| `provenance-core` | Canonical evidence semantics, identities, events, relationships, manifests |
| `provenance-verify` | Independent recomputation and verification |
| `provenance-store` | Replaceable evidence persistence |
| `provenance-adapters` | Framework-specific observation |
| `provenance-mcp` | MCP tools and resources |
| `provenance-cli` | Lightweight operator interface |
| `provenance-ui` | Read-only human inspection |

The initial Python reference module is imported as `provenance_core`; the hyphenated names above describe architectural modules rather than Python import syntax.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module contracts and dependency rules.

See [BUNDLE.md](BUNDLE.md) for the Phase 2 evidence-bundle layout consumed by the independent verifier.

See [STORE.md](STORE.md) for the Phase 3 local content-addressed storage contract.

See [CUSTODY.md](CUSTODY.md) for the Phase 4 append-only custody and clock-observation contract.

See [OLLAMA.md](OLLAMA.md) for the Phase 5 local Ollama observation contract and Phase 6 real-model CI boundary.

See [MCP.md](MCP.md) for the Phase 7 stdio MCP interface contract.

See [CLI.md](CLI.md) for the Phase 8 Rust terminal CLI/TUI contract.

---

# Implementation Roadmap

Development is phase-gated.

The current sequence begins:

```text
Phase 0  Constitutional foundation
   ↓
Phase 1  Canonical evidence core
   ↓
Phase 2  Independent verifier
   ↓
Phase 3  Local evidence store
   ↓
Phase 4  Minimal custody
   ↓
Phase 5  Ollama reference adapter
   ↓
Phase 6  Ollama GitHub Actions smoke test
   ↓
Phase 7  MCP
   ↓
Phase 8  Rust terminal CLI/TUI
   ↓
Phase 9  read-only local viewer
   ↓
additional adapters
```

The full roadmap, exit gates, CI progression, and later trust/privacy/distributed phases are defined in [ROADMAP.md](ROADMAP.md).

The implementation rule is deliberately simple:

> **Build the smallest trustworthy layer. Prove it. Then add the next layer.**

---

# The Standard PROVENANCE Should Meet

A useful test for this project is simple.

Imagine a serious incident occurred five years ago.

The original developers are gone.

The vendor may no longer exist.

The machine that executed the system is unavailable.

Someone hands an independent investigator the retained PROVENANCE evidence.

That investigator should be able to ask:

> What happened?

> In what order?

> Which system performed each action?

> What information did it actually have?

> Which external systems did it use?

> Which artifacts can still be verified?

> What changed?

> Who handled the evidence?

> Where does the record contain gaps?

> Which statements are direct observations?

> Which statements came from another party?

> Which conclusions were derived later?

And the evidence should answer those questions **without requiring blind trust in the software that produced the report**.

That is the target.

---

# Status

**Bootstrap / Phase 8 implementation.**

The constitutional and architectural foundation is in place. The first executable module is now `provenance_core`, covering the initial Phase 1 surface:

- canonical UTF-8 JSON records;
- duplicate-key, BOM, non-finite and unsupported-number rejection;
- ordinary SHA-256 raw-content identities;
- domain-separated artifact-record, event, and manifest identities;
- `OBSERVED`, `DECLARED`, and `DERIVED` evidence classes;
- collection-status and retention-state vocabulary;
- source-bound DERIVED events;
- explicit retained, digest-only, and missing artifact states in manifests;
- core/envelope self-hash exclusion;
- normalized manifest membership; and
- focused dependency-free regression tests.

The independent verifier is now implemented in `provenance_verify`, with canonical bundle verification, artifact/event identity recomputation, exact physical membership checks, retained-content hash and byte-count verification, explicit missing-evidence handling, reference resolution, symlink rejection, and adversarial tamper tests.

The local evidence store is now implemented in `provenance_store`, with content-addressed immutable objects, atomic no-overwrite publication, exact-byte deduplication, verifier-gated snapshots, atomic `HEAD` publication, reopen-from-verified-state, stale-writer rejection, and explicit recovery from previously missing evidence.

The minimal custody chain is now implemented through `provenance_core`, `provenance_verify`, and `provenance_custody`: domain-separated custody identities, append-only per-subject chains, explicit unknown actor/source values, clock-source assurance, independent chain verification, and a local immutable custody ledger.

The first real-system adapter is now implemented in `provenance_adapters` for local Ollama. It retains exact request/response bytes, distinguishes observed exchange data from Ollama-declared model identity, records custody, and finalizes through the existing independent verifier.

A dedicated Ollama Actions lane launches independent small-model instances on clean runners and verifies both successful evidence capture and retained-byte tamper detection.

The stdio MCP interface and the Rust terminal CLI/TUI are now implemented. The CLI exposes record, inspect, verify, finalize, export, and a keyboard-first slash-command palette while delegating evidence semantics and independent verification to the existing modules. MCP and CLI share one hardened operational working-state journal so acknowledged pending evidence cannot silently diverge between interfaces.

The local pure-HTML/CSS/JS viewer and generic/provider adapters remain later roadmap phases.

Interfaces and compatibility guarantees should still be considered unstable until explicitly versioned and released.

---

# Philosophy

PROVENANCE does not exist to tell a system what it should have done.

It exists so that, after the fact, we do not have to guess what it actually did.

```text
No rewritten history.
No invented reasoning.
No hidden interpretation.
No silent evidence gaps.
No interference.

Just the record.
```

Or, less formally:

> **Here's the evidence. We know exactly what you did. Tell it to the judge.**

---

## License

PROVENANCE is licensed under the [Mozilla Public License 2.0](LICENSE).

---

**QSOL-IMC / QSOLKCB**

*Evidence first. Interpretation belongs downstream.*
