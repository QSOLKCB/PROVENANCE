# Usage Instructions

This guide covers the normal PROVENANCE workflow and the major interfaces. Deep evidence semantics live in the linked specifications.

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
```

## Evidence classes

| Class | Meaning |
|---|---|
| `OBSERVED` | Directly captured at the declared observation boundary |
| `DECLARED` | Supplied or asserted by a caller/provider/operator |
| `DERIVED` | Computed from identified source evidence |

Do not promote declarations into observations simply because an adapter parsed them. See [INVARIANTS.md](INVARIANTS.md).

## Rust CLI

Build:

```bash
cargo build --manifest-path provenance-cli/Cargo.toml --locked
```

Development binary:

```text
./provenance-cli/target/debug/provenance
```

### Record text

```bash
./provenance-cli/target/debug/provenance record \
  --store /path/to/store \
  --custody /path/to/custody \
  --text "evidence" \
  --actor "operator:alice" \
  --operation "example.capture"
```

### Record a file

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

### Inspect

```bash
./provenance-cli/target/debug/provenance inspect \
  --store /path/to/store \
  --custody /path/to/custody
```

Use `--identity sha256:<digest>` for a known evidence identity.

### Finalize

```bash
./provenance-cli/target/debug/provenance finalize \
  --store /path/to/store \
  --custody /path/to/custody \
  --scope closed
```

Use `--scope open` when collection gaps must remain explicit.

### Verify

```bash
./provenance-cli/target/debug/provenance verify \
  --store /path/to/store \
  --custody /path/to/custody
```

### Export versus package

`export` is the historical verified Phase 2 snapshot-copy operation:

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

See [PACKAGE.md](PACKAGE.md).

## Optional Phase 12 authenticity

After creating a finalized Phase 11 package, you can add detached authenticity records without changing the package.

Generate an Ed25519 key if needed:

```bash
ssh-keygen -t ed25519 -f ./provenance-signing-key
```

Sign the exact canonical `package.json` bytes:

```bash
./provenance-cli/target/debug/provenance sign-package \
  --package /path/to/forensic-package \
  --key ./provenance-signing-key \
  --output ./package.signature.json
```

For a Git commit anchor, first write the canonical payload:

```bash
./provenance-cli/target/debug/provenance anchor-payload \
  --package /path/to/forensic-package \
  --output /path/to/repo/package.provenance
```

Commit that file, then create the detached anchor record:

```bash
./provenance-cli/target/debug/provenance anchor-git \
  --package /path/to/forensic-package \
  --git-repo /path/to/repo \
  --commit HEAD \
  --path package.provenance \
  --output ./package.git-anchor.json
```

Verify integrity, signature, and anchor separately:

```bash
./provenance-cli/target/debug/provenance verify-assurance \
  --package /path/to/forensic-package \
  --signature ./package.signature.json \
  --anchor ./package.git-anchor.json \
  --git-repo /path/to/repo
```

See [TRUST.md](TRUST.md) for exactly what these mechanisms prove—and what they do not.
## Read-only UI

```bash
python3 -m provenance_ui \
  --store /path/to/store \
  --custody /path/to/custody
```

Default bind: `127.0.0.1:8765`. Non-loopback binding requires explicit operator action. See [UI.md](UI.md).

## MCP

```bash
python3 -m provenance_mcp \
  --store /path/to/store \
  --custody /path/to/custody
```

Tools:

```text
provenance.record
provenance.inspect
provenance.verify
provenance.finalize
provenance.export
provenance.package
```

See [MCP.md](MCP.md).

## Adapters

Reference observation paths include local Ollama, generic HTTP/HTTPS, and local process execution. Provider-specific metadata stays behind a provider-neutral adapter boundary.

See [ADAPTERS.md](ADAPTERS.md) and [OLLAMA.md](OLLAMA.md).

## Python verification APIs

```python
from pathlib import Path
from provenance_verify import verify_bundle

report = verify_bundle(Path("/path/to/bundle"))
print(report.integrity_verified)
print(report.errors)
```

```python
from provenance_verify import verify_forensic_package

report = verify_forensic_package("/path/to/forensic-package")
print(report.integrity_verified)
print(report.package_identity)
print(report.errors)
```

## Focused test lanes

```bash
python3 -m unittest tests.test_core -v
python3 -m unittest tests.test_verify -v
python3 -m unittest tests.test_store -v
python3 -m unittest tests.test_custody -v
python3 -m unittest tests.test_mcp -v
python3 -m unittest tests.test_ui -v
python3 -m unittest tests.test_generic_adapters -v
python3 -m unittest tests.test_package -v
cargo test --manifest-path provenance-cli/Cargo.toml --locked
```

## Phase 13 reference and benchmark verification

Normal verification uses the bounded deterministic parallel path.

For conformance/debugging, the serial reference APIs remain available:

```python
from provenance_verify import (
    verify_bundle_reference,
    verify_forensic_package_reference,
)
```

Re-run the environment-scoped benchmark with:

```bash
python3 scripts/benchmark_phase13.py \
  --artifact-count 32 \
  --artifact-bytes 1048576 \
  --repetitions 5
```

Do not transfer benchmark numbers to another host without re-measuring. See [PERFORMANCE.md](PERFORMANCE.md).
## Phase 14 selective disclosure

A redacted disclosure is created from a retained artifact in a finalized Phase 11 package.

Example:

```bash
./provenance-cli/target/debug/provenance redact-disclosure \
  --package /path/to/forensic-package \
  --source sha256:<source-digest> \
  --range 17:29 \
  --output /path/to/disclosure
```

Verify disclosed lineage without revealing source bytes:

```bash
./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure /path/to/disclosure
```

If the original source package is available, additionally recompute the transform:

```bash
./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure /path/to/disclosure \
  --source-package /path/to/forensic-package
```

The disclosure retains the source digest and original ArtifactRecord metadata but omits the source content bytes. The derivative is always a new DERIVED artifact.

See [PRIVACY.md](PRIVACY.md) for privacy leakage limits, digest confirmation risks, and exact verification semantics.
## Phase 15 distributed custody handoff

A finalized Phase 11 package can be handed to an independently operated receiver without requiring a live network service.

Create the signed sender bundle:

```bash
./provenance-cli/target/debug/provenance transfer-create \
  --package /path/to/source-package \
  --source-system org-a/system-1 \
  --destination-system org-b/system-9 \
  --sender-key /path/to/sender-key \
  --output /path/to/transfer
```

Copy that directory through the chosen offline/store-and-forward channel.

At the receiver:

```bash
./provenance-cli/target/debug/provenance transfer-receive \
  --transfer /path/to/transfer \
  --package-destination /receiver/package \
  --receipt /receiver/receipt \
  --custody /receiver/custody \
  --receiver-system org-b/system-9 \
  --receiver-key /path/to/receiver-key
```

Verify the end-to-end handoff:

```bash
./provenance-cli/target/debug/provenance verify-receipt \
  --receipt /receiver/receipt \
  --transfer /path/to/transfer \
  --package /receiver/package
```

Do not compare sender and receiver wall clocks to infer order. The protocol exposes only evidence-backed partial-order edges. See [TRANSFER.md](TRANSFER.md).
## Operational rules

- Do not put secrets into evidence-bearing URLs, argv, prompts, or artifacts unless retention is intentional.
- Treat `DIGEST_ONLY`, `MISSING`, open scope, and incomplete custody as evidence states—not defects to hide.
- Do not edit finalized evidence to make verification pass.
- Preserve exact identities when transferring evidence.
- Prefer the independent verifier over producer/UI claims.

## Deep reference

[Architecture](ARCHITECTURE.md) · [Invariants](INVARIANTS.md) · [Store](STORE.md) · [Custody](CUSTODY.md) · [Bundle](BUNDLE.md) · [Package](PACKAGE.md) · [Trust](TRUST.md) · [Performance](PERFORMANCE.md) · [Privacy](PRIVACY.md) · [Transfer](TRANSFER.md) · [CLI](CLI.md) · [MCP](MCP.md) · [UI](UI.md) · [Adapters](ADAPTERS.md) · [Roadmap](ROADMAP.md)
