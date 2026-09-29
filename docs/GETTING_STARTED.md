# Getting Started

Get from a fresh checkout to independently verified PROVENANCE evidence, a portable forensic package, and—when needed—signed, redacted, or transferred derivatives.

PROVENANCE is implemented through **Phase 16**. The normal local workflow remains lightweight; the heavier release-grade trust lane is separate.

## Requirements

For the normal reference workflow:

- Linux or another POSIX-style environment with descriptor-relative filesystem support.
- Python 3.12+.
- Rust/Cargo for the terminal CLI.
- Git.

Additional tools are needed only for specific features:

- `ssh-keygen` for Ed25519 signatures and signed transfer records.
- Ollama for the local real-model adapter path.
- GitHub Actions for the Phase 16 release-grade `full` lane.

The release lane pins its own toolchain versions; normal local development does not require you to reproduce those exact pins unless you are validating a release candidate. See [RELEASE.md](RELEASE.md).

## 1. Clone and build

```bash
git clone https://github.com/QSOLKCB/PROVENANCE.git
cd PROVENANCE

cargo build --manifest-path provenance-cli/Cargo.toml --locked
mkdir -p .demo
```

The development CLI is:

```text
./provenance-cli/target/debug/provenance
```

The CLI is a thin operator surface over the existing Python contracts; it does not define a second evidence format.

## 2. Record evidence

```bash
./provenance-cli/target/debug/provenance record \
  --store .demo/store \
  --custody .demo/custody \
  --text "Hello from PROVENANCE" \
  --actor "operator:demo" \
  --operation "demo.capture"
```

Operator-supplied content remains **DECLARED** evidence.

The CLI separately records the invocation occurrence as **OBSERVED** evidence, so repeating identical declared content does not erase the fact that separate calls occurred.

## 3. Inspect working evidence

```bash
./provenance-cli/target/debug/provenance inspect \
  --store .demo/store \
  --custody .demo/custody
```

Use `--identity sha256:<digest>` when you already know the identity you want to inspect.

## 4. Finalize

```bash
./provenance-cli/target/debug/provenance finalize \
  --store .demo/store \
  --custody .demo/custody \
  --scope closed
```

Use `--scope open` when collection is intentionally incomplete or a known evidence gap must remain explicit.

Finalization does not rewrite earlier evidence. It seals the current immutable snapshot.

## 5. Verify independently

```bash
./provenance-cli/target/debug/provenance verify \
  --store .demo/store \
  --custody .demo/custody
```

Verification recomputes the evidence bundle and custody chain rather than trusting producer claims.

The core rule is:

```text
RECOMPUTE
NOT TRUST
```

## 6. Create a portable forensic package

```bash
./provenance-cli/target/debug/provenance package \
  --store .demo/store \
  --custody .demo/custody \
  --destination .demo/forensic-package
```

The Phase 11 forensic package contains:

```text
finalized evidence bundle
custody snapshot
schema/version metadata
verification metadata
declared gaps
portable member identities
```

It can be moved to another machine and independently verified without the original monitored application.

See [PACKAGE.md](PACKAGE.md).

## 7. Optional: sign the package

Generate an Ed25519 key:

```bash
ssh-keygen -t ed25519 -f .demo/signing-key
```

Create a detached signature:

```bash
./provenance-cli/target/debug/provenance sign-package \
  --package .demo/forensic-package \
  --key .demo/signing-key \
  --output .demo/package.signature.json
```

Verify package integrity and the detached signature as separate assurance dimensions:

```bash
./provenance-cli/target/debug/provenance verify-assurance \
  --package .demo/forensic-package \
  --signature .demo/package.signature.json
```

A valid signature proves possession of the corresponding key over the signed bytes. It does not by itself prove a legal or organizational identity.

See [TRUST.md](TRUST.md) for Git commit anchoring and the exact trust boundary.

## 8. Optional: read-only viewer

```bash
python3 -m provenance_ui \
  --store .demo/store \
  --custody .demo/custody
```

Open:

```text
http://127.0.0.1:8765/
```

The viewer is read-only. Removing or replacing it does not alter evidence identities or verification semantics.

See [UI.md](UI.md).

## 9. Optional: create a redacted disclosure

For a retained artifact identity in the forensic package:

```bash
./provenance-cli/target/debug/provenance redact-disclosure \
  --package .demo/forensic-package \
  --source sha256:<artifact-digest> \
  --range START:END \
  --output .demo/disclosure
```

Verify the disclosure and, when the original package is available, recompute the transform:

```bash
./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure .demo/disclosure \
  --source-package .demo/forensic-package
```

The original evidence is unchanged. The redacted output is a new **DERIVED** artifact with explicit lineage.

See [PRIVACY.md](PRIVACY.md).

## 10. Optional: hand the package to another system

Phase 15 supports signed offline/store-and-forward custody transfer between independently operated systems.

Create a sender transfer bundle:

```bash
./provenance-cli/target/debug/provenance transfer-create \
  --package .demo/forensic-package \
  --source-system sender/demo \
  --destination-system receiver/demo \
  --sender-key /path/to/sender-key \
  --output .demo/transfer
```

Check the transfer bundle:

```bash
./provenance-cli/target/debug/provenance verify-transfer \
  --transfer .demo/transfer
```

At the receiver, acceptance requires a sender fingerprint obtained through an **independent trust channel**. Do not treat the fingerprint embedded in the same untrusted transfer as independent authentication.

```bash
./provenance-cli/target/debug/provenance transfer-receive \
  --transfer /path/to/offline-transfer \
  --package-destination /receiver/package \
  --receipt /receiver/receipt \
  --custody /receiver/custody \
  --receiver-system receiver/demo \
  --receiver-key /path/to/receiver-key \
  --expected-sender-fingerprint 'SHA256:<trusted-sender-fingerprint>'
```

Verify the receiver acknowledgement:

```bash
./provenance-cli/target/debug/provenance verify-receipt \
  --receipt /receiver/receipt \
  --transfer /path/to/offline-transfer \
  --package /receiver/package
```

The protocol preserves **partial ordering**. Sender and receiver wall clocks are not compared to invent a global sequence.

See [TRANSFER.md](TRANSFER.md).

## 11. Optional: MCP interface

Start the dependency-free stdio server:

```bash
python3 -m provenance_mcp \
  --store .demo/store \
  --custody .demo/custody
```

The MCP surface exposes the same underlying evidence contracts. Caller-provided values remain DECLARED unless independently observed.

See [MCP.md](MCP.md).

## 12. Before tagging a release candidate

Phase 16 adds the release-grade `full` workflow.

The important rule is:

```text
GREEN RUN
MUST MATCH
THE EXACT COMMIT YOU TAG
```

For the release candidate:

1. merge all intended code and documentation changes;
2. identify the resulting exact `main` SHA;
3. run or confirm the `full` workflow on that exact SHA;
4. require `release-suite`, both Ollama matrix jobs, and `release-gate` to succeed;
5. record the SHA and workflow run;
6. tag that exact SHA.

Useful local check:

```bash
git checkout main
git pull --ff-only
git rev-parse HEAD
```

If the tag is intended to become the **Phase 17 immutable candidate freeze**, no implementation, schema-semantic, verifier-semantic, or evidence-contract change should follow it. A required implementation fix means returning to Phase 16, re-running the release lane, and cutting a new candidate.

Phase 17 freezes the implementation. Phase 18 performs formal verification and the final archival release.

See [RELEASE.md](RELEASE.md) and [ROADMAP.md](ROADMAP.md).

## Next

- [Full usage instructions](INSTRUCTIONS.md)
- [Release-grade trust lane](RELEASE.md)
- [Documentation index](README.md)
- [Architecture](ARCHITECTURE.md)
- [Evidence invariants](INVARIANTS.md)
- [Portable package](PACKAGE.md)
- [Distributed transfer](TRANSFER.md)
- [Roadmap](ROADMAP.md)
