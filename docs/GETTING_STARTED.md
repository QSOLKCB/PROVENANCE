# Getting Started

Get from a fresh checkout to a verified PROVENANCE forensic package in a few minutes.

## Requirements

- Linux or another POSIX-style environment with descriptor-relative filesystem support.
- Python 3.12+ for the reference implementation and interfaces.
- Rust/Cargo for the terminal CLI.
- Git.

PROVENANCE works locally. Ollama is optional unless you want the real-model adapter path.

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

## 2. Record evidence

```bash
./provenance-cli/target/debug/provenance record \
  --store .demo/store \
  --custody .demo/custody \
  --text "Hello from PROVENANCE" \
  --actor "operator:demo" \
  --operation "demo.capture"
```

Operator-supplied content remains **DECLARED**. The CLI separately records the invocation occurrence as **OBSERVED** evidence.

## 3. Finalize

```bash
./provenance-cli/target/debug/provenance finalize \
  --store .demo/store \
  --custody .demo/custody \
  --scope closed
```

Use `--scope open` only when known evidence gaps or ongoing collection must remain explicit.

## 4. Verify

```bash
./provenance-cli/target/debug/provenance verify \
  --store .demo/store \
  --custody .demo/custody
```

Verification independently recomputes bundle integrity and custody-chain integrity.

## 5. Create a portable forensic package

```bash
./provenance-cli/target/debug/provenance package \
  --store .demo/store \
  --custody .demo/custody \
  --destination .demo/forensic-package
```

The Phase 11 package includes the finalized evidence bundle, custody snapshot, schema metadata, verification metadata, and declared gaps. It can be moved to another machine and independently verified.

## 6. Optional: sign the package

```bash
ssh-keygen -t ed25519 -f .demo/signing-key

./provenance-cli/target/debug/provenance sign-package \
  --package .demo/forensic-package \
  --key .demo/signing-key \
  --output .demo/package.signature.json

./provenance-cli/target/debug/provenance verify-assurance \
  --package .demo/forensic-package \
  --signature .demo/package.signature.json
```

This verifies key-to-bytes authenticity separately from package integrity. See [TRUST.md](TRUST.md) for Git commit anchoring and the proof boundary.

## 7. Optional: read-only viewer

```bash
python3 -m provenance_ui \
  --store .demo/store \
  --custody .demo/custody
```

Open `http://127.0.0.1:8765/`.

## Optional: create a redacted disclosure

For a retained artifact identity in a package:

```bash
./provenance-cli/target/debug/provenance redact-disclosure \
  --package .demo/forensic-package \
  --source sha256:<artifact-digest> \
  --range START:END \
  --output .demo/disclosure

./provenance-cli/target/debug/provenance verify-disclosure \
  --disclosure .demo/disclosure \
  --source-package .demo/forensic-package
```

The original package is unchanged. See [PRIVACY.md](PRIVACY.md).
## Optional: hand the package to another system

For independently operated sender/receiver environments:

```bash
./provenance-cli/target/debug/provenance transfer-create \
  --package .demo/forensic-package \
  --source-system sender/demo \
  --destination-system receiver/demo \
  --sender-key /path/to/sender-key \
  --output .demo/transfer
```

The resulting transfer directory can be moved offline and accepted later with `transfer-receive`.

See [TRANSFER.md](TRANSFER.md) before using distributed custody in a real deployment; system labels and signing keys do not automatically prove legal/organizational identity.
## Next

- [Full usage instructions](INSTRUCTIONS.md)
- [Documentation index](README.md)
- [Architecture](ARCHITECTURE.md)
- [Evidence bundle](BUNDLE.md)
- [Portable package](PACKAGE.md)
- [Roadmap](ROADMAP.md)
