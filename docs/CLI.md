# PROVENANCE CLI / Terminal Interface — Phase 8

## Status

~~~text
INTERFACE=provenance-cli:rust/v1
FRONTEND=Rust
BACKEND=existing Python reference modules
MCP_REQUIRED=NO
NETWORK_REQUIRED=NO
RUST_CRATE_DEPENDENCIES=NONE
~~~

Phase 8 adds a terminal-native human/operator surface without changing the evidence contract.

The Rust binary is intentionally small. It performs command discovery, argv handling, project-root discovery, exit-code propagation, and the interactive slash-command palette.

Evidence operations remain in the existing reference modules:

~~~text
provenance_core
provenance_store
provenance_custody
provenance_verify
~~~

The CLI does not implement a second verifier.

---

# Build

From the repository root:

~~~bash
cargo build --manifest-path provenance-cli/Cargo.toml --locked
~~~

The binary is:

~~~text
provenance-cli/target/debug/provenance
~~~

The initial implementation is checkout-native. It locates the repository automatically when run from the checkout/build tree. Set PROVENANCE_ROOT when invoking the binary from elsewhere.

PROVENANCE_ROOT selects where the implementation is loaded from; it does not change the caller's working directory. Relative --store, --custody, --file, and --destination paths are resolved relative to the directory from which the operator invoked provenance.

PROVENANCE_PYTHON may select the Python executable. The default is python3.

---

# Commands

The initial surface is:

~~~text
provenance record
provenance inspect
provenance verify
provenance finalize
provenance export
provenance package
provenance tui
~~~

All evidence commands take explicit local roots:

~~~text
--store /path/to/store
--custody /path/to/custody
~~~

No daemon, MCP transport, HTTP server, cloud account, or provider login is required.

---

# Record

Example:

~~~bash
provenance record \
  --store ./evidence \
  --custody ./custody \
  --file ./source.bin \
  --actor operator:alice \
  --operation file.capture
~~~

Operator-supplied content and meaning is recorded as DECLARED evidence.

The CLI separately emits a unique retained invocation receipt as OBSERVED evidence with actor provenance-cli:rust/v1.

This preserves the distinction:

~~~text
operator declaration
→ DECLARED

CLI receipt of invocation
→ OBSERVED
~~~

Identical declarations may deduplicate by content identity while separate CLI invocations remain separate recorded occurrences.

The --digest-only option retains the content identity and artifact metadata without retaining the source bytes.

Authentication is not implemented in Phase 8. Later provider-auth work must keep credentials outside ordinary evidence payloads.

---

# Shared working-state continuity

Phase 8 does not create a separate CLI pending-evidence universe.

For compatibility with the merged Phase 7 implementation, CLI and MCP deliberately share the same hardened operational lock and working-state journal:

~~~text
.provenance-mcp-working.lock
.provenance-mcp-working.json
provenance.mcp-working-state.v1
~~~

The names are historical. This state is operational metadata, not an MCP evidence format and not part of finalized evidence identity.

This sharing means:

~~~text
MCP acknowledges A
CLI acknowledges B
    ↓
one serialized durable working set
    ↓
either interface may finalize A ∪ B
~~~

The CLI revalidates journal artifact membership, pending verification subjects, HEAD lineage, and retained object state through existing store contracts before proceeding.

---

# Finalize and verify

~~~bash
provenance finalize \
  --store ./evidence \
  --custody ./custody \
  --scope closed

provenance verify \
  --store ./evidence \
  --custody ./custody
~~~

Finalization delegates to LocalEvidenceStore.finalize().

Verification delegates to LocalEvidenceStore.verify_current(), LocalCustodyLedger.verify(), and provenance_verify.

The Rust surface does not recompute or reinterpret evidence itself.

---

# Inspect

Without an identity:

~~~bash
provenance inspect --store ./evidence --custody ./custody
~~~

reports current manifest identity, working artifact/event counts, pending counts, and the current manifest when present.

With an identity:

~~~bash
provenance inspect \
  --store ./evidence \
  --custody ./custody \
  --identity sha256:<digest>
~~~

resolves the identity as a known artifact, event, manifest, or custody record.

---

# Export

~~~bash
provenance export \
  --store ./evidence \
  --custody ./custody \
  --destination ./exported
~~~

Phase 8 export is the same narrow snapshot-copy concept used by the MCP interface:

~~~text
current verified snapshot
→ descriptor-bound copy
→ independent verify_bundle(copy)
→ EXPORTED custody
~~~

It does not claim completion of the later Phase 11 portable forensic-package contract.

---

# Slash-command terminal mode

Start:

~~~bash
provenance tui --store ./evidence --custody ./custody
~~~

Typing a single slash opens the palette:

~~~text
/record
/inspect
/verify
/finalize
/export
~~~

Typing a prefix such as /ver filters the palette.

Exact commands execute keyboard-first:

~~~text
/verify
/inspect
/finalize --scope closed
/record --file evidence.bin --actor operator:alice --operation file.capture
/export --destination ./exported
~~~

/quit exits.

The TUI preserves a machine-detectable failure result across the session. If any executed slash command returns a non-zero backend status, the TUI remembers the first failure status and returns it when the session exits or stdin closes. A later successful command does not erase that failure status.

This first terminal UI is intentionally line-mode rather than a full-screen terminal framework. It establishes the interaction contract without introducing curses, a rendering framework, or external Rust crates.

---

# Self-demonstration

Phase 8 CI builds the real Rust binary and executes:

~~~text
record
↓
inspect working state
↓
finalize
↓
verify
↓
export
↓
independent verify_bundle(export)
~~~

A second integration test launches two independent Rust CLI processes concurrently against the same empty roots and requires both acknowledged records to appear in the same finalized verified bundle.

The palette is also driven through stdin to prove slash-command discovery works without a graphical UI.

The CLI workflow is triggered by changes to the Rust surface, the Python CLI backend, and its transitive PROVENANCE contracts: core, store, custody, verifier, and MCP interoperability. This prevents a lower-layer change from bypassing terminal lifecycle coverage merely because no CLI-owned file changed.

The integration suite also executes the built binary from outside the repository with PROVENANCE_ROOT pointing back to the checkout. That regression requires relative source, store, custody, and export paths to remain anchored to the caller's working directory.

---

# Core rule

~~~text
RUST HANDLES THE TERMINAL.
EXISTING MODULES HANDLE EVIDENCE.
THE VERIFIER REMAINS INDEPENDENT.
MCP IS OPTIONAL.
NETWORK IS OPTIONAL.
~~~

---

# Phase 11 extension — portable forensic package

The Phase 8 `export` command remains a verified copy of the current immutable Phase 2 snapshot.

Phase 11 adds a distinct command:

~~~bash
provenance package \
  --store /path/to/store \
  --custody /path/to/custody \
  --destination /path/to/forensic-package
~~~

This creates and independently verifies a `provenance.forensic-package.v1` directory containing the evidence snapshot, stable custody snapshot, schema/version metadata, verification metadata, and recomputed declared gaps.

After successful publication, the live custody ledger receives an `EXPORTED` record for the evidence manifest whose `related_identity` is the package identity. The already-finalized package is not rewritten to include that later export record.

See `PACKAGE.md`.

---

# Phase 12 extension — signatures and anchors

Detached trust operations act on finalized Phase 11 packages and do not require `--store` / `--custody`.

~~~text
provenance sign-package
provenance anchor-payload
provenance anchor-git
provenance verify-assurance
~~~

These commands are standalone backend commands rather than TUI palette actions because they operate on detached packages/records rather than the active mutable store session.

Sign:

~~~bash
provenance sign-package \
  --package /path/to/package \
  --key /path/to/ed25519-key \
  --output ./package.signature.json
~~~

Create bytes to commit as a Git anchor:

~~~bash
provenance anchor-payload \
  --package /path/to/package \
  --output /path/to/git-repo/package.provenance
~~~

After committing that exact file, create the detached anchor record:

~~~bash
provenance anchor-git \
  --package /path/to/package \
  --git-repo /path/to/git-repo \
  --commit HEAD \
  --path package.provenance \
  --output ./package.git-anchor.json
~~~

Verify dimensions independently:

~~~bash
provenance verify-assurance \
  --package /path/to/package \
  --signature ./package.signature.json \
  --anchor ./package.git-anchor.json \
  --git-repo /path/to/git-repo
~~~

See `TRUST.md` for the exact proof boundary.
