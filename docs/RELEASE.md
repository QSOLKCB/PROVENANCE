# Release-Grade Trust Lane

For the post-archive v1.2.0 candidate and its final merged SHA/tag sequence, see [RELEASE_V1_2_0.md](RELEASE_V1_2_0.md). Its DOI is separate from the published Phase 18 record.

Phase 16 adds a high-assurance validation lane for release candidates.

It is intentionally separate from routine fast CI.

The lane does **not** freeze the implementation and does **not** perform formal verification. Those responsibilities begin in Phase 17 and Phase 18.

## Workflow

The reference lane is:

```text
.github/workflows/full.yml
```

Routine module workflows remain path-filtered and fast.

The full lane runs automatically only when the release-lane contract or its documentation changes. For an actual release candidate, run `full` manually against the exact candidate branch/ref before creating the Phase 17 immutable tag.

## Release gate

A successful release-grade run requires all of these dimensions to pass:

```text
fresh source checkout
pinned Python toolchain
pinned Rust toolchain
full Python invariant/tamper/integration suite
Rust CLI build + unit tests
canonical core/verifier recheck under a second hash seed
clean source tree after tests
real Ollama observation on qwen2.5:0.5b
real Ollama observation on qwen2:0.5b
tamper detection in each real-model observation lane
final release-gate aggregation
```

The complete Python discovery includes the core, independent verifier, local store, custody, adapters, MCP, CLI, UI, package, trust, performance-equivalence, privacy, and distributed-transfer tests.

Package export and independent verification are therefore exercised through the existing package/MCP/CLI integration tests rather than reimplemented inside the release workflow.

## Toolchain pins

Phase 16 deliberately avoids floating project-level toolchains in the release lane.

Current reference pins:

```text
runner family      ubuntu-24.04
Python             3.12.11
Rust               1.90.0
Ollama             0.34.0
checkout action    11d5960a326750d5838078e36cf38b85af677262
setup-python       a26af69be951a213d495a4c3e4e4022e16d87065
upload-artifact    ea165f8d65b6e75b540449e92b4886f43607fa02
Ollama installer   SHA-256 25f64b810b947145095956533e1bdf56eacea2673c55a7e586be4515fc882c9f
```

The GitHub-hosted `ubuntu-24.04` image is a managed runner family rather than an immutable image digest. The workflow records the executed run and exact repository commit; the later Phase 17 freeze identifies the implementation target by immutable tag and commit SHA.

No dependency cache is authoritative in the Phase 16 lane.

## Real-model evidence

Each Ollama matrix job starts its own local server, pulls one small reference model, and runs the existing `scripts.ollama_smoke` observation path.

The resulting observation directory is uploaded as a 30-day workflow artifact for inspection.

Those artifacts are CI evidence only. They are not the final archival bundle described by Phase 18.

## Canonicalization cross-check

The full suite runs with a fixed Python hash seed, then the canonical core and verifier suites are repeated with a different seed.

This is not a proof of language independence. It is a regression check that canonical identities and verifier semantics do not accidentally depend on one Python hash-table seed.

## Clean-tree rule

After the release suite completes, generated Rust build output is removed and Git must report no tracked or untracked source-tree mutation.

A release validation process must not silently rewrite the implementation it is validating.

## Manual release-candidate procedure

1. Select the exact candidate branch/ref in GitHub Actions.
2. Run the `full` workflow manually.
3. Require `release-suite`, both Ollama matrix jobs, and `release-gate` to succeed.
4. Record the candidate commit SHA and workflow run.
5. Only then proceed to Phase 17 and create the immutable penultimate implementation tag.

If implementation changes after a green run, that run no longer qualifies the new commit. Re-run the full lane.

## What Phase 16 does not prove

A green release-grade lane does not establish:

```text
formal proof of runtime correctness
source-data truth
adapter honesty beyond tested observation boundaries
legal identity
legal or factual truth
absence of all defects
immutable implementation freeze
```

Formalization begins only after Phase 17 freezes the exact implementation target.

## Failure rule

Any failed required job means:

```text
RELEASE-GRADE TRUST LANE = FAILED
```

Do not average failures away, ignore one model lane, or substitute a routine focused workflow for the release gate.

If a defect is found after Phase 17 freeze and requires implementation changes, follow the roadmap restart rule: return to Phase 16, fix the implementation, re-run the full lane, and cut a new freeze target.
