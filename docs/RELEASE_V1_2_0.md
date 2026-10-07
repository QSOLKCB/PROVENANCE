# v1.2.0 — External Research Provenance

Status: release candidate; PR review and release gates pending.

Reserved release DOI: [10.5281/zenodo.23207011](https://doi.org/10.5281/zenodo.23207011).
The DOI supplied by the owner is an identifier for this new version. This
document does not assert that its Zenodo record has been published.

## Changes

- Optional, vendor-neutral `provenance.research-manifest.v1` with exact upstream
  commit, canonical domain identity and SHA-256 artifact bindings.
- Explicit reference/copy/adaptation/derivation bindings and modification notices.
- Separate manuscript, formalized and local scope; theorem names, Comparator
  targets and optional retained verification receipts.
- Upstream license, NOTICE observation state, credit and exact citation capture.
- Independent read-only byte verifier with visible gaps and no mathematical or
  legal truth promotion.
- Small pinned OpenAI Math family-271 fixture with unmodified Apache-2.0 files
  and regression/integration coverage.

Compatibility: existing evidence, custody, package, signature and transfer formats
are unchanged. No new runtime dependency or automatic upstream fetch is introduced.

## Final immutable release sequence

1. Finish PR review and fixes.
2. Merge the PR, then resolve the exact merged commit on `main`. A squash, rebase
   or merge commit can differ from the reviewed branch head.
3. Run the release-grade `full` workflow against that exact commit/ref and record
   its SHA and successful workflow run. If the commit changes, repeat this gate.
4. Create `v1.2.0` pointing to that final validated merged SHA. Record the full
   SHA in the release notes and Zenodo metadata. Do not target a moving branch
   name alone, and do not move an existing tag.
5. Finalize the GitHub release under the enabled immutability setting after
   required assets are attached. Archive source from that exact tagged commit,
   retain checksums and validation evidence, then publish the new Zenodo version
   using DOI `10.5281/zenodo.23207011`.

The final release SHA and run IDs are recorded in release/archival evidence after
they exist; a commit cannot embed its own final Git SHA in its contents.

## Formal verification boundary

The published v1.1.1 DOI `10.5281/zenodo.23043860`, frozen v1.0.0 implementation,
`formal/TARGET.json`, proof sources and Phase 18 scripts retain their historical
meaning. The existing formal workflow continues to check that old target and
emit evidence under its old DOI, even when triggered from a newer repository
commit. Its formal-source archive retains the published v1.1.1 citation at
`formal/CITATION.cff` and excludes the moving root citation. Its output must not
be relabeled as a v1.2.0 proof.

The new research module is tested but is outside the existing FV-01–FV-04 runtime
bridge. An eventual formal extension must follow an explicit freeze and new
target/proof-scope declaration. This candidate makes no whole-program or new
mathematical verification claim.
