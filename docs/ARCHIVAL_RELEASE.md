# Phase 18 Archival Release Protocol

## Reserved / minted DOI

```text
10.5281/zenodo.23043860
```

This DOI is the archival identifier reserved for the Phase 18 PROVENANCE record.

The implementation authority remains separate and immutable:

```text
v1.0.0
0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742
```

The final archival record must identify both the DOI and the frozen implementation target.

---

## Archive components

The Phase 18 `formal` workflow produces an artifact containing:

```text
PROVENANCE-v1.0.0-source.tar.gz
PROVENANCE-phase18-formal-sources.tar.gz
formal-evidence.json
SHA256SUMS
```

### Frozen source archive

`PROVENANCE-v1.0.0-source.tar.gz` is created directly from Git tag `v1.0.0`.

It represents the immutable implementation target, not current `main`.

### Formal-source archive

The formal-source archive contains the Phase 18 proof and archive material needed to interpret the formal claim:

- Lean sources;
- pinned Lean toolchain;
- Lake project;
- formal target declaration;
- formal-verification bridge;
- archival protocol;
- citation metadata;
- formal evidence generator;
- formal CI definition.

### Formal evidence manifest

`formal-evidence.json` binds:

- DOI;
- frozen tag;
- frozen implementation SHA;
- proof commit;
- Lean toolchain;
- claim identifiers;
- proof/archive source identities;
- proof verification contract.

### SHA256SUMS

The checksum file identifies the generated archive members independently of filenames alone.

---

## Zenodo record boundary

The Zenodo description should distinguish:

```text
FROZEN IMPLEMENTATION
from
FORMAL PROOF / ARCHIVE MATERIAL
```

Recommended interpretation:

- `v1.0.0` / `0b1a2eea…` is the frozen runtime target;
- the later formal proof commit contains proof and archive material;
- the Lean proof proves only `FV-01` through `FV-04`;
- runtime equivalence is supported by the documented bridge, not mechanically proved end-to-end;
- post-`v1.0.0` maintenance changes on `main` are not silently folded into the frozen target.

---

## Final publication sequence

After this Phase 18 implementation PR is merged:

1. require the `formal` workflow to be green on the exact proof/archive commit;
2. retain the workflow run ID and generated Phase 18 artifact;
3. create the final archival repository tag on that proof/archive commit;
4. run/confirm the formal workflow on the final archival tag;
5. download the generated artifact;
6. upload the frozen source archive, formal-source archive, formal evidence manifest, and checksum file to the Zenodo record;
7. publish DOI `10.5281/zenodo.23043860`;
8. record the final archival tag and proof commit in the Zenodo metadata/description.

Do not move or reinterpret `v1.0.0`.

---

## Suggested Zenodo technical note

```text
Frozen implementation target:
  PROVENANCE v1.0.0
  commit 0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742

Formal proof toolchain:
  Lean 4.34.1

Formal claims:
  FV-01 self-hash exclusion
  FV-02 append-only history extension
  FV-03 classification non-promotion
  FV-04 presentation non-interference

Formal proof scope:
  encoded model plus documented runtime bridge;
  not whole-program runtime verification.

DOI:
  10.5281/zenodo.23043860
```

---

## Exit gate

Phase 18 is complete only when all of the following exist:

```text
immutable v1.0.0 implementation target
green formal proof workflow
final archival repository tag
published Zenodo record
DOI bound to frozen target and proof/archive material
```

Until the final tag and Zenodo publication are complete, the roadmap status remains in progress.
