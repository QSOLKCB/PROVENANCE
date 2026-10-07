# OpenAI Math reference fixture

This small, offline fixture retains five unmodified files from
[`openai/math@adc7f1241b42e322a6451854ab7e4b4c146bf78a`](https://github.com/openai/math/tree/adc7f1241b42e322a6451854ab7e4b4c146bf78a).
OpenAI authored the upstream material, distributed under Apache-2.0; the
complete license is in [upstream/LICENSE](upstream/LICENSE). The files retain
their original notices. PROVENANCE's implementation remains MPL-2.0.

| Local fixture | Upstream path |
|---|---|
| `upstream/LICENSE` | `LICENSE` |
| `upstream/scope.md` | `lean/docs/271.md` |
| `upstream/Heisenberg.lean` | `lean/ComparatorChallenges/Heisenberg.lean` |
| `upstream/Heisenberg.json` | `lean/ComparatorChallenges/Heisenberg.json` |
| `upstream/citation.md` | `preprints/Spontaneous-magnetization-in-the-quantum-Heisenberg-ferromagnet-September-24-2026/README.md` |

The manifest records family 271, manuscript identity, declared formalization
scope, theorem name, Comparator configuration, license, and the supplied
academic citation. SHA-256 identities cover exact retained file bytes.
The manuscript PDF, solution library, dependencies and proof-execution logs
are not retained. No upstream proof or Comparator has been run here.

The challenge statement contains upstream `sorry`: it is a specification
to compare against a separate solution, not a completed Lean proof.
The fixture makes no mathematical verification claim. The empty receipt list
means no executed verification evidence is supplied.

Run from the repository root:

```bash
python3 -m examples.openai_math.verify
python3 -m unittest discover -s tests -p 'test_research.py' -v
```

Changes to upstream files must be represented by a new manifest and explicit
reuse/modification bindings; do not silently refresh this pinned fixture.
