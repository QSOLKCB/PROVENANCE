# PROVENANCE Phase 13 — Performance Hardening

Phase 13 reduces verification overhead without changing evidence semantics.

The first accepted optimization follows the bounded deterministic parallel-execution pattern from `QSOLKCB/OPT`.

## Contract

The hard rule is:

~~~text
OPTIMIZED_RESULT
==
REFERENCE_RESULT
~~~

for stable evidence inputs where exact equivalence is claimed.

The serial verifier remains available as the reference path:

~~~python
from provenance_verify import (
    verify_bundle_reference,
    verify_forensic_package_reference,
)
~~~

The default verifier uses bounded parallel work:

~~~python
from provenance_verify import (
    verify_bundle,
    verify_forensic_package,
)
~~~

## Optimization

Parallelized independent work includes:

~~~text
bundle artifact-record + retained-content verification
bundle event verification
forensic-package member hashing / byte counting
~~~

The optimized path does **not** parallelize semantic reduction.

Worker results are reduced in the same manifest/member order used by the reference path.

Therefore worker completion order cannot change:

~~~text
check ordering
error ordering
reference ordering
verification report contents
~~~

## Bounded scheduling

The Phase 13 scheduler uses:

~~~text
default worker cap = 4
bounded queued batches = 2 × active workers
ordered executor.map reduction
~~~

The worker cap is a resource bound, not proof that four workers actually overlapped.

CI separately executes an overlap witness that requires multiple tasks to be simultaneously active and asserts observed concurrency never exceeds the configured cap.

## Reference equivalence

The Phase 13 conformance suite compares complete immutable report objects, including:

~~~text
integrity_verified
manifest/package identities
scope
checks tuple
errors tuple
known missing counts
custody counts
~~~

Fixtures include:

~~~text
valid bundles
multiple simultaneously corrupted artifact contents
tampered event records
valid forensic packages
multiple corrupted package members
~~~

The optimized and serial reports must compare equal.

## Stable-input boundary

The verifier remains read-only.

Phase 13 does not turn mutable filesystem trees into atomic historical snapshots. Exact serial/parallel equivalence is claimed for stable evidence inputs such as finalized immutable store snapshots and finalized forensic packages.

Concurrent external mutation remains outside the snapshot-consistency guarantee and may cause verification failure.

## Benchmark harness

Run:

~~~bash
python3 scripts/benchmark_phase13.py \
  --artifact-count 32 \
  --artifact-bytes 1048576 \
  --repetitions 5
~~~

The harness:

- creates one deterministic workload;
- verifies optimized/reference equality before timing;
- alternates timing order between repetitions;
- fails if any report changes or diverges;
- records environment, CPU, Python/toolchain, workload, repetitions, variance, worker cap, and median ratio;
- labels all numbers environment-specific.

CI also uses `set -o pipefail` so a dead benchmark process cannot be hidden by `tee`.

## Recorded Phase 13 observation

Observed on the Phase 13 GitHub Actions validation run:

~~~text
runner:
  GitHub Actions 1000096576

OS:
  Linux 6.17.0-1022-azure x86_64
  Ubuntu 24.04.5 runner image

CPU:
  AMD EPYC 9V74 80-Core Processor
  4 logical CPUs exposed to runner

toolchain:
  CPython 3.12.3
  GCC 13.3.0 build

workload:
  32 retained artifacts
  1,048,576 bytes per artifact
  33,554,432 retained artifact bytes total
  32 events
  5 timed repetitions
  worker cap = 4
~~~

### Bundle verification

~~~text
serial reference median = 45.343164 ms
optimized median        = 25.792463 ms
median ratio            = 0.568828
observed median gain    = 43.117%
reference stdev         = 0.206271 ms
optimized stdev         = 0.203136 ms
~~~

### Forensic-package verification

~~~text
serial reference median = 96.480844 ms
optimized median        = 59.515135 ms
median ratio            = 0.616860
observed median gain    = 38.314%
reference stdev         = 0.502481 ms
optimized stdev         = 2.283362 ms
~~~

These are archived environment-specific observations.

They are **not** universal defaults or promises for other CPUs, filesystems, artifact sizes, worker counts, cache states, or concurrency conditions.

Re-measure before transferring the performance claim to another environment.

## What did not change

Phase 13 does not change:

~~~text
canonicalization
SHA-256 identity
domain separation
manifest semantics
artifact/event schemas
custody semantics
package closure
signature/anchor semantics
failure visibility
special-file rejection
symlink protections
descriptor-relative reads
~~~

No cache is authoritative.

No failed verification is converted into success.

## CI

~~~bash
python3 -m unittest tests.test_performance -v
python3 scripts/benchmark_phase13.py
~~~

Workflow:

~~~text
.github/workflows/performance.yml
~~~
