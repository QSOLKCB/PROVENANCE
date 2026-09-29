"""Internal bounded deterministic parallel-execution helper for Phase 13."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Sequence, TypeVar


T = TypeVar("T")
R = TypeVar("R")

DEFAULT_MAX_VERIFY_WORKERS = 4
_INFLIGHT_BATCHES_PER_WORKER = 2


def ordered_bounded_map(
    function: Callable[[T], R],
    items: Sequence[T],
    *,
    max_workers: int,
) -> list[R]:
    """Execute bounded work in parallel while reducing in input order."""

    if type(max_workers) is not int or max_workers < 1:
        raise ValueError("max_workers must be a positive integer")
    count = len(items)
    if count == 0:
        return []
    workers = min(max_workers, count)
    if workers == 1:
        return [function(item) for item in items]

    batch_size = workers * _INFLIGHT_BATCHES_PER_WORKER
    results: list[R] = []
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="provenance-verify",
    ) as executor:
        for offset in range(0, count, batch_size):
            batch = items[offset : offset + batch_size]
            # executor.map preserves input ordering even when workers finish
            # out of order. Batching bounds queued/in-flight work.
            results.extend(executor.map(function, batch))
    return results
