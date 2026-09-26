"""Performance profiling utilities for timing analysis stages.

Provides context managers and decorators for measuring execution time
of analysis functions, with structured logging.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from ..core.logging import get_logger

logger = get_logger(__name__)


@contextmanager
def profile_stage(stage_name: str, **context: Any) -> Generator[dict[str, Any], None, None]:
    """Context manager to time an analysis stage.

    Usage:
        with profile_stage("gt_spoofing", pcap="test.pcap") as p:
            # ... do work ...
        # p["elapsed_ms"] now contains the elapsed time

    Args:
        stage_name: Name of the analysis stage.
        context: Additional context key-value pairs for logging.

    Yields:
        A dict that will be populated with elapsed_ms after the block exits.
    """
    result: dict[str, Any] = {"stage": stage_name, **context}
    start = time.perf_counter()
    try:
        yield result
    finally:
        elapsed = (time.perf_counter() - start) * 1000
        result["elapsed_ms"] = round(elapsed, 2)
        logger.info("stage_profiled", **result)


class Profiler:
    """Accumulates timing metrics across multiple stages."""

    def __init__(self) -> None:
        self._stages: dict[str, float] = {}
        self._total_ms: float = 0.0

    @contextmanager
    def stage(self, name: str) -> Generator[None, None, None]:
        """Time a named stage and accumulate the result."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - start) * 1000
            self._stages[name] = self._stages.get(name, 0.0) + elapsed
            self._total_ms += elapsed
            logger.info("stage_timed", stage=name, elapsed_ms=round(elapsed, 2))

    def summary(self) -> dict[str, Any]:
        """Return a summary of all timed stages."""
        return {
            "stages": {k: round(v, 2) for k, v in self._stages.items()},
            "total_ms": round(self._total_ms, 2),
        }
