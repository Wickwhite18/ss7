"""LRU cache for tshark execution results.

Caches raw tshark output keyed by (pcap_file_hash, filter_hash) to avoid
re-running expensive tshark invocations on the same inputs.
"""

from __future__ import annotations

import hashlib
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

from ..core.logging import get_logger

logger = get_logger(__name__)


class TsharkResultCache:
    """LRU cache for tshark command results."""

    def __init__(self, capacity: int = 100):
        self.capacity = capacity
        self._cache: OrderedDict[str, str] = OrderedDict()

    @staticmethod
    def _make_key(pcap_path: str, filter_expr: str, fields: list[str]) -> str:
        """Build a cache key from pcap file hash + filter + fields."""
        # Hash the pcap file content (first 64KB for speed)
        try:
            file_hash = hashlib.md5()
            with open(pcap_path, "rb") as f:
                # Read file size + first chunk for fingerprint
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                chunk = f.read(65536)
                file_hash.update(str(size).encode())
                file_hash.update(chunk)
                fh = file_hash.hexdigest()
        except OSError:
            # Fall back to path string hash
            fh = hashlib.md5(pcap_path.encode()).hexdigest()

        filter_hash = hashlib.md5(
            (filter_expr + "|" + ",".join(fields)).encode()
        ).hexdigest()

        return f"{fh}:{filter_hash}"

    def get(self, pcap_path: str, filter_expr: str, fields: list[str]) -> Optional[str]:
        """Retrieve cached tshark output if available."""
        key = self._make_key(pcap_path, filter_expr, fields)
        if key in self._cache:
            self._cache.move_to_end(key)
            logger.info("cache_hit", key=key[:16])
            return self._cache[key]
        logger.info("cache_miss", key=key[:16])
        return None

    def put(
        self, pcap_path: str, filter_expr: str, fields: list[str], result: str
    ) -> None:
        """Store tshark output in the cache."""
        key = self._make_key(pcap_path, filter_expr, fields)
        self._cache[key] = result
        self._cache.move_to_end(key)

        while len(self._cache) > self.capacity:
            evicted_key, _ = self._cache.popitem(last=False)
            logger.info("cache_evicted", key=evicted_key[:16])

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        logger.info("cache_cleared")

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        return {
            "size": len(self._cache),
            "capacity": self.capacity,
        }
