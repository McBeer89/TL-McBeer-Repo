"""
Simple file-based JSON cache for scraped data.

Cache files are stored in output/.cache/ and expire after a configurable TTL.
"""

import json
import time
from pathlib import Path
from typing import Any, Optional


_CACHE_DIR = Path(__file__).parent.parent / "output" / ".cache"


def _cache_path(key: str) -> Path:
    """Return the file path for a given cache key."""
    safe_key = key.replace("/", "_").replace(".", "_")
    return _CACHE_DIR / f"{safe_key}.json"


def get_cached(key: str, ttl_days: int = 7) -> Optional[Any]:
    """
    Return cached data for the given key, or None if missing/expired.

    Args:
        key: Cache key (e.g. technique ID)
        ttl_days: Cache lifetime in days

    Returns:
        Deserialized data, or None if cache miss or expired
    """
    path = _cache_path(key)
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            entry = json.load(f)
        stored_at = entry.get("_cached_at", 0)
        if time.time() - stored_at > ttl_days * 86400:
            return None
        return entry.get("data")
    except Exception:
        return None


def set_cached(key: str, data: Any) -> None:
    """
    Store data in the cache under the given key.

    Args:
        key: Cache key
        data: JSON-serialisable data to store
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(key)
    entry = {"_cached_at": time.time(), "data": data}
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)
    except Exception:
        pass  # Cache write failure is non-fatal
