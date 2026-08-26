"""Cached JSON fetching shared by the live intel connectors.

Both public feeds this app consumes (CISA KEV, MITRE ATT&CK STIX) are large,
change slowly, and must never take bootstrap down when the network is
unavailable. Strategy: serve from the local cache while it's fresh, refetch
when stale, and fall back to a stale cache (or None) on any fetch failure --
the same graceful-degradation posture as llm_reasoning.reason().
"""
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def fetch_json_cached(url: str, cache_filename: str, max_age_seconds: float) -> Any | None:
    """Return parsed JSON from cache if fresh, else refetch and rewrite the
    cache. Falls back to a stale cache on fetch failure; returns None only
    when there is no cache and the fetch fails."""
    cache_path = CACHE_DIR / cache_filename

    if cache_path.exists() and (time.time() - cache_path.stat().st_mtime) < max_age_seconds:
        return json.loads(cache_path.read_text())

    try:
        response = httpx.get(url, timeout=60.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data))
        return data
    except Exception as exc:  # network down, HTTP error, bad JSON -- degrade, don't die
        if cache_path.exists():
            logger.warning("Fetch of %s failed (%s); serving stale cache %s", url, exc, cache_path)
            return json.loads(cache_path.read_text())
        logger.warning("Fetch of %s failed (%s) and no cache exists; skipping", url, exc)
        return None
