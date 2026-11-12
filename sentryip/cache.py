"""
Local SQLite caching layer with configurable TTL for external threat intel queries.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional
from sentryip.config import settings
from sentryip.logging import logger


class CacheManager:
    """Thread-safe SQLite caching with TTL expiration."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (settings.home_dir / "cache.sqlite3")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tool_cache (
                        cache_key TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON tool_cache(expires_at)")
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize cache DB: {e}")

    def get(self, cache_key: str) -> Optional[Any]:
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT data, expires_at FROM tool_cache WHERE cache_key = ?",
                    (cache_key,)
                )
                row = cursor.fetchone()
                if row:
                    if row["expires_at"] > now:
                        return json.loads(row["data"])
                    else:
                        # Expired, clean up
                        conn.execute("DELETE FROM tool_cache WHERE cache_key = ?", (cache_key,))
                        conn.commit()
        except Exception as e:
            logger.warning(f"Cache get error for key {cache_key}: {e}")
        return None

    def set(self, cache_key: str, data: Any, ttl_seconds: Optional[int] = None) -> None:
        if ttl_seconds is None:
            ttl_seconds = settings.cache_ttl_hours * 3600

        now = time.time()
        expires_at = now + ttl_seconds
        serialized = json.dumps(data)

        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO tool_cache (cache_key, data, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                """, (cache_key, serialized, now, expires_at))
                conn.commit()
        except Exception as e:
            logger.warning(f"Cache set error for key {cache_key}: {e}")

    def clear(self) -> None:
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM tool_cache")
                conn.commit()
        except Exception as e:
            logger.warning(f"Cache clear error: {e}")


cache = CacheManager()

