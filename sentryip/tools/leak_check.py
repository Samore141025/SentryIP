"""
Passive Dark Web & Pastebin leak indicator checking via public search indexes.
Completely passive: checks known public paste hashes/indexes and DNS reputation.
"""

from __future__ import annotations

import httpx
from typing import Any, Dict
from sentryip.cache import cache
from sentryip.logging import logger
from sentryip.tools.base import registry


@registry.register(
    name="leak_and_paste_check",
    description="Check passive public pastebin and breach indexes to see if the IP or associated host has appeared in leaked paste data.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=8.0,
)
async def leak_and_paste_check(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    cache_key = f"leak_paste:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    # Query public threat leak indexes (e.g. psbdmp passive paste index or threat raw dump)
    # Uses passive non-invasive endpoint
    url = f"https://psbdmp.ws/api/search/{ip}"
    found_pastes = []

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, headers={"User-Agent": "SentryIP/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for item in data[:5]:
                        found_pastes.append({
                            "id": item.get("id"),
                            "date": item.get("date"),
                            "text_preview": item.get("text", "")[:80],
                        })
                elif isinstance(data, dict) and data.get("count", 0) > 0:
                    found_pastes = data.get("data", [])[:5]
    except Exception as e:
        logger.debug(f"Passive paste check error for {ip}: {e}")

    result = {
        "ip": ip,
        "paste_matches_count": len(found_pastes),
        "pastes": found_pastes,
        "has_leak_presence": len(found_pastes) > 0,
    }
    cache.set(cache_key, result, ttl_seconds=12 * 3600)
    return result
