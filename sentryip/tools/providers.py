"""
Threat intelligence and network data collection tools for SentryIP.
All tools follow passive intelligence principles: no active scanning or connecting to targets.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any, Dict, List, Optional
import dns.asyncresolver
import dns.reversename
import httpx
from ipwhois import IPWhois

from sentryip.cache import cache
from sentryip.config import settings
from sentryip.logging import logger
from sentryip.tools.base import registry


def _is_safe_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Tool 2: rdap_whois
# --------------------------------------------------------------------------
@registry.register(
    name="rdap_whois",
    description="Retrieve RDAP registration records: owner/org, ASN, CIDR/netblock, registrar country, abuse contact, and allocation dates via ipwhois RDAP.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=15.0,
)
async def rdap_whois(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"rdap_whois:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    def _sync_rdap():
        obj = IPWhois(ip)
        return obj.lookup_rdap(depth=1)

    try:
        # Run blocking ipwhois in thread pool
        res = await asyncio.to_thread(_sync_rdap)
        asn = res.get("asn")
        asn_cidr = res.get("asn_cidr")
        asn_country = res.get("asn_country_code")
        asn_desc = res.get("asn_description")

        network = res.get("network", {}) or {}
        net_name = network.get("name")
        net_cidr = network.get("cidr")
        country = network.get("country") or asn_country

        # Extract abuse contact emails
        abuse_emails: List[str] = []
        objects = res.get("objects", {}) or {}
        for entity_id, entity in objects.items():
            roles = entity.get("roles") or []
            if "abuse" in roles or "noc" in roles or "technical" in roles:
                contact = entity.get("contact", {}) or {}
                emails = contact.get("email") or []
                for e in emails:
                    if isinstance(e, dict) and "value" in e:
                        abuse_emails.append(e["value"])
                    elif isinstance(e, str):
                        abuse_emails.append(e)

        data = {
            "ip": ip,
            "asn": f"AS{asn}" if asn and not str(asn).startswith("AS") else asn,
            "asn_description": asn_desc,
            "cidr": net_cidr or asn_cidr,
            "country": country,
            "org_name": net_name,
            "abuse_contact": abuse_emails[0] if abuse_emails else None,
            "raw_notices": [n.get("title") for n in res.get("notices", []) if n.get("title")],
        }
        cache.set(cache_key, data)
        return data
    except Exception as e:
        logger.warning(f"RDAP lookup failed for {ip}: {e}")
        return {"error": f"RDAP lookup failed: {str(e)}", "ip": ip}


# --------------------------------------------------------------------------
# Tool 3: reverse_dns (rDNS + FCrDNS)
# --------------------------------------------------------------------------
@registry.register(
    name="reverse_dns",
    description="Check PTR record (reverse DNS) and perform Forward-Confirmed Reverse DNS (FCrDNS) verification.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=8.0,
)
async def reverse_dns(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"reverse_dns:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    ptr_records: List[str] = []
    fcrdns_verified = False
    forward_ips: List[str] = []

    try:
        rev_name = dns.reversename.from_address(ip)
        answers = await resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            ptr_records.append(str(rdata.target).rstrip("."))
    except Exception as e:
        logger.debug(f"PTR lookup failed for {ip}: {e}")

    # Forward confirm
    if ptr_records:
        candidate_hostname = ptr_records[0]
        try:
            addr_type = "AAAA" if ":" in ip else "A"
            fwd_answers = await resolver.resolve(candidate_hostname, addr_type)
            for rdata in fwd_answers:
                f_ip = rdata.address
                forward_ips.append(f_ip)
                if f_ip == ip:
                    fcrdns_verified = True
        except Exception as e:
            logger.debug(f"FCrDNS forward resolution failed for {candidate_hostname}: {e}")

    result = {
        "ip": ip,
        "ptr_records": ptr_records,
        "primary_ptr": ptr_records[0] if ptr_records else None,
        "fcrdns_verified": fcrdns_verified,
        "forward_ips": forward_ips,
    }
    cache.set(cache_key, result)
    return result


# --------------------------------------------------------------------------
# Tool 4: geolocate (ip-api.com or ipinfo.io)
# --------------------------------------------------------------------------
@registry.register(
    name="geolocate",
    description="Query geolocation, ISP, timezone, and hosting/proxy/mobile flags (using ipinfo.io if token set, or ip-api.com free tier).",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=10.0,
)
async def geolocate(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"geolocate:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    # If ipinfo token is provided, prefer ipinfo.io
    if settings.ipinfo_token:
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                resp = await client.get(
                    f"https://ipinfo.io/{ip}/json",
                    headers={"Authorization": f"Bearer {settings.ipinfo_token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    loc = data.get("loc", "").split(",")
                    lat = float(loc[0]) if len(loc) == 2 else None
                    lon = float(loc[1]) if len(loc) == 2 else None
                    privacy = data.get("privacy", {})

                    out = {
                        "ip": ip,
                        "source": "ipinfo.io",
                        "country": data.get("country"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "latitude": lat,
                        "longitude": lon,
                        "timezone": data.get("timezone"),
                        "isp": data.get("org"),
                        "org": data.get("org"),
                        "asn": data.get("org", "").split()[0] if data.get("org") else None,
                        "hosting": privacy.get("hosting", False),
                        "proxy": privacy.get("proxy", False),
                        "vpn": privacy.get("vpn", False),
                        "tor": privacy.get("tor", False),
                    }
                    cache.set(cache_key, out)
                    return out
        except Exception as e:
            logger.warning(f"ipinfo.io query failed: {e}")

    # Fallback to ip-api.com
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    out = {
                        "ip": ip,
                        "source": "ip-api.com",
                        "country": data.get("countryCode") or data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "hosting": data.get("hosting", False),
                        "proxy": data.get("proxy", False),
                        "vpn": data.get("proxy", False),
                        "tor": False,
                    }
                    cache.set(cache_key, out)
                    return out
                else:
                    return {"error": data.get("message", "ip-api lookup error"), "ip": ip}
    except Exception as e:
        logger.warning(f"ip-api lookup failed: {e}")
        return {"error": f"Geolocation lookup failed: {str(e)}", "ip": ip}

    return {"error": "Geolocation lookup unavailable", "ip": ip}


# --------------------------------------------------------------------------
# Tool 5: abuseipdb_check
# --------------------------------------------------------------------------
@registry.register(
    name="abuseipdb_check",
    description="Query AbuseIPDB for abuse confidence score, total reports, last reported time, report categories, usage type, and whitelisting status (requires ABUSEIPDB_API_KEY).",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    required_api_key="ABUSEIPDB_API_KEY",
    timeout_seconds=10.0,
)
async def abuseipdb_check(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    if not settings.abuseipdb_api_key:
        return {
            "skipped": True,
            "reason": "ABUSEIPDB_API_KEY environment variable is not configured.",
            "ip": ip,
        }

    cache_key = f"abuseipdb:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "true",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                body = resp.json().get("data", {})
                reports = body.get("reports", [])[:5]  # Take top 5 reports summary
                recent_categories = set()
                for r in reports:
                    for cat in r.get("categories", []):
                        recent_categories.add(cat)

                result = {
                    "ip": ip,
                    "abuse_confidence_score": body.get("abuseConfidenceScore", 0),
                    "total_reports": body.get("totalReports", 0),
                    "num_distinct_users": body.get("numDistinctUsers", 0),
                    "last_reported_at": body.get("lastReportedAt"),
                    "is_whitelisted": body.get("isWhitelisted", False),
                    "usage_type": body.get("usageType"),
                    "isp": body.get("isp"),
                    "domain": body.get("domain"),
                    "recent_categories": list(recent_categories),
                }
                cache.set(cache_key, result)
                return result
            elif resp.status_code == 429:
                return {"error": "AbuseIPDB rate limit exceeded (429)", "ip": ip}
            else:
                return {"error": f"AbuseIPDB API returned status {resp.status_code}: {resp.text}", "ip": ip}
    except Exception as e:
        logger.error(f"AbuseIPDB check exception: {e}")
        return {"error": f"AbuseIPDB query failed: {str(e)}", "ip": ip}


# --------------------------------------------------------------------------
# Tool 6: virustotal_ip
# --------------------------------------------------------------------------
@registry.register(
    name="virustotal_ip",
    description="Query VirusTotal v3 for malicious/suspicious/harmless engine detection counts, reputation score, network tags, and communicating malware files (requires VT_API_KEY).",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    required_api_key="VT_API_KEY",
    timeout_seconds=12.0,
)
async def virustotal_ip(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    if not settings.vt_api_key:
        return {
            "skipped": True,
            "reason": "VT_API_KEY environment variable is not configured.",
            "ip": ip,
        }

    cache_key = f"vt:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": settings.vt_api_key}

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                results = attr.get("last_analysis_results", {})

                # Identify flagging engines
                flagging_engines = []
                for engine, eng_res in results.items():
                    category = eng_res.get("category")
                    if category in ["malicious", "suspicious"]:
                        flagging_engines.append({
                            "engine": engine,
                            "category": category,
                            "result": eng_res.get("result"),
                        })

                out = {
                    "ip": ip,
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "reputation": attr.get("reputation", 0),
                    "tags": attr.get("tags", []),
                    "flagging_engines": flagging_engines[:10],
                    "network": attr.get("network"),
                    "as_owner": attr.get("as_owner"),
                }
                cache.set(cache_key, out)
                return out
            elif resp.status_code == 404:
                return {"ip": ip, "malicious_count": 0, "suspicious_count": 0, "not_found": True}
            elif resp.status_code == 429:
                return {"error": "VirusTotal API rate limit reached (429)", "ip": ip}
            else:
                return {"error": f"VirusTotal API returned {resp.status_code}", "ip": ip}
    except Exception as e:
        logger.error(f"VirusTotal query error: {e}")
        return {"error": f"VirusTotal query failed: {str(e)}", "ip": ip}


# --------------------------------------------------------------------------
# Tool 7: greynoise_check
# --------------------------------------------------------------------------
@registry.register(
    name="greynoise_check",
    description="Check GreyNoise Community API for scanner classification (benign, malicious, unknown), noise vs RIOT (Rule It Out / known benign services) status, and actor name.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=10.0,
)
async def greynoise_check(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"greynoise:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                out = {
                    "ip": ip,
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name"),
                    "link": data.get("link"),
                    "last_seen": data.get("last_seen"),
                    "message": data.get("message"),
                }
                cache.set(cache_key, out)
                return out
            elif resp.status_code == 404:
                # Not observed by GreyNoise
                out = {
                    "ip": ip,
                    "noise": False,
                    "riot": False,
                    "classification": "unknown",
                    "name": None,
                    "message": "IP has not been observed scanning or in RIOT database",
                }
                cache.set(cache_key, out)
                return out
            else:
                return {"error": f"GreyNoise returned status {resp.status_code}", "ip": ip}
    except Exception as e:
        logger.warning(f"GreyNoise query failed: {e}")
        return {"error": f"GreyNoise query failed: {str(e)}", "ip": ip}


# --------------------------------------------------------------------------
# Tool 8: shodan_internetdb
# --------------------------------------------------------------------------
@registry.register(
    name="shodan_internetdb",
    description="Query Shodan's passive InternetDB endpoint (completely passive, no port scanning, no API key required) for open ports, CPEs, known CVEs, hostnames, and tags.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=10.0,
)
async def shodan_internetdb(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"internetdb:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    url = f"https://internetdb.shodan.io/{ip}"
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                out = {
                    "ip": ip,
                    "open_ports": data.get("ports", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                }
                cache.set(cache_key, out)
                return out
            elif resp.status_code == 404:
                out = {
                    "ip": ip,
                    "open_ports": [],
                    "cpes": [],
                    "vulns": [],
                    "hostnames": [],
                    "tags": [],
                    "message": "No open ports or services observed in passive dataset",
                }
                cache.set(cache_key, out)
                return out
            else:
                return {"error": f"InternetDB returned status {resp.status_code}", "ip": ip}
    except Exception as e:
        logger.warning(f"InternetDB query failed: {e}")
        return {"error": f"Shodan InternetDB query failed: {str(e)}", "ip": ip}


# --------------------------------------------------------------------------
# Tool 9: tor_and_blocklist_check
# --------------------------------------------------------------------------
FEED_URLS = {
    "tor_exit_nodes": "https://check.torproject.org/torbulkexitlist",
    "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
}


async def _fetch_feed(client: httpx.AsyncClient, name: str, url: str) -> set[str]:
    cache_key = f"feed:{name}"
    cached = cache.get(cache_key)
    if cached is not None and isinstance(cached, list):
        return set(cached)

    try:
        resp = await client.get(url, timeout=8.0)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            ips = set()
            for line in lines:
                clean = line.strip()
                if not clean or clean.startswith(";") or clean.startswith("#"):
                    continue
                # Extract IP or CIDR
                token = clean.split()[0].split(";")[0]
                if "/" in token:
                    # CIDR notation
                    ips.add(token)
                else:
                    if _is_safe_ip(token):
                        ips.add(token)
            cache.set(cache_key, list(ips), ttl_seconds=12 * 3600)  # 12h TTL
            return ips
    except Exception as e:
        logger.debug(f"Feed {name} fetch error: {e}")
    return set()


@registry.register(
    name="tor_and_blocklist_check",
    description="Check whether the IP is an active Tor exit node or listed on major public blocklists (Feodo Botnet Tracker, Emerging Threats Compromised IPs, Spamhaus DROP). Cached locally for 12 hours.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    timeout_seconds=12.0,
)
async def tor_and_blocklist_check(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    target_obj = ipaddress.ip_address(ip)
    matches = []
    is_tor_exit = False

    async with httpx.AsyncClient(timeout=8.0) as client:
        # Fetch feeds concurrently
        tasks = [
            _fetch_feed(client, name, url)
            for name, url in FEED_URLS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (name, url), res in zip(FEED_URLS.items(), results):
            if isinstance(res, set):
                # Check direct match
                if ip in res:
                    matches.append(name)
                    if name == "tor_exit_nodes":
                        is_tor_exit = True
                else:
                    # Check CIDR match if applicable
                    for entry in res:
                        if "/" in entry:
                            try:
                                net = ipaddress.ip_network(entry, strict=False)
                                if target_obj in net:
                                    matches.append(f"{name} ({entry})")
                                    break
                            except ValueError:
                                pass

    return {
        "ip": ip,
        "is_tor_exit_node": is_tor_exit,
        "blocklist_matches": matches,
        "listed_in_any": len(matches) > 0,
        "feeds_checked": list(FEED_URLS.keys()),
    }


# --------------------------------------------------------------------------
# Tool 10: otx_pulses
# --------------------------------------------------------------------------
@registry.register(
    name="otx_pulses",
    description="Query AlienVault OTX (Open Threat Exchange) for threat pulses, tags, malware families, and adversary campaigns associated with the IP (optional OTX_API_KEY).",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Target IP address"}
        },
        "required": ["ip"],
    },
    required_api_key="OTX_API_KEY",
    timeout_seconds=12.0,
)
async def otx_pulses(arguments: Dict[str, Any]) -> Dict[str, Any]:
    ip = arguments.get("ip", "").strip()
    if not _is_safe_ip(ip):
        return {"error": "Invalid IP address"}

    cache_key = f"otx:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {}
    if settings.otx_api_key:
        headers["X-OTX-API-KEY"] = settings.otx_api_key

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                pulse_count = pulse_info.get("count", len(pulses))

                pulse_summaries = []
                all_tags = set()
                for p in pulses[:5]:
                    name = p.get("name")
                    tags = p.get("tags", [])
                    all_tags.update(tags)
                    pulse_summaries.append({
                        "id": p.get("id"),
                        "name": name,
                        "created": p.get("created"),
                        "tags": tags[:5],
                    })

                out = {
                    "ip": ip,
                    "pulse_count": pulse_count,
                    "pulses": pulse_summaries,
                    "tags": list(all_tags)[:15],
                    "reputation": data.get("reputation", 0),
                }
                cache.set(cache_key, out)
                return out
            elif resp.status_code == 404:
                out = {"ip": ip, "pulse_count": 0, "pulses": [], "tags": []}
                cache.set(cache_key, out)
                return out
            elif resp.status_code == 403:
                return {
                    "skipped": True,
                    "reason": "AlienVault OTX API returned 403. Check OTX_API_KEY.",
                    "ip": ip,
                }
            else:
                return {"error": f"OTX returned status {resp.status_code}", "ip": ip}
    except Exception as e:
        logger.warning(f"OTX query failed: {e}")
        return {"error": f"AlienVault OTX query failed: {str(e)}", "ip": ip}

