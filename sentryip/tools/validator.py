"""
Validation and classification tool for IPv4 and IPv6 addresses.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict
from sentryip.tools.base import registry


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """Validate and classify an IP string using python ipaddress module."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError as e:
        return {
            "valid": False,
            "ip": ip_str,
            "ip_type": "invalid",
            "is_public": False,
            "error": f"Invalid IP address format: {str(e)}",
        }

    version = addr.version
    is_loopback = addr.is_loopback
    is_private = addr.is_private
    is_link_local = addr.is_link_local
    is_multicast = addr.is_multicast
    is_reserved = addr.is_reserved
    is_unspecified = addr.is_unspecified

    # Check for bogon / 0.0.0.0/8 or 255.255.255.255
    ip_type = "public"
    is_public = True

    if is_loopback:
        ip_type = "loopback"
        is_public = False
    elif is_link_local:
        ip_type = "link-local"
        is_public = False
    elif is_multicast:
        ip_type = "multicast"
        is_public = False
    elif is_private:
        ip_type = "private"
        is_public = False
    elif is_reserved or is_unspecified:
        ip_type = "reserved"
        is_public = False

    # Check bogon subnets (e.g. 0.0.0.0/8 or 100.64.0.0/10 CGNAT, 192.0.2.0/24 documentation)
    if version == 4:
        first_octet = int(str(addr).split(".")[0])
        if first_octet == 0 or first_octet >= 240:
            ip_type = "bogon"
            is_public = False

    return {
        "valid": True,
        "ip": str(addr),
        "version": f"IPv{version}",
        "ip_type": ip_type,
        "is_public": is_public,
        "is_loopback": is_loopback,
        "is_private": is_private,
        "is_link_local": is_link_local,
        "is_multicast": is_multicast,
        "is_reserved": is_reserved,
    }


@registry.register(
    name="validate_ip",
    description="Validate IPv4/IPv6 format and classify as public, private (RFC1918), loopback, link-local, multicast, reserved, or bogon. If not public, the agent stops early and explains why.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "The target IP address to validate and classify.",
            }
        },
        "required": ["ip"],
    },
    timeout_seconds=5.0,
)
async def validate_ip(arguments: Dict[str, Any]) -> Dict[str, Any]:
    raw_ip = arguments.get("ip", "")
    return classify_ip(raw_ip)

