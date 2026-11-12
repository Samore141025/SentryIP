"""
Pydantic data models for SentryIP structured tool inputs and final SOC reports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class IPType(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    BOGON = "bogon"
    INVALID = "invalid"


class OwnershipInfo(BaseModel):
    org: Optional[str] = Field(default=None, description="Organization or owner name")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number (e.g., AS15169)")
    cidr: Optional[str] = Field(default=None, description="Allocated CIDR or netblock")
    country: Optional[str] = Field(default=None, description="Registrar country code or name")
    abuse_contact: Optional[str] = Field(default=None, description="Abuse contact email or phone")


class NetworkInfo(BaseModel):
    rdns: Optional[str] = Field(default=None, description="Reverse DNS / PTR record hostname")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider")
    hosting: Optional[bool] = Field(default=None, description="Datacenter / cloud / hosting flag")
    vpn_proxy: Optional[bool] = Field(default=None, description="Known VPN, proxy, or exit node")
    tor: Optional[bool] = Field(default=None, description="Known active Tor exit node")


class GeolocationInfo(BaseModel):
    country: Optional[str] = Field(default=None)
    region: Optional[str] = Field(default=None)
    city: Optional[str] = Field(default=None)
    latitude: Optional[float] = Field(default=None)
    longitude: Optional[float] = Field(default=None)
    timezone: Optional[str] = Field(default=None)


class ReputationFinding(BaseModel):
    source: str = Field(description="Origin source, e.g. VirusTotal, AbuseIPDB, Blocklist, GreyNoise")
    finding: str = Field(description="Summary of the specific signal or observation")
    severity: str = Field(default="info", description="Severity: info, low, medium, high, critical")


class FinalReport(BaseModel):
    ip: str = Field(description="Target IP address investigated")
    ip_type: IPType = Field(description="Classification of the IP address")
    verdict: Verdict = Field(description="Final assessment: SAFE, SUSPICIOUS, MALICIOUS, or UNKNOWN")
    risk_score: int = Field(ge=0, le=100, description="Risk score from 0 (benign) to 100 (confirmed threat)")
    confidence: int = Field(ge=0, le=100, description="Analyst confidence level from 0 to 100")
    summary: str = Field(description="Executive SOC summary explaining the rationale and findings")
    ownership: OwnershipInfo = Field(default_factory=OwnershipInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    geolocation: GeolocationInfo = Field(default_factory=GeolocationInfo)
    open_ports: List[int] = Field(default_factory=list, description="Passively identified open ports")
    vulns: List[str] = Field(default_factory=list, description="Associated CVEs or known vulnerabilities")
    reputation_findings: List[ReputationFinding] = Field(default_factory=list)
    reasoning: List[str] = Field(default_factory=list, description="Step-by-step SOC analyst chain of evidence")
    recommended_actions: List[str] = Field(default_factory=list, description="Concrete blue-team mitigation steps")
    tools_used: List[str] = Field(default_factory=list, description="List of tools successfully queried")
    tools_skipped: List[str] = Field(default_factory=list, description="List of tools skipped (e.g. missing API keys)")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Investigation timestamp in UTC ISO format",
    )

