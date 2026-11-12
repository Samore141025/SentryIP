import pytest
import json
from pydantic import ValidationError
from sentryip.models import (
    FinalReport,
    Verdict,
    IPType,
    OwnershipInfo,
    NetworkInfo,
    GeolocationInfo,
    ReputationFinding,
)


def test_final_report_valid_schema():
    report_dict = {
        "ip": "1.1.1.1",
        "ip_type": "public",
        "verdict": "SAFE",
        "risk_score": 5,
        "confidence": 95,
        "summary": "Cloudflare public DNS resolver, clean reputation across all threat feeds.",
        "ownership": {
            "org": "Cloudflare, Inc.",
            "asn": "AS13335",
            "cidr": "1.1.1.0/24",
            "country": "US",
            "abuse_contact": "abuse@cloudflare.com",
        },
        "network": {
            "rdns": "one.one.one.one",
            "isp": "Cloudflare, Inc.",
            "hosting": True,
            "vpn_proxy": False,
            "tor": False,
        },
        "geolocation": {
            "country": "US",
            "city": "San Francisco",
        },
        "open_ports": [53, 853, 443],
        "vulns": [],
        "reputation_findings": [
            {
                "source": "GreyNoise",
                "finding": "RIOT verified benign service (Cloudflare DNS)",
                "severity": "info",
            }
        ],
        "reasoning": [
            "Validated as public IP.",
            "0 reports on AbuseIPDB.",
            "GreyNoise RIOT verified benign service.",
        ],
        "recommended_actions": [
            "No action required; safe public DNS resolver."
        ],
        "tools_used": ["validate_ip", "rdap_whois", "reverse_dns", "greynoise_check"],
        "tools_skipped": ["virustotal_ip"],
        "timestamp": "2026-11-12T12:00:00Z",
    }

    report = FinalReport.model_validate(report_dict)
    assert report.ip == "1.1.1.1"
    assert report.verdict == Verdict.SAFE
    assert report.risk_score == 5
    assert report.confidence == 95
    assert report.ownership.asn == "AS13335"
    assert 53 in report.open_ports


def test_final_report_invalid_risk_score():
    report_dict = {
        "ip": "1.1.1.1",
        "ip_type": "public",
        "verdict": "SAFE",
        "risk_score": 150,  # Invalid: must be <= 100
        "confidence": 95,
        "summary": "Summary",
    }
    with pytest.raises(ValidationError):
        FinalReport.model_validate(report_dict)


def test_final_report_invalid_verdict():
    report_dict = {
        "ip": "1.1.1.1",
        "ip_type": "public",
        "verdict": "EXTREMELY_BAD",  # Invalid enum value
        "risk_score": 90,
        "confidence": 95,
        "summary": "Summary",
    }
    with pytest.raises(ValidationError):
        FinalReport.model_validate(report_dict)

