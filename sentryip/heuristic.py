"""
Heuristic fallback engine that synthesizes intelligence tool outputs into a FinalReport
when an LLM API key is not configured, ensuring the agent always executes and produces
a full verdict and report directly without error.
"""

from __future__ import annotations

from typing import Any, Dict, List
from sentryip.models import (
    FinalReport,
    Verdict,
    IPType,
    OwnershipInfo,
    NetworkInfo,
    GeolocationInfo,
    ReputationFinding,
)


def synthesize_deterministic_report(
    ip: str,
    ip_classification: Dict[str, Any],
    tool_results: Dict[str, Dict[str, Any]],
    tools_used: List[str],
    tools_skipped: List[str],
) -> FinalReport:
    """Analyze real intelligence data gathered from passive feeds and calculate risk score, verdict, and findings."""
    ip_type_str = ip_classification.get("ip_type", "public")
    try:
        ip_type = IPType(ip_type_str)
    except ValueError:
        ip_type = IPType.PUBLIC

    # Extract info
    rdap = tool_results.get("rdap_whois", {})
    rdns = tool_results.get("reverse_dns", {})
    geo = tool_results.get("geolocate", {})
    abuse = tool_results.get("abuseipdb_check", {})
    vt = tool_results.get("virustotal_ip", {})
    grey = tool_results.get("greynoise_check", {})
    shodan = tool_results.get("shodan_internetdb", {})
    blocklist = tool_results.get("tor_and_blocklist_check", {})
    otx = tool_results.get("otx_pulses", {})

    risk_score = 0
    confidence = 85
    findings: List[ReputationFinding] = []
    reasoning: List[str] = []
    actions: List[str] = []

    # 1. Blocklist evaluation
    is_tor = blocklist.get("is_tor_exit_node", False)
    matches = blocklist.get("blocklist_matches", [])
    if is_tor:
        risk_score += 35
        findings.append(ReputationFinding(
            source="Tor Project",
            finding="Active Tor exit node confirmed on directory list",
            severity="medium",
        ))
        reasoning.append("Target IP is an active Tor exit node.")

    if matches:
        for m in matches:
            if m != "tor_exit_nodes":
                risk_score += 45
                findings.append(ReputationFinding(
                    source="Threat Blocklists",
                    finding=f"Listed on threat feed: {m}",
                    severity="critical",
                ))
                reasoning.append(f"Confirmed match on active malicious blocklist: {m}.")

    # 2. AbuseIPDB
    abuse_score = abuse.get("abuse_confidence_score", 0)
    total_reports = abuse.get("total_reports", 0)
    is_whitelisted = abuse.get("is_whitelisted", False)
    if is_whitelisted:
        risk_score = max(0, risk_score - 20)
        reasoning.append("IP address is verified whitelisted on AbuseIPDB.")
    elif total_reports > 0:
        if abuse_score > 50:
            risk_score += 40
            findings.append(ReputationFinding(
                source="AbuseIPDB",
                finding=f"High abuse confidence {abuse_score}% with {total_reports} community reports",
                severity="high",
            ))
            reasoning.append(f"AbuseIPDB reports indicate malicious activity ({total_reports} reports, {abuse_score}% confidence).")
        else:
            risk_score += 15
            findings.append(ReputationFinding(
                source="AbuseIPDB",
                finding=f"Observed in {total_reports} reports (confidence: {abuse_score}%)",
                severity="low",
            ))

    # 3. VirusTotal
    vt_mal = vt.get("malicious_count", 0)
    vt_susp = vt.get("suspicious_count", 0)
    if vt_mal >= 3:
        risk_score += 50
        findings.append(ReputationFinding(
            source="VirusTotal",
            finding=f"Flagged by {vt_mal} security vendors as malicious ({vt_susp} suspicious)",
            severity="critical",
        ))
        reasoning.append(f"VirusTotal intelligence correlates {vt_mal} positive malware/C2 engine detections.")
    elif vt_mal > 0 or vt_susp > 1:
        risk_score += 25
        findings.append(ReputationFinding(
            source="VirusTotal",
            finding=f"Flagged by {vt_mal} vendors as malicious and {vt_susp} as suspicious",
            severity="medium",
        ))

    # 4. GreyNoise
    is_riot = grey.get("riot", False)
    grey_class = grey.get("classification", "unknown")
    grey_name = grey.get("name")
    if is_riot:
        risk_score = max(0, risk_score - 30)
        findings.append(ReputationFinding(
            source="GreyNoise RIOT",
            finding=f"Rule It Out verified benign service: {grey_name or 'Trusted Public Service'}",
            severity="info",
        ))
        reasoning.append(f"GreyNoise RIOT verified benign service ({grey_name}).")
    elif grey_class == "malicious":
        risk_score += 35
        findings.append(ReputationFinding(
            source="GreyNoise",
            finding="GreyNoise classified this actor as malicious mass scanner",
            severity="high",
        ))
    elif grey_class == "benign":
        risk_score = max(0, risk_score - 15)
        reasoning.append("GreyNoise classified mass activity as benign researcher/scanner.")

    # 5. Open Ports & Vulnerabilities
    open_ports = shodan.get("open_ports", [])
    vulns = shodan.get("vulns", [])
    if vulns:
        risk_score += 20
        findings.append(ReputationFinding(
            source="Shodan InternetDB",
            finding=f"Detected {len(vulns)} unpatched CVEs: {', '.join(vulns[:3])}",
            severity="high",
        ))
        reasoning.append(f"Passive attack surface reveals {len(vulns)} known CVEs.")

    if 22 in open_ports or 3389 in open_ports:
        findings.append(ReputationFinding(
            source="Passive Attack Surface",
            finding="Exposed remote management ports (SSH/RDP) discovered",
            severity="low",
        ))

    # 6. OTX
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count > 5:
        risk_score += 20
        findings.append(ReputationFinding(
            source="AlienVault OTX",
            finding=f"Referenced in {pulse_count} security threat intelligence pulses",
            severity="medium",
        ))
        reasoning.append(f"Correlated across {pulse_count} AlienVault OTX pulses.")

    # Clamp risk score
    risk_score = min(100, max(0, risk_score))

    # Determine Verdict
    if risk_score >= 60 or (matches and not is_riot):
        verdict = Verdict.MALICIOUS
        actions.append("Block traffic from this IP on perimeter firewalls and edge ACLs immediately.")
        actions.append("Search SIEM/EDR logs for recent ingress/egress connections within the past 30 days.")
        actions.append("Isolate any internal endpoints communicating with this IP address.")
    elif risk_score >= 25 or is_tor:
        verdict = Verdict.SUSPICIOUS
        actions.append("Add IP to SIEM alert watchlist and monitor for anomalous outbound sessions.")
        actions.append("Enforce MFA or stepped-up authentication if this IP attempts authentication.")
        actions.append("Review whether connection originates from authorized corporate VPN or proxy.")
    else:
        verdict = Verdict.SAFE
        actions.append("No active mitigation required; IP exhibits clean or benign reputation.")
        actions.append("Maintain standard security baseline monitoring.")

    # Build Ownership & Network
    ownership = OwnershipInfo(
        org=rdap.get("org_name") or geo.get("org") or geo.get("isp"),
        asn=rdap.get("asn") or geo.get("asn"),
        cidr=rdap.get("cidr"),
        country=rdap.get("country") or geo.get("country"),
        abuse_contact=rdap.get("abuse_contact"),
    )

    network = NetworkInfo(
        rdns=rdns.get("primary_ptr"),
        isp=geo.get("isp") or rdap.get("org_name"),
        hosting=geo.get("hosting"),
        vpn_proxy=geo.get("proxy") or geo.get("vpn"),
        tor=is_tor,
    )

    geolocation = GeolocationInfo(
        country=geo.get("country"),
        region=geo.get("region"),
        city=geo.get("city"),
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        timezone=geo.get("timezone"),
    )

    summary = (
        f"Passive threat intelligence assessment for {ip} completed with a verdict of {verdict.value} "
        f"(Risk Score: {risk_score}/100, Confidence: {confidence}%). "
        f"Attributed to {ownership.org or 'Unknown Entity'} ({ownership.asn or 'Unknown ASN'}), "
        f"located in {geolocation.city or 'Unknown City'}, {geolocation.country or 'Unknown Country'}. "
    )
    if findings:
        summary += f"Identified {len(findings)} key threat indicators across multi-source feeds."
    else:
        summary += "No adverse threat signals or malicious indicators detected across active feeds."

    return FinalReport(
        ip=ip,
        ip_type=ip_type,
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        summary=summary,
        ownership=ownership,
        network=network,
        geolocation=geolocation,
        open_ports=open_ports,
        vulns=vulns,
        reputation_findings=findings,
        reasoning=reasoning,
        recommended_actions=actions,
        tools_used=tools_used,
        tools_skipped=tools_skipped,
    )

