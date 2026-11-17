"""
Executive standalone dark-mode HTML & Printable forensic reporting for SOC briefing.
"""

from __future__ import annotations

import html
from pathlib import Path
from sentryip.block_generator import generate_block_rules
from sentryip.models import FinalReport, Verdict


def generate_html_report(report: FinalReport) -> str:
    """Generate high-fidelity, standalone dark-mode HTML forensic report."""
    verdict_class = report.verdict.value.lower()
    score_color = "#e53e3e" if report.risk_score >= 60 else ("#dd6b20" if report.risk_score >= 25 else "#38a169")

    # Mitigation syntax
    rules = generate_block_rules(report.ip)
    rules_html = "".join([f"<div class='rule-item'><strong>{k}:</strong> <code>{html.escape(v)}</code></div>" for k, v in rules.items()])

    # MITRE TTPs
    mitre_html = ""
    if report.mitre_attack:
        mitre_rows = "".join([
            f"<tr><td><span class='badge badge-warning'>{html.escape(m.technique_id)}</span></td>"
            f"<td>{html.escape(m.tactic)}</td>"
            f"<td><strong>{html.escape(m.name)}</strong></td>"
            f"<td>{html.escape(m.description)}</td></tr>"
            for m in report.mitre_attack
        ])
        mitre_html = f"""
        <div class="card">
            <h2>⚔️ MITRE ATT&CK TTP Mapping</h2>
            <table>
                <thead><tr><th>ID</th><th>Tactic</th><th>Technique</th><th>Observation</th></tr></thead>
                <tbody>{mitre_rows}</tbody>
            </table>
        </div>
        """

    # Findings
    findings_html = ""
    if report.reputation_findings:
        findings_rows = "".join([
            f"<tr><td><strong>{html.escape(f.source)}</strong></td>"
            f"<td><span class='badge badge-{f.severity.lower()}'>{html.escape(f.severity.upper())}</span></td>"
            f"<td>{html.escape(f.finding)}</td></tr>"
            for f in report.reputation_findings
        ])
        findings_html = f"""
        <div class="card">
            <h2>🚨 Correlated Threat Findings</h2>
            <table>
                <thead><tr><th>Source</th><th>Severity</th><th>Evidence & Observation</th></tr></thead>
                <tbody>{findings_rows}</tbody>
            </table>
        </div>
        """

    # Reasoning & Actions
    reasoning_list = "".join([f"<li>{html.escape(r)}</li>" for r in report.reasoning])
    actions_list = "".join([f"<li><strong>{html.escape(a)}</strong></li>" for a in report.recommended_actions])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentryIP Forensic Report - {html.escape(report.ip)}</title>
<style>
    :root {{
        --bg: #0d1117;
        --card-bg: #161b22;
        --border: #30363d;
        --text: #c9d1d9;
        --heading: #f0f6fc;
        --accent: #58a6ff;
        --safe: #2ea043;
        --suspicious: #d29922;
        --malicious: #f85149;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 24px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 1080px;
        margin: 0 auto;
    }}
    .header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 2px solid var(--border);
        padding-bottom: 20px;
        margin-bottom: 24px;
    }}
    h1, h2, h3 {{ color: var(--heading); margin-top: 0; }}
    .badge {{
        display: inline-block;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 13px;
        text-transform: uppercase;
    }}
    .badge-safe {{ background: var(--safe); color: #fff; }}
    .badge-suspicious {{ background: var(--suspicious); color: #000; }}
    .badge-malicious {{ background: var(--malicious); color: #fff; }}
    .badge-high, .badge-critical {{ background: var(--malicious); color: #fff; }}
    .badge-medium {{ background: var(--suspicious); color: #000; }}
    .badge-low, .badge-info {{ background: #1f6feb; color: #fff; }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 20px;
        margin-bottom: 20px;
    }}
    .card {{
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }}
    .gauge-container {{
        background: #21262d;
        height: 14px;
        border-radius: 7px;
        overflow: hidden;
        margin: 10px 0;
    }}
    .gauge-fill {{
        height: 100%;
        background: {score_color};
        width: {report.risk_score}%;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
    }}
    th, td {{
        text-align: left;
        padding: 10px;
        border-bottom: 1px solid var(--border);
    }}
    th {{ color: var(--accent); }}
    code {{
        background: #21262d;
        padding: 2px 6px;
        border-radius: 4px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        color: #79c0ff;
    }}
    .rule-item {{
        margin-bottom: 8px;
        padding: 8px;
        background: #090d13;
        border-radius: 6px;
    }}
    @media print {{
        body {{ background: #fff; color: #000; }}
        .card {{ background: #f6f8fa; border: 1px solid #d0d7de; color: #000; }}
        h1, h2, th {{ color: #000; }}
        code {{ background: #eee; color: #000; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>🛡️ SentryIP Threat Forensic Briefing</h1>
            <div>Target: <code>{html.escape(report.ip)}</code> ({report.ip_type.value.upper()}) | Generated: {report.timestamp}</div>
        </div>
        <div style="text-align: right;">
            <span class="badge badge-{verdict_class}">{report.verdict.value}</span>
            <div style="font-size: 20px; font-weight: bold; margin-top: 8px; color: {score_color};">Risk: {report.risk_score}/100</div>
        </div>
    </div>

    <div class="card">
        <h2>📋 Executive Summary</h2>
        <div class="gauge-container"><div class="gauge-fill"></div></div>
        <p>{html.escape(report.summary)}</p>
    </div>

    <div class="grid">
        <div class="card">
            <h2>🌐 Infrastructure Attribution</h2>
            <table>
                <tr><td><strong>Organization</strong></td><td>{html.escape(report.ownership.org or 'Unknown')}</td></tr>
                <tr><td><strong>ASN</strong></td><td>{html.escape(report.ownership.asn or 'Unknown')}</td></tr>
                <tr><td><strong>CIDR Netblock</strong></td><td><code>{html.escape(report.ownership.cidr or 'N/A')}</code></td></tr>
                <tr><td><strong>Registrar Country</strong></td><td>{html.escape(report.ownership.country or 'N/A')}</td></tr>
                <tr><td><strong>Abuse Contact</strong></td><td><code>{html.escape(report.ownership.abuse_contact or 'N/A')}</code></td></tr>
            </table>
        </div>

        <div class="card">
            <h2>📡 Network & Connectivity</h2>
            <table>
                <tr><td><strong>Reverse DNS (PTR)</strong></td><td><code>{html.escape(report.network.rdns or 'None')}</code></td></tr>
                <tr><td><strong>ISP</strong></td><td>{html.escape(report.network.isp or 'N/A')}</td></tr>
                <tr><td><strong>Hosting / Datacenter</strong></td><td>{'Yes' if report.network.hosting else 'No'}</td></tr>
                <tr><td><strong>VPN / Proxy</strong></td><td>{'Yes' if report.network.vpn_proxy else 'No'}</td></tr>
                <tr><td><strong>TOR Exit Node</strong></td><td>{'<span class="badge badge-malicious">Active Tor Node</span>' if report.network.tor else 'No'}</td></tr>
            </table>
        </div>
    </div>

    <div class="card">
        <h2>🔌 Passive Attack Surface</h2>
        <p><strong>Open Ports:</strong> {', '.join([str(p) for p in report.open_ports]) if report.open_ports else 'None observed'}</p>
        <p><strong>Known CVEs:</strong> {', '.join(report.vulns) if report.vulns else 'No public CVEs cataloged'}</p>
    </div>

    {findings_html}
    {mitre_html}

    <div class="card">
        <h2>🛡️ SOC Deductions & Mitigation Actions</h2>
        <h3>Analyst Chain of Evidence</h3>
        <ul>{reasoning_list}</ul>
        <h3>Recommended Incident Response</h3>
        <ul>{actions_list}</ul>
    </div>

    <div class="card">
        <h2>🛑 Automated Firewall / EDR Containment Rules</h2>
        {rules_html}
    </div>

    <div style="text-align: center; color: #8b949e; font-size: 12px; margin-top: 30px;">
        SentryIP Autonomous Threat Intel Analyst • Passive Intelligence Defense • Advisory SOC Forensic Briefing
    </div>
</div>
</body>
</html>"""
    return html_content


def export_report_to_html(report: FinalReport, output_path: str) -> Path:
    """Write generated HTML forensic briefing to file."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    content = generate_html_report(report)
    p.write_text(content, encoding="utf-8")
    return p
