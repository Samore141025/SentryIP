"""
Slack and Discord incoming webhook dispatcher for SOC alert routing.
"""

from __future__ import annotations

import httpx
from typing import Dict, Any
from sentryip.logging import logger
from sentryip.models import FinalReport, Verdict


async def send_webhook_alert(webhook_url: str, report: FinalReport) -> bool:
    """Send card-style notification to Discord or Slack."""
    verdict_emoji = "🟢" if report.verdict == Verdict.SAFE else ("🟡" if report.verdict == Verdict.SUSPICIOUS else "🔴")
    score_bar = f"{report.risk_score}/100"

    is_discord = "discord.com" in webhook_url

    if is_discord:
        # Discord Embed payload
        color = 0x2ea043 if report.verdict == Verdict.SAFE else (0xd29922 if report.verdict == Verdict.SUSPICIOUS else 0xf85149)
        payload: Dict[str, Any] = {
            "embeds": [
                {
                    "title": f"🛡️ SentryIP Alert: {report.ip} is {report.verdict.value} {verdict_emoji}",
                    "description": report.summary,
                    "color": color,
                    "fields": [
                        {"name": "Risk Score", "value": score_bar, "inline": True},
                        {"name": "Confidence", "value": f"{report.confidence}%", "inline": True},
                        {"name": "Organization / ASN", "value": f"{report.ownership.org or 'Unknown'} ({report.ownership.asn or 'N/A'})", "inline": False},
                        {"name": "rDNS", "value": f"`{report.network.rdns or 'None'}`", "inline": True},
                        {"name": "Tor Exit", "value": "Yes ⚠️" if report.network.tor else "No", "inline": True},
                        {"name": "Open Ports", "value": ", ".join(map(str, report.open_ports)) or "None", "inline": False},
                        {"name": "Recommended Action", "value": report.recommended_actions[0] if report.recommended_actions else "No action needed", "inline": False},
                    ],
                    "footer": {"text": "SentryIP Autonomous SOC Threat Intelligence Analyst"},
                    "timestamp": report.timestamp,
                }
            ]
        }
    else:
        # Standard Slack BlockKit payload
        payload = {
            "text": f"{verdict_emoji} SentryIP Alert: {report.ip} ({report.verdict.value} - Risk: {score_bar})",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🛡️ SentryIP Threat Report: {report.ip} [{report.verdict.value}]"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Summary:* {report.summary}\n*Risk Score:* `{score_bar}` | *Confidence:* `{report.confidence}%`\n*Attribution:* {report.ownership.org or 'Unknown'} (`{report.ownership.asn or 'N/A'}`)"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Mitigation:* {report.recommended_actions[0] if report.recommended_actions else 'No action needed'}"
                    }
                }
            ]
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code in [200, 204]:
                logger.info(f"Webhook alert successfully dispatched to {webhook_url}")
                return True
            else:
                logger.warning(f"Webhook alert failed with status {resp.status_code}: {resp.text}")
                return False
    except Exception as e:
        logger.error(f"Failed to deliver webhook alert: {e}")
        return False
