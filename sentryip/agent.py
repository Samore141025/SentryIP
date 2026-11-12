"""
Autonomous SOC Threat Intelligence Agent Loop.
Supports single-key Google Gemini (via google-genai SDK), Anthropic Claude,
and automated heuristic correlation.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Callable, Dict, List, Optional

from sentryip.config import settings
from sentryip.logging import logger
from sentryip.models import FinalReport, IPType, OwnershipInfo, NetworkInfo, GeolocationInfo, Verdict
from sentryip.prompts import SYSTEM_PROMPT
from sentryip.tools.base import registry
from sentryip.tools.validator import classify_ip
from sentryip.heuristic import synthesize_deterministic_report


class SentryIPAgent:
    """Autonomous SOC agent executing a tool-calling reasoning loop to investigate IPs."""

    def __init__(
        self,
        model: Optional[str] = None,
        max_steps: Optional[int] = None,
        on_tool_start: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        on_tool_finish: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.model = model
        self.max_steps = max_steps or settings.max_steps
        self.on_tool_start = on_tool_start
        self.on_tool_finish = on_tool_finish

    async def investigate(self, ip: str) -> FinalReport:
        """Run the autonomous investigation loop for a target IP address."""
        ip_clean = ip.strip()
        logger.info(f"Initiating investigation for IP: {ip_clean}")

        # 1. Local pre-validation
        if self.on_tool_start:
            self.on_tool_start("validate_ip", {"ip": ip_clean})
        pre_val = classify_ip(ip_clean)
        if self.on_tool_finish:
            self.on_tool_finish("validate_ip", pre_val)

        if not pre_val.get("valid") or not pre_val.get("is_public"):
            ip_type_str = pre_val.get("ip_type", "invalid")
            try:
                ip_type_enum = IPType(ip_type_str)
            except ValueError:
                ip_type_enum = IPType.INVALID

            summary = (
                f"Target IP {ip_clean} is classified as {ip_type_str.upper()}. "
                "Investigation stopped early: Non-public/unroutable addresses cannot and should "
                "not be queried against public internet threat intelligence databases."
            )
            return FinalReport(
                ip=ip_clean,
                ip_type=ip_type_enum,
                verdict=Verdict.SAFE if ip_type_str in ["private", "loopback"] else Verdict.UNKNOWN,
                risk_score=0,
                confidence=100,
                summary=summary,
                ownership=OwnershipInfo(org=f"RFC {ip_type_str} allocation"),
                network=NetworkInfo(),
                geolocation=GeolocationInfo(),
                open_ports=[],
                vulns=[],
                reputation_findings=[],
                reasoning=[
                    f"Address evaluated by validator: {ip_clean}",
                    f"Classified as non-public ({ip_type_str}).",
                    "Early termination enforced as per passive SOC protocol.",
                ],
                recommended_actions=[
                    "Verify internal routing or endpoint asset inventory if investigating internal RFC1918 traffic.",
                    "No external firewall block needed for private address space.",
                ],
                tools_used=["validate_ip"],
                tools_skipped=[],
            )

        # 2. Check available LLM Provider: Google Gemini prioritized if set
        if settings.gemini_api_key:
            try:
                return await self._run_gemini_agent(ip_clean, pre_val)
            except Exception as e:
                logger.error(f"Gemini agent failed: {e}. Falling back to autonomous correlation.", exc_info=True)
                return await self._run_autonomous_tools_and_correlate(ip_clean, pre_val)

        if settings.anthropic_api_key:
            try:
                return await self._run_claude_agent(ip_clean, pre_val)
            except Exception as e:
                logger.error(f"Claude agent failed: {e}. Falling back to autonomous correlation.", exc_info=True)
                return await self._run_autonomous_tools_and_correlate(ip_clean, pre_val)

        # 3. Autonomous Correlation Mode (Zero LLM key required)
        return await self._run_autonomous_tools_and_correlate(ip_clean, pre_val)

    async def _run_gemini_agent(self, ip_clean: str, pre_val: Dict[str, Any]) -> FinalReport:
        """Run autonomous investigation using Google Gemini API via official SDK or direct REST fallback."""
        model_name = self.model or settings.gemini_model or "gemini-2.5-flash"

        # Pre-fetch intelligence feeds so Gemini has complete context to cross-correlate
        autonomous_report = await self._run_autonomous_tools_and_correlate(ip_clean, pre_val)

        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"You are investigating target IP: {ip_clean}\n"
            f"Here is the raw passive threat intelligence gathered from all active feeds:\n"
            f"{autonomous_report.model_dump_json(indent=2)}\n\n"
            "Analyze and cross-correlate all the indicators above as an elite SOC threat analyst. "
            "Output the final consensus report in valid JSON enclosed in ```json ... ``` code blocks."
        )

        report_text = ""

        # Strategy A: Use official google-genai SDK if available
        try:
            import importlib
            genai_mod = importlib.import_module("google.genai")
            client = genai_mod.Client(api_key=settings.gemini_api_key)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=model_name,
                contents=prompt,
            )
            report_text = getattr(response, "text", "") or ""
        except Exception as sdk_err:
            logger.debug(f"google-genai SDK unavailable or error ({sdk_err}), using native HTTP REST fallback")
            # Strategy B: Clean, direct Google Gemini REST API using httpx (zero import issues)
            import httpx
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ]
            }
            async with httpx.AsyncClient(timeout=25.0) as http_client:
                resp = await http_client.post(
                    api_url,
                    params={"key": settings.gemini_api_key},
                    json=payload,
                )
                if resp.status_code == 200:
                    resp_json = resp.json()
                    candidates = resp_json.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            report_text = parts[0].get("text", "")
                else:
                    logger.warning(f"Gemini REST API returned status {resp.status_code}: {resp.text}")

        parsed = self._extract_json_report(
            report_text,
            ip_clean,
            set(autonomous_report.tools_used),
            set(autonomous_report.tools_skipped),
        )
        return parsed or autonomous_report

    async def _run_claude_agent(self, ip_clean: str, pre_val: Dict[str, Any]) -> FinalReport:
        """Run tool-calling loop using Anthropic Claude."""
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        model_name = self.model or settings.sentryip_model or "claude-sonnet-4-5"

        messages: List[Dict[str, Any]] = [
            {
                "role": "user",
                "content": f"Investigate the following IP address for potential security threats: {ip_clean}. "
                           "Remember: Call validate_ip first, cross-correlate multiple intel tools, "
                           "and output the final report as a valid JSON object.",
            }
        ]

        tools = registry.get_anthropic_tools()
        tools_executed: set[str] = {"validate_ip"}
        tools_skipped: set[str] = set()

        if not settings.abuseipdb_api_key:
            tools_skipped.add("abuseipdb_check")
        if not settings.vt_api_key:
            tools_skipped.add("virustotal_ip")
        if not settings.otx_api_key:
            tools_skipped.add("otx_pulses")

        step = 0
        final_report: Optional[FinalReport] = None

        while step < self.max_steps:
            step += 1
            response = await client.messages.create(
                model=model_name,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=messages,
                tools=tools,
            )

            tool_calls = [c for c in response.content if c.type == "tool_use"]
            text_blocks = [c.text for c in response.content if c.type == "text"]

            if tool_calls:
                messages.append({"role": "assistant", "content": response.content})

                async def _exec_tool(tc):
                    name = tc.name
                    args = tc.input
                    if self.on_tool_start:
                        self.on_tool_start(name, args)

                    result = await registry.execute(name, args)
                    tools_executed.add(name)

                    if self.on_tool_finish:
                        self.on_tool_finish(name, result)

                    return {
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": json.dumps(result),
                    }

                tool_results = await asyncio.gather(*[_exec_tool(tc) for tc in tool_calls])
                messages.append({"role": "user", "content": tool_results})
                continue

            full_text = "\n".join(text_blocks)
            final_report = self._extract_json_report(full_text, ip_clean, tools_executed, tools_skipped)
            if final_report:
                break

        return final_report or await self._run_autonomous_tools_and_correlate(ip_clean, pre_val)

    async def _run_autonomous_tools_and_correlate(
        self, ip: str, ip_classification: Dict[str, Any]
    ) -> FinalReport:
        """Executes all passive threat tools concurrently with live events and correlates results."""
        tools_to_run = [
            "rdap_whois",
            "reverse_dns",
            "geolocate",
            "shodan_internetdb",
            "greynoise_check",
            "tor_and_blocklist_check",
            "otx_pulses",
            "abuseipdb_check",
            "virustotal_ip",
        ]

        tool_results: Dict[str, Dict[str, Any]] = {"validate_ip": ip_classification}
        tools_executed: List[str] = ["validate_ip"]
        tools_skipped: List[str] = []

        async def _run_single(tool_name: str):
            if self.on_tool_start:
                self.on_tool_start(tool_name, {"ip": ip})

            res = await registry.execute(tool_name, {"ip": ip})

            if self.on_tool_finish:
                self.on_tool_finish(tool_name, res)

            return tool_name, res

        tasks = [_run_single(t) for t in tools_to_run]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for item in gathered:
            if isinstance(item, tuple):
                name, data = item
                if data.get("skipped"):
                    tools_skipped.append(name)
                else:
                    tool_results[name] = data
                    tools_executed.append(name)

        return synthesize_deterministic_report(
            ip=ip,
            ip_classification=ip_classification,
            tool_results=tool_results,
            tools_used=tools_executed,
            tools_skipped=tools_skipped,
        )

    def _extract_json_report(
        self,
        text: str,
        target_ip: str,
        tools_executed: set[str],
        tools_skipped: set[str],
    ) -> Optional[FinalReport]:
        """Extract and validate the JSON report from LLM response."""
        json_str = ""

        matches = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if matches:
            json_str = matches[-1]
        else:
            raw_match = re.search(r"(\{\s*\"ip\":.*?\})", text, re.DOTALL)
            if raw_match:
                json_str = raw_match.group(1)

        if not json_str:
            return None

        try:
            data = json.loads(json_str)
            if not data.get("tools_used"):
                data["tools_used"] = list(tools_executed)
            if not data.get("tools_skipped"):
                data["tools_skipped"] = list(tools_skipped)

            return FinalReport.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse or validate JSON report: {e}")
            return None
