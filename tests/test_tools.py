import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sentryip.tools.base import registry
from sentryip.tools.validator import validate_ip
from sentryip.tools.providers import (
    shodan_internetdb,
    greynoise_check,
    abuseipdb_check,
    virustotal_ip,
)


@pytest.mark.asyncio
async def test_validate_ip_tool():
    res = await registry.execute("validate_ip", {"ip": "1.1.1.1"})
    assert res["valid"] is True
    assert res["is_public"] is True
    assert res["ip_type"] == "public"


@pytest.mark.asyncio
async def test_shodan_internetdb_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "1.1.1.1",
        "ports": [53, 80, 443],
        "cpes": ["cpe:/a:cloudflare:dns"],
        "vulns": ["CVE-2020-0001"],
        "hostnames": ["one.one.one.one"],
        "tags": ["dns"],
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await registry.execute("shodan_internetdb", {"ip": "1.1.1.1"})
        assert res["ip"] == "1.1.1.1"
        assert res["open_ports"] == [53, 80, 443]
        assert "CVE-2020-0001" in res["vulns"]


@pytest.mark.asyncio
async def test_greynoise_riot_mocked():
    from sentryip.cache import cache
    cache.clear()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await registry.execute("greynoise_check", {"ip": "8.8.8.8"})
        assert res["riot"] is True
        assert res["classification"] == "benign"
        assert res["name"] == "Google Public DNS"


@pytest.mark.asyncio
async def test_abuseipdb_missing_key_skipped():
    with patch("sentryip.config.settings.abuseipdb_api_key", ""):
        res = await registry.execute("abuseipdb_check", {"ip": "8.8.8.8"})
        assert res.get("skipped") is True
        assert "not configured" in res.get("reason", "")


@pytest.mark.asyncio
async def test_virustotal_missing_key_skipped():
    with patch("sentryip.config.settings.vt_api_key", ""):
        res = await registry.execute("virustotal_ip", {"ip": "8.8.8.8"})
        assert res.get("skipped") is True
        assert "not configured" in res.get("reason", "")

