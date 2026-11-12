import pytest
from sentryip.tools.validator import classify_ip


def test_classify_valid_public_ipv4():
    res = classify_ip("8.8.8.8")
    assert res["valid"] is True
    assert res["is_public"] is True
    assert res["ip_type"] == "public"
    assert res["version"] == "IPv4"


def test_classify_valid_public_ipv6():
    res = classify_ip("2001:4860:4860::8888")
    assert res["valid"] is True
    assert res["is_public"] is True
    assert res["ip_type"] == "public"
    assert res["version"] == "IPv6"


def test_classify_private_rfc1918():
    for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.5"]:
        res = classify_ip(ip)
        assert res["valid"] is True
        assert res["is_public"] is False
        assert res["ip_type"] == "private"
        assert res["is_private"] is True


def test_classify_loopback():
    res = classify_ip("127.0.0.1")
    assert res["valid"] is True
    assert res["is_public"] is False
    assert res["ip_type"] == "loopback"
    assert res["is_loopback"] is True

    res6 = classify_ip("::1")
    assert res6["valid"] is True
    assert res6["is_public"] is False
    assert res6["ip_type"] == "loopback"


def test_classify_invalid():
    for bad_ip in ["999.999.999.999", "not_an_ip", "192.168.1.300", ""]:
        res = classify_ip(bad_ip)
        assert res["valid"] is False
        assert res["is_public"] is False
        assert res["ip_type"] == "invalid"

