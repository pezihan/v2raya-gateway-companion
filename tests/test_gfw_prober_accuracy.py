import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.gfw_prober import GFWProber

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.gfw_prober import GFWProber

def test_ssl_warning_is_not_blocked():
    """Verify that SSL certificate issues / mismatch are NOT flagged as GFW blocked"""
    prober = GFWProber()

    async def _run():
        with patch.object(prober, "_resolve_domestic_dns", new_callable=AsyncMock) as mock_dom, \
             patch.object(prober, "_resolve_overseas_doh", new_callable=AsyncMock) as mock_overseas, \
             patch.object(prober, "_probe_tcp_tls", new_callable=AsyncMock) as mock_tls:
            
            mock_dom.return_value = {"1.2.3.4"}
            mock_overseas.return_value = {"1.2.3.4"}
            mock_tls.return_value = {
                "accessible": True,
                "latency_ms": 35,
                "error_type": "SSL_WARNING",
                "error": None,
                "note": "证书或TLS版本不匹配，但主机网络可达"
            }

            res = await prober.check_domain("self-signed-site.example", force_refresh=True)
            assert res["is_blocked"] is False
            assert res["block_type"] == "NONE"
            assert "主机网络可达" in res["summary"]

    asyncio.run(_run())

def test_port_80_fallback_for_http_only_site():
    """Verify that a site where 443 times out but 80 is open is NOT marked as blocked"""
    prober = GFWProber()

    async def _run():
        with patch.object(prober, "_resolve_domestic_dns", new_callable=AsyncMock) as mock_dom, \
             patch.object(prober, "_resolve_overseas_doh", new_callable=AsyncMock) as mock_overseas, \
             patch.object(prober, "_probe_tcp_tls", new_callable=AsyncMock) as mock_tls, \
             patch.object(prober, "_probe_tcp_port", new_callable=AsyncMock) as mock_port:

            mock_dom.return_value = {"112.80.248.75"}
            mock_overseas.return_value = {"112.80.248.75"}
            mock_tls.return_value = {
                "accessible": False,
                "error_type": "TIMEOUT",
                "error": "TCP 443 连接超时"
            }
            mock_port.return_value = True

            res = await prober.check_domain("http-only-site.example", force_refresh=True)
            assert res["is_blocked"] is False
            assert res["block_type"] == "NONE"

    asyncio.run(_run())

def test_tcp_rst_is_detected_as_blocked():
    """Verify that TCP RST (ConnectionResetError) is correctly flagged as GFW block"""
    prober = GFWProber()

    async def _run():
        with patch.object(prober, "_resolve_domestic_dns", new_callable=AsyncMock) as mock_dom, \
             patch.object(prober, "_resolve_overseas_doh", new_callable=AsyncMock) as mock_overseas, \
             patch.object(prober, "_probe_tcp_tls", new_callable=AsyncMock) as mock_tls:

            mock_dom.return_value = {"104.244.42.1"}
            mock_overseas.return_value = {"104.244.42.1"}
            mock_tls.return_value = {
                "accessible": False,
                "error_type": "TCP_RST",
                "error": "TCP 连接被重置 (GFW 典型 RST 拦截)"
            }

            res = await prober.check_domain("blocked-twitter.example", force_refresh=True)
            assert res["is_blocked"] is True
            assert res["block_type"] == "TCP_RST"

    asyncio.run(_run())

def test_dns_poisoning_detected():
    """Verify that known GFW poisoned IP is flagged as DNS_POISONED"""
    prober = GFWProber()

    async def _run():
        with patch.object(prober, "_resolve_domestic_dns", new_callable=AsyncMock) as mock_dom, \
             patch.object(prober, "_resolve_overseas_doh", new_callable=AsyncMock) as mock_overseas, \
             patch.object(prober, "_probe_tcp_tls", new_callable=AsyncMock) as mock_tls:

            mock_dom.return_value = {"243.185.187.39"}
            mock_overseas.return_value = {"142.250.190.46"}
            mock_tls.return_value = {"accessible": True, "latency_ms": 20, "error_type": None, "error": None}

            res = await prober.check_domain("poisoned.example", force_refresh=True)
            assert res["is_blocked"] is True
            assert res["block_type"] == "DNS_POISONED"

    asyncio.run(_run())
