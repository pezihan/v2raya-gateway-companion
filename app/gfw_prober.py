import asyncio
import socket
import ssl
import time
from typing import Dict, Optional, Set
import dns.resolver
import httpx
from app.config import settings

# Common GFW DNS Poisoned Bogon / Fake IPs
KNOWN_POISONED_IPS: Set[str] = {
    "127.0.0.1", "0.0.0.0", "10.10.34.34",
    "243.185.187.39", "37.61.54.158", "93.46.8.89", "59.24.3.173",
    "203.98.7.65", "8.7.198.45", "78.16.49.15", "159.106.121.75",
    "46.82.174.68", "202.106.1.2", "202.181.7.85", "216.234.179.13",
    "209.145.54.50", "49.2.123.56", "54.251.179.9", "69.63.187.12",
    "69.171.224.11", "74.125.127.102", "118.97.106.230", "128.121.126.139"
}

# Cache results for 300 seconds to prevent hammering
_probe_cache: Dict[str, Dict] = {}

class GFWProber:
    def __init__(self):
        self.domestic_dns = settings.DOMESTIC_DNS
        self.overseas_doh = settings.OVERSEAS_DOH
        self.timeout = settings.PROBE_TIMEOUT

    async def _resolve_domestic_dns(self, domain: str) -> Optional[Set[str]]:
        """Resolves A records via domestic DNS (223.5.5.5)"""
        loop = asyncio.get_running_loop()
        def _sync_resolve():
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.domestic_dns]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            try:
                answers = resolver.resolve(domain, 'A')
                return {str(rdata) for rdata in answers}
            except Exception:
                return set()
        return await loop.run_in_executor(None, _sync_resolve)

    async def _resolve_overseas_doh(self, domain: str) -> Optional[Set[str]]:
        """Resolves A records via Overseas DoH (Cloudflare 1.1.1.1 / Google)"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://1.1.1.1/dns-query",
                    params={"name": domain, "type": "A"},
                    headers={"accept": "application/dns-json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    return {ans["data"] for ans in answers if ans.get("type") == 1}
        except Exception:
            pass
        return set()

    async def _probe_tcp_port(self, ip: str, port: int) -> bool:
        """Helper to check if a specific TCP port is open and connectable"""
        loop = asyncio.get_running_loop()
        def _sync_port_check():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(min(self.timeout, 2.0))
                s.connect((ip, port))
                s.close()
                return True
            except Exception:
                return False
        return await loop.run_in_executor(None, _sync_port_check)

    async def _probe_tcp_tls(self, domain: str, target_ip: Optional[str] = None) -> Dict:
        """
        Attempts direct TCP connection & TLS ClientHello with SNI without proxy.
        Detects TCP RST (GFW characteristic) or connection timeout.
        Certificate mismatches / SSL alerts are NOT treated as GFW blocks.
        """
        loop = asyncio.get_running_loop()
        def _sync_tls_probe():
            start_time = time.time()
            ip = target_ip or domain
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, 443))
                
                # Wrap with TLS and send ClientHello with target SNI
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    elapsed = int((time.time() - start_time) * 1000)
                    return {
                        "accessible": True,
                        "latency_ms": elapsed,
                        "error_type": None,
                        "error": None
                    }
            except ConnectionResetError:
                return {
                    "accessible": False,
                    "error_type": "TCP_RST",
                    "error": "TCP 连接被重置 (GFW 典型 RST 拦截)"
                }
            except socket.timeout:
                return {
                    "accessible": False,
                    "error_type": "TIMEOUT",
                    "error": "TCP 443 连接超时 (疑似黑洞丢包)"
                }
            except ssl.SSLError as e:
                # IMPORTANT: If SSL error occurs after TCP connect, the server is reached!
                # Expired certs, self-signed certs, or SNI warnings are NOT GFW blocks.
                elapsed = int((time.time() - start_time) * 1000)
                return {
                    "accessible": True,
                    "latency_ms": elapsed,
                    "error_type": "SSL_WARNING",
                    "error": None,
                    "note": f"证书或TLS版本不匹配 ({str(e).split(':')[-1].strip()})，但主机网络可达"
                }
            except Exception as e:
                return {
                    "accessible": False,
                    "error_type": "CONN_FAILED",
                    "error": str(e)
                }
        return await loop.run_in_executor(None, _sync_tls_probe)

    async def check_domain(self, domain: str, force_refresh: bool = False) -> Dict:
        """
        Executes a comprehensive GFW blockage analysis:
        1. DNS Poisoning check (known poisoned bogons / private IPs)
        2. Direct TCP / TLS SNI probe (detects TCP RST)
        3. Port 80 fallback for HTTP-only sites to prevent timeout false positives
        """
        domain = domain.lower().strip()
        now = time.time()
        if not force_refresh and domain in _probe_cache:
            cache_entry = _probe_cache[domain]
            if now - cache_entry["timestamp"] < 300:
                return cache_entry["data"]

        # Run Domestic DNS & Overseas DoH in parallel
        dom_ips, overseas_ips = await asyncio.gather(
            self._resolve_domestic_dns(domain),
            self._resolve_overseas_doh(domain)
        )

        is_poisoned = False
        poison_reason = ""

        # Check if domestic DNS returned known poisoned IPs
        poisoned_intersection = dom_ips.intersection(KNOWN_POISONED_IPS)
        if poisoned_intersection:
            is_poisoned = True
            poison_reason = f"国内DNS返回典型投毒虚假IP: {', '.join(poisoned_intersection)}"
        else:
            # Check for bogon / private IPs returned for public domains
            for ip_str in dom_ips:
                try:
                    import ipaddress
                    parsed_ip = ipaddress.ip_address(ip_str)
                    if (parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_unspecified) and not domain.endswith((".local", ".lan", ".home.arpa")):
                        is_poisoned = True
                        poison_reason = f"国内DNS返回异常保留/私有IP: {ip_str}"
                        break
                except Exception:
                    pass

        # Probe TCP / TLS directly
        test_ip = list(overseas_ips)[0] if overseas_ips else (list(dom_ips)[0] if dom_ips else None)
        tls_result = await self._probe_tcp_tls(domain, test_ip)

        # Synthesis of blockage determination
        is_blocked = False
        block_type = "NONE"
        evidence_list = []

        if is_poisoned:
            is_blocked = True
            block_type = "DNS_POISONED"
            evidence_list.append(poison_reason)

        err_type = tls_result.get("error_type")
        if err_type == "TCP_RST":
            is_blocked = True
            block_type = "TCP_RST"
            evidence_list.append(tls_result.get("error"))
        elif err_type == "TIMEOUT":
            # If 443 timed out, check port 80 (HTTP) to see if site is just a non-HTTPS site
            if test_ip:
                http_accessible = await self._probe_tcp_port(test_ip, 80)
                if http_accessible:
                    # Site is reachable via port 80! NOT blocked by GFW!
                    tls_result["accessible"] = True
                    tls_result["latency_ms"] = tls_result.get("latency_ms") or 50
                    if not is_poisoned:
                        is_blocked = False
                else:
                    # Both 443 and 80 timed out
                    # Only mark as GFW TIMEOUT if overseas DoH succeeded, indicating it's an active overseas host
                    if overseas_ips and not is_poisoned:
                        is_blocked = True
                        block_type = "TIMEOUT"
                        evidence_list.append("国内直连超时 (80/443端口均无响应，疑似黑洞丢包)")
            else:
                if overseas_ips and not is_poisoned:
                    is_blocked = True
                    block_type = "TIMEOUT"
                    evidence_list.append("国内直连超时 (目标无响应)")
        elif tls_result.get("accessible"):
            if not is_poisoned:
                is_blocked = False

        summary_text = " | ".join(evidence_list) if evidence_list else (
            tls_result.get("note") or "国内直连畅通"
        )

        result = {
            "domain": domain,
            "is_blocked": is_blocked,
            "block_type": block_type,  # 'DNS_POISONED', 'TCP_RST', 'TIMEOUT', 'NONE'
            "summary": summary_text,
            "latency_ms": tls_result.get("latency_ms"),
            "domestic_ips": list(dom_ips),
            "overseas_ips": list(overseas_ips),
            "checked_at": int(now)
        }

        _probe_cache[domain] = {
            "timestamp": now,
            "data": result
        }

        return result

prober = GFWProber()
