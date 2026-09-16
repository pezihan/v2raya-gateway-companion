import asyncio
import time
import re
from typing import Optional, Dict, List, Set
from app.gfw_prober import prober
from app.v2raya_manager import v2raya_manager
from app.domain_utils import get_root_domain

# Helper to parse TLS SNI from raw TCP payload
def extract_tls_sni(payload: bytes) -> Optional[str]:
    try:
        if len(payload) < 44:
            return None
        # TLS Handshake (0x16), Version (0x03, 0x01/02/03)
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
        # Handshake Type 1 (ClientHello)
        if payload[5] != 0x01:
            return None

        # Skip record header (5) + handshake header (4) + client_version (2) + random (32) = 43
        pos = 43
        # Session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        # Cipher Suites
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_len
        # Compression methods
        comp_len = payload[pos]
        pos += 1 + comp_len
        # Extensions Length
        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        ext_end = pos + ext_len

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_size = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0:  # server_name extension
                # SNI list length (2 bytes) + type (1 byte: 0 for host_name) + length (2 bytes)
                if pos + 5 <= len(payload) and payload[pos+2] == 0:
                    sni_length = int.from_bytes(payload[pos+3:pos+5], 'big')
                    sni = payload[pos+5:pos+5+sni_length].decode('utf-8', errors='ignore')
                    return sni.lower()
            pos += ext_size
    except Exception:
        pass
    return None

class GatewayTrafficSniffer:
    def __init__(self):
        self.is_running = False
        self.target_ip: Optional[str] = None
        self.start_time: Optional[float] = None
        self.duration_seconds: int = 0
        self._task: Optional[asyncio.Task] = None
        self._recent_domains: Dict[str, float] = {} # domain -> last_checked_ts
        self.detected_alerts: List[Dict] = []
        self.broadcast_callback = None
        self._sniffer_thread = None

    def set_broadcast_callback(self, callback):
        self.broadcast_callback = callback

    async def _emit_alert(self, alert: Dict):
        self.detected_alerts.insert(0, alert)
        if len(self.detected_alerts) > 200:
            self.detected_alerts.pop()
        if self.broadcast_callback:
            try:
                await self.broadcast_callback(alert)
            except Exception:
                pass

    async def handle_observed_domain(self, domain: str, target_ip: str):
        domain = domain.lower().strip(".")
        if not domain or len(domain) < 3 or "." not in domain:
            return

        now = time.time()
        # Cooldown check: ignore if probed within last 30s
        if domain in self._recent_domains and (now - self._recent_domains[domain] < 30):
            return
        self._recent_domains[domain] = now

        # Step 1: Check if already routed via proxy in v2rayA
        if v2raya_manager.is_domain_proxied(domain):
            # Already unblocked and routed through proxy -> ignore completely!
            return

        # Step 2: Probe GFW blockage
        probe_res = await prober.check_domain(domain)
        if probe_res.get("is_blocked"):
            root = get_root_domain(domain)
            is_sub = (root != domain)
            
            alert = {
                "id": f"{int(now * 1000)}_{abs(hash(domain)) % 10000}",
                "timestamp": int(now),
                "target_ip": target_ip,
                "domain": domain,
                "root_domain": root,
                "is_subdomain": is_sub,
                "suggested_root": root if is_sub else None,
                "block_type": probe_res.get("block_type"),
                "reason": probe_res.get("summary"),
                "domestic_ips": probe_res.get("domestic_ips", []),
                "overseas_ips": probe_res.get("overseas_ips", []),
                "already_in_rules": False
            }
            await self._emit_alert(alert)

    def start(self, target_ip: str, duration_seconds: int = 0) -> Dict:
        if self.is_running:
            self.stop()

        self.target_ip = target_ip.strip()
        self.duration_seconds = duration_seconds
        self.start_time = time.time()
        self.is_running = True

        # Start packet sniffer in background
        loop = asyncio.get_event_loop()
        
        def _run_scapy_sniffer():
            try:
                from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Raw
                
                bpf_filter = f"src host {self.target_ip} and (udp port 53 or tcp port 80 or tcp port 443)"
                
                def _packet_callback(pkt):
                    if not self.is_running:
                        return
                    try:
                        extracted_domain = None
                        # Check DNS
                        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            extracted_domain = qname
                        # Check TLS SNI or HTTP Host
                        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load)
                            dport = pkt[TCP].dport
                            if dport == 443:
                                sni = extract_tls_sni(payload)
                                if sni:
                                    extracted_domain = sni
                            elif dport == 80:
                                match = re.search(b'Host:\\s*([a-zA-Z0-9.-]+)', payload, re.IGNORECASE)
                                if match:
                                    extracted_domain = match.group(1).decode('utf-8', errors='ignore')

                        if extracted_domain:
                            asyncio.run_coroutine_threadsafe(
                                self.handle_observed_domain(extracted_domain, self.target_ip),
                                loop
                            )
                    except Exception:
                        pass

                sniff(filter=bpf_filter, prn=_packet_callback, store=0, stop_filter=lambda p: not self.is_running)
            except Exception as e:
                print(f"[Sniffer Error] Scapy sniffing stopped or failed: {e}")

        import threading
        self._sniffer_thread = threading.Thread(target=_run_scapy_sniffer, daemon=True)
        self._sniffer_thread.start()

        return {
            "success": True,
            "target_ip": self.target_ip,
            "duration_seconds": self.duration_seconds,
            "status": "running"
        }

    def stop(self) -> Dict:
        self.is_running = False
        self.target_ip = None
        self.start_time = None
        return {
            "success": True,
            "status": "stopped"
        }

    def get_status(self) -> Dict:
        elapsed = 0
        if self.is_running and self.start_time:
            elapsed = int(time.time() - self.start_time)
            # Auto-stop if duration specified
            if self.duration_seconds > 0 and elapsed >= self.duration_seconds:
                self.stop()

        return {
            "is_running": self.is_running,
            "target_ip": self.target_ip,
            "elapsed_seconds": elapsed,
            "duration_seconds": self.duration_seconds,
            "detected_count": len(self.detected_alerts)
        }

sniffer = GatewayTrafficSniffer()
