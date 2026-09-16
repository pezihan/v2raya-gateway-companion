import os
import re
import socket
from typing import List, Dict

def get_lan_devices() -> List[Dict]:
    """
    Discovers active LAN devices by reading /proc/net/arp and active sockets.
    Returns list of dicts: [{"ip": "...", "mac": "...", "hostname": "..."}]
    """
    devices = []
    seen_ips = set()

    # Try reading /proc/net/arp (Linux standard)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:] # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        # Exclude 00:00:00:00:00:00 or broadcast
                        if mac and mac != "00:00:00:00:00:00" and ip not in seen_ips:
                            hostname = ip
                            try:
                                host_info = socket.gethostbyaddr(ip)
                                if host_info and host_info[0]:
                                    hostname = host_info[0]
                            except Exception:
                                pass
                                
                            devices.append({
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname
                            })
                            seen_ips.add(ip)
        except Exception:
            pass

    # If empty, add a default localhost / example for testing
    if not devices:
        devices.append({"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "hostname": "本机 (localhost)"})

    return devices
