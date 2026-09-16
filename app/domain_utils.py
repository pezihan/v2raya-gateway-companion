import re
from urllib.parse import urlparse
from typing import Tuple, Optional, Set, List, Dict

# Multi-part public suffixes commonly encountered
TWO_LEVEL_TLDS = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "bj.cn", "sh.cn",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.hk", "org.hk", "edu.hk", "idv.hk", "net.hk",
    "com.tw", "org.tw", "idv.tw", "club.tw", "net.tw",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "id.au",
    "co.nz", "net.nz", "org.nz", "geek.nz",
    "com.sg", "edu.sg", "org.sg", "net.sg",
    "com.my", "net.my", "org.my", "edu.my",
    "co.kr", "ne.kr", "or.kr", "re.kr",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in"
}

def extract_domain(input_text: str) -> Optional[str]:
    """
    Extracts a clean, lowercase hostname/domain from an arbitrary string,
    which could be a full URL, scheme+domain+port, or plain domain.
    """
    if not input_text:
        return None
    
    text = input_text.strip()
    if not text:
        return None
        
    # Remove leading/trailing quotes or markdown/brackets
    text = text.strip("'\"<>[]() \t\r\n")
    
    # If it starts with protocol or //, parse using urlparse
    if "://" in text or text.startswith("//"):
        try:
            parsed = urlparse(text if "://" in text else "http:" + text)
            hostname = parsed.hostname
            if hostname:
                return hostname.lower().strip(".")
        except Exception:
            pass
            
    # Handle domain:port or domain/path without protocol
    if "/" in text or ":" in text:
        try:
            parsed = urlparse("http://" + text)
            hostname = parsed.hostname
            if hostname:
                return hostname.lower().strip(".")
        except Exception:
            pass
            
    # Regex fallback to find standard domain pattern
    match = re.search(r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)
    if match:
        return match.group(0).lower().strip(".")
        
    return text.lower().strip(".")

def get_root_domain(domain: str) -> str:
    """
    Deduces the apex/root domain (TLD+1) for a given hostname.
    Example:
      'www.google.com' -> 'google.com'
      'api.sub.example.com.cn' -> 'example.com.cn'
      'telegram.org' -> 'telegram.org'
      '185.140.240.128' -> '185.140.240.128'
    """
    if not domain:
        return ""
    
    # Check if IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return domain
        
    parts = domain.lower().split('.')
    if len(parts) <= 2:
        return domain
        
    # Check for known 2-part TLD (e.g. .com.cn)
    potential_two_level = ".".join(parts[-2:])
    if potential_two_level in TWO_LEVEL_TLDS:
        if len(parts) >= 3:
            return ".".join(parts[-3:])
        return domain
        
    # Standard single-level TLD (e.g. .com, .org, .net, .io, .ai)
    return ".".join(parts[-2:])

def analyze_domain(input_text: str) -> Dict:
    """
    Analyzes an input string, extracts hostname, root domain,
    and returns metadata whether it is a subdomain and what root is recommended.
    """
    hostname = extract_domain(input_text)
    if not hostname:
        return {
            "success": False,
            "error": "无法识别出有效域名"
        }
        
    root_domain = get_root_domain(hostname)
    is_subdomain = (hostname != root_domain) and (not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))
    
    return {
        "success": True,
        "input": input_text,
        "hostname": hostname,
        "root_domain": root_domain,
        "is_subdomain": is_subdomain,
        "suggested_root": root_domain if is_subdomain else None
    }

def format_routinga_rule(
    target: str,
    action: str = "proxy",
    match_type: str = "domain",
    target_type: str = "domain"
) -> str:
    """
    Formats a target into a standard RoutingA line.
    Supports:
      - IP rules: ip(geoip:hk, geoip:mo) -> proxy, ip(91.108.4.0/22) -> proxy
      - GeoSite: domain(geosite:cn) -> direct
      - Ext DAT: domain(ext:"LoyalsoldierSite.dat:gfw") -> proxy
      - Domain types: domain(domain:google.com) -> proxy, domain(full:mail.qq.com) -> direct,
                      domain(keyword:google) -> proxy, domain(regexp:...) -> proxy
    """
    t = target.strip()
    act = action.strip().lower()
    t_lower = t.lower()

    # 1. IP rule types (target_type is ip, or starts with geoip:, or is an IP/CIDR)
    if target_type == "ip" or match_type in ["geoip", "cidr", "ip"] or t_lower.startswith("geoip:"):
        if t_lower.startswith("geoip:"):
            return f"ip({t}) -> {act}"
        clean_ip = t.strip('"\'')
        # IPv6 addresses in v2rayA RoutingA require double quotes because of colons
        if ":" in clean_ip:
            return f'ip("{clean_ip}") -> {act}'
        else:
            return f"ip({clean_ip}) -> {act}"

    # 2. GeoSite preset: domain(geosite:cn) -> direct
    if t_lower.startswith("geosite:"):
        return f"domain({t_lower}) -> {act}"

    # 3. External dat preset: domain(ext:"...") -> proxy
    if t_lower.startswith("ext:"):
        return f"domain({t}) -> {act}"

    # 4. Keyword / Regex / Full match types
    if match_type in ["full", "keyword", "regexp"]:
        clean_domain = t_lower.strip('"\'')
        return f"domain({match_type}:{clean_domain}) -> {act}"

    # 5. Default domain match
    if t_lower.startswith("domain:"):
        return f"domain({t_lower}) -> {act}"

    clean_domain = t_lower.strip('"\'')
    return f"domain(domain:{clean_domain}) -> {act}"

