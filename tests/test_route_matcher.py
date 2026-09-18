import pytest
from app.v2raya_manager import V2RayAManager

SAMPLE_ROUTINGA = """# ===============================================
# 默认规则
# ===============================================
default: direct

# ===============================================
# 强制直连
# ===============================================
domain(full:mail.qq.com) -> direct
domain(domain:baidu.com) -> direct

# ===============================================
# 自定义代理
# ===============================================
domain(domain:telegram.org) -> proxy
domain(keyword:twitter) -> proxy
domain(regexp:.*\\.youtube\\.com) -> proxy
"""

def test_get_domain_route_action_matching(tmp_path, monkeypatch):
    test_file = tmp_path / "routinga.conf"
    test_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(test_file)
    mgr.db_path = "/nonexistent/path.db"

    # 1. Full match
    assert mgr.get_domain_route_action("mail.qq.com") == "direct"
    assert mgr.get_domain_route_action("other.mail.qq.com") == "direct"  # Falls back to default: direct

    # 2. Domain match (and subdomains)
    assert mgr.get_domain_route_action("telegram.org") == "proxy"
    assert mgr.get_domain_route_action("web.telegram.org") == "proxy"
    assert mgr.get_domain_route_action("api.sub.telegram.org") == "proxy"
    assert mgr.get_domain_route_action("baidu.com") == "direct"
    assert mgr.get_domain_route_action("tieba.baidu.com") == "direct"

    # 3. Keyword match
    assert mgr.get_domain_route_action("mobile.twitter.com") == "proxy"
    assert mgr.get_domain_route_action("api-twitter-service.net") == "proxy"

    # 4. Regexp match
    assert mgr.get_domain_route_action("www.youtube.com") == "proxy"
    assert mgr.get_domain_route_action("music.youtube.com") == "proxy"

    # 5. Default fallback
    assert mgr.get_domain_route_action("randomunregistereddomain.cn") == "direct"
    assert mgr.is_domain_proxied("randomunregistereddomain.cn") is False
    assert mgr.is_domain_proxied("telegram.org") is True

def test_default_proxy_policy(tmp_path):
    proxy_default_conf = """default: proxy
domain(domain:qq.com) -> direct
"""
    test_file = tmp_path / "routinga_proxy.conf"
    test_file.write_text(proxy_default_conf, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(test_file)
    mgr.db_path = "/nonexistent/path.db"

    assert mgr.get_domain_route_action("qq.com") == "direct"
    assert mgr.get_domain_route_action("unknown-site.org") == "proxy"
    assert mgr.is_domain_proxied("unknown-site.org") is True

def test_parse_xray_access_log_line():
    mgr = V2RayAManager()
    
    line1 = "2026/09/18 10:20:15 192.168.1.50:54321 accepted tcp:api.github.com:443 [proxy]"
    parsed1 = mgr.parse_xray_access_log_line(line1)
    assert parsed1 is not None
    assert parsed1["client_ip"] == "192.168.1.50"
    assert parsed1["client_port"] == 54321
    assert parsed1["destination"] == "api.github.com"
    assert parsed1["port"] == 443
    assert parsed1["outbound"] == "proxy"

    line2 = "192.168.1.88:12345 accepted tcp:www.baidu.com:80 [direct]"
    parsed2 = mgr.parse_xray_access_log_line(line2)
    assert parsed2 is not None
    assert parsed2["client_ip"] == "192.168.1.88"
    assert parsed2["destination"] == "www.baidu.com"
    assert parsed2["port"] == 80
    assert parsed2["outbound"] == "direct"

    # Invalid line
    assert mgr.parse_xray_access_log_line("INFO[0001] some log line without format") is None
