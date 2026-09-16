import pytest
from app.domain_utils import extract_domain, get_root_domain, analyze_domain, format_routinga_rule

def test_extract_domain():
    assert extract_domain("https://www.google.com/search?q=test") == "www.google.com"
    assert extract_domain("http://api.telegram.org:8443/bot123") == "api.telegram.org"
    assert extract_domain("https://sub.domain.co.uk/path") == "sub.domain.co.uk"
    assert extract_domain("mail.qq.com") == "mail.qq.com"
    assert extract_domain("pornhub.com/view_video") == "pornhub.com"

def test_get_root_domain():
    assert get_root_domain("www.google.com") == "google.com"
    assert get_root_domain("google.com") == "google.com"
    assert get_root_domain("api.sub.example.com.cn") == "example.com.cn"
    assert get_root_domain("blog.developer.co.uk") == "developer.co.uk"
    assert get_root_domain("185.140.240.128") == "185.140.240.128"

def test_analyze_domain():
    res = analyze_domain("https://www.google.com/test")
    assert res["success"] is True
    assert res["hostname"] == "www.google.com"
    assert res["root_domain"] == "google.com"
    assert res["is_subdomain"] is True
    assert res["suggested_root"] == "google.com"

    res2 = analyze_domain("telegram.org")
    assert res2["is_subdomain"] is False
    assert res2["suggested_root"] is None

def test_format_routinga_rule():
    assert format_routinga_rule("google.com", "proxy", "domain") == "domain(domain:google.com) -> proxy"
    assert format_routinga_rule("mail.qq.com", "direct", "full") == "domain(full:mail.qq.com) -> direct"
