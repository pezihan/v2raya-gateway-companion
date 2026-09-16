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


# ===============================================
# 自定义需要代理的域名
# ===============================================

# Telegram
domain(full:telegram.org) -> proxy
domain(domain:telegram.org) -> proxy
domain(full:web.telegram.org) -> proxy
domain(domain:web.telegram.org) -> proxy

# 其它自定义域名
domain(domain:91porna.com) -> proxy
domain(domain:www.pornhub.com) -> proxy
"""

def test_parse_rules(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"
    
    rules = mgr.parse_rules()
    assert len(rules) >= 7
    targets = [r["target"] for r in rules]
    assert "mail.qq.com" in targets
    assert "telegram.org" in targets
    assert "91porna.com" in targets

def test_is_domain_proxied(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"
    
    # telegram.org is domain: matched
    assert mgr.is_domain_proxied("telegram.org") is True
    assert mgr.is_domain_proxied("api.telegram.org") is True
    # mail.qq.com is direct, not proxied
    assert mgr.is_domain_proxied("mail.qq.com") is False
    # unknown domain
    assert mgr.is_domain_proxied("example.com") is False

def test_optimize_redundant_rules(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"
    
    # Should optimize out full:telegram.org and web.telegram.org because domain:telegram.org exists
    res = mgr.optimize_rules()
    assert res["success"] is True
    assert res["cleaned_count"] >= 1

def test_update_rule(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"
    
    # Update www.pornhub.com to pornhub.com
    res = mgr.update_rule(
        old_target="www.pornhub.com",
        new_target="pornhub.com",
        new_match_type="domain",
        new_action="proxy"
    )
    assert res is True
    
    updated_rules = mgr.parse_rules()
    targets = [r["target"] for r in updated_rules]
    assert "pornhub.com" in targets
    assert "www.pornhub.com" not in targets

def test_audit_and_auto_fix(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(SAMPLE_ROUTINGA, encoding="utf-8")
    
    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"
    
    # Check audit issues
    audit = mgr.audit_rules()
    assert audit["total_issues"] >= 2  # Has redundant full and www.pornhub.com
    
    # Execute auto fix
    fix_res = mgr.auto_fix_rules()
    assert fix_res["success"] is True
    assert fix_res["total_fixed"] >= 2
    
    # Verify fixed content
    fixed_rules = mgr.parse_rules()
    targets = [r["target"] for r in fixed_rules]
    assert "pornhub.com" in targets
    assert "www.pornhub.com" not in targets

def test_check_for_external_changes(tmp_path):
    import sqlite3
    import time

    db_file = tmp_path / "v2raya.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE configure (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO configure VALUES ('routingA', 'domain(domain:init.com) -> proxy')")
    conn.commit()
    conn.close()

    conf_file = tmp_path / "routinga.conf"
    mgr = V2RayAManager()
    mgr.db_path = str(db_file)
    mgr.backup_path = str(conf_file)
    mgr._get_candidate_paths = lambda: [str(db_file)]
    mgr._update_recorded_mtimes()
    mgr.get_raw_routinga()

    # Without external changes
    assert mgr.check_for_external_changes() is False

    # Simulate external change by v2rayA
    time.sleep(0.05)
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE configure SET value = 'domain(domain:updated-by-v2raya.com) -> proxy' WHERE key = 'routingA'")
    conn.commit()
    conn.close()

    # Should detect change and return True
    changed = mgr.check_for_external_changes()
    assert changed is True
    assert "updated-by-v2raya.com" in mgr.get_raw_routinga()

def test_geosite_and_geoip_parsing(tmp_path):
    sample = """
# =========================================================
# 中国大陆及私有地址直连
# =========================================================

domain(geosite:cn) -> direct
ip(geoip:private, geoip:cn) -> direct

# =========================================================
# 香港 / 澳门 IP
# =========================================================

ip(geoip:hk, geoip:mo) -> proxy

# =========================================================
# IP 网段与外部规则
# =========================================================

ip(91.108.4.0/22) -> proxy
domain(ext:"LoyalsoldierSite.dat:gfw") -> proxy
"""
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(sample, encoding="utf-8")

    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"

    rules = mgr.parse_rules()
    assert len(rules) == 5

    geosite_rule = next(r for r in rules if r["target"] == "geosite:cn")
    assert geosite_rule["rule_type"] == "geosite"
    assert geosite_rule["target_type"] == "domain"
    assert geosite_rule["action"] == "direct"
    assert geosite_rule["category"] == "中国大陆及私有地址直连"

    geoip_rule = next(r for r in rules if "geoip:hk" in r["target"])
    assert geoip_rule["rule_type"] == "geoip"
    assert geoip_rule["target_type"] == "ip"
    assert geoip_rule["action"] == "proxy"
    assert geoip_rule["category"] == "香港 / 澳门 IP"

    ip_rule = next(r for r in rules if "91.108.4.0/22" in r["target"])
    assert ip_rule["rule_type"] == "ip"
    assert ip_rule["match_type"] == "cidr"
    assert ip_rule["target_type"] == "ip"

    ext_rule = next(r for r in rules if "LoyalsoldierSite.dat:gfw" in r["target"])
    assert ext_rule["rule_type"] == "ext"
    assert ext_rule["target_type"] == "domain"

def test_add_and_update_with_category(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text("default: direct\n", encoding="utf-8")

    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"

    # Add geosite rule under new category
    mgr.add_rule(target="geosite:google", action="proxy", match_type="geosite", target_type="domain", category="Google 预设")
    rules = mgr.parse_rules()
    assert any(r["target"] == "geosite:google" and r["category"] == "Google 预设" for r in rules)

    # Move to another category
    mgr.update_rule(
        old_target="geosite:google",
        new_target="geosite:google",
        new_match_type="geosite",
        new_action="proxy",
        new_category="常用海外网站",
        target_type="domain"
    )
    rules2 = mgr.parse_rules()
    updated = next(r for r in rules2 if r["target"] == "geosite:google")
    assert updated["category"] == "常用海外网站"

def test_user_full_config_support(tmp_path):
    user_conf = """# =========================================================
# 默认规则
# =========================================================

default: direct


# =========================================================
# 强制直连
# =========================================================

domain(full:mail.qq.com) -> direct


# =========================================================
# 自定义需要代理的域名
# =========================================================

# Telegram
domain(full:telegram.org) -> proxy
domain(domain:telegram.org) -> proxy
domain(full:web.telegram.org) -> proxy
domain(domain:web.telegram.org) -> proxy
domain(full:telegram.me) -> proxy
domain(domain:telegram.me) -> proxy
domain(full:t.me) -> proxy
domain(domain:t.me) -> proxy
domain(full:telegram.dog) -> proxy

# 其他自定义域名
domain(domain:gpt.eacase.de5.net) -> proxy
domain(domain:api.x.com) -> proxy
domain(domain:x.com) -> proxy
domain(domain:twitter.com) -> proxy
domain(domain:twimg.com) -> proxy
domain(domain:t.co) -> proxy
domain(domain:pornhub.com) -> proxy
domain(domain:phncdn.com) -> proxy
domain(domain:jable.tv) -> proxy
domain(domain:google.com) -> proxy
domain(domain:youtube.com) -> proxy
domain(domain:googlevideo.com) -> proxy
domain(domain:ytimg.com) -> proxy
domain(domain:ggpht.com) -> proxy
domain(domain:github.com) -> proxy
domain(domain:githubassets.com) -> proxy
domain(domain:githubusercontent.com) -> proxy
domain(domain:openai.com) -> proxy
domain(domain:chatgpt.com) -> proxy
domain(domain:oaistatic.com) -> proxy
domain(domain:oaiusercontent.com) -> proxy
domain(domain:anthropic.com) -> proxy
domain(domain:claude.ai) -> proxy

# Telegram IP段
ip(91.108.4.0/22) -> proxy
ip(91.108.8.0/22) -> proxy
ip(91.108.12.0/22) -> proxy
ip(91.108.16.0/22) -> proxy
ip(91.108.20.0/22) -> proxy
ip(91.108.56.0/22) -> proxy
ip(149.154.160.0/20) -> proxy
ip(149.154.164.0/22) -> proxy
ip(149.154.168.0/22) -> proxy
ip(149.154.172.0/22) -> proxy
ip("2001:b28:f23c::/48") -> proxy
ip("2a0a:f280::/32") -> proxy
ip("2001:67c:4e8::/48") -> proxy

# GFWList
domain(ext:"LoyalsoldierSite.dat:gfw") -> proxy

# 常用被墙网站分类
domain(geosite:google) -> proxy
domain(geosite:github) -> proxy
domain(geosite:telegram) -> proxy
domain(geosite:twitter) -> proxy
domain(geosite:gfw) -> proxy

# 境外常用直连
ip(geoip:hk, geoip:mo) -> proxy

# 保证国内直连
domain(geosite:cn) -> direct
ip(geoip:private, geoip:cn) -> direct
"""
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text(user_conf, encoding="utf-8")

    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"

    rules = mgr.parse_rules()
    assert len(rules) == 56

    # Verify IPv6 parsing cleans quotes for UI presentation
    v6_rule = next(r for r in rules if "2001:b28:f23c::/48" in r["target"])
    assert v6_rule["target"] == "2001:b28:f23c::/48"
    assert v6_rule["rule_type"] == "ip"
    assert v6_rule["match_type"] == "cidr"
    assert v6_rule["target_type"] == "ip"

    # Verify IPv4 CIDR
    v4_rule = next(r for r in rules if r["target"] == "91.108.4.0/22")
    assert v4_rule["rule_type"] == "ip"
    assert v4_rule["match_type"] == "cidr"

    # Verify updating IPv6 rule properly wraps in quotes in saved RoutingA
    mgr.update_rule(
        old_target="2001:b28:f23c::/48",
        new_target="2001:b28:f23c::/48",
        new_match_type="cidr",
        new_action="direct",
        target_type="ip"
    )
    raw_after = mgr.get_raw_routinga()
    assert 'ip("2001:b28:f23c::/48") -> direct' in raw_after

    # Verify deleting specific rule with match_type (full vs domain)
    mgr.delete_rule(target="telegram.org", match_type="full", action="proxy")
    raw_after_del = mgr.get_raw_routinga()
    assert "domain(full:telegram.org) -> proxy" not in raw_after_del
    assert "domain(domain:telegram.org) -> proxy" in raw_after_del

def test_category_sections_and_reordering(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text("""# =========================================================
# 默认规则
# =========================================================
default: direct

# =========================================================
# 中国大陆及私有地址直连
# =========================================================
domain(geosite:cn) -> direct

# =========================================================
# 自定义代理
# =========================================================
domain(domain:ip138.com) -> proxy
""", encoding="utf-8")

    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"

    # 1. Test get_ordered_categories
    cats = mgr.get_ordered_categories()
    assert cats == ["中国大陆及私有地址直连", "自定义代理"]

    # 2. Test reorder_categories: Move '自定义代理' to the very top (right below default: direct)
    success = mgr.reorder_categories(["自定义代理", "中国大陆及私有地址直连"])
    assert success is True

    # 3. Verify in raw file that '自定义代理' is now physically before '中国大陆及私有地址直连'
    raw = mgr.get_raw_routinga()
    idx_proxy = raw.find("自定义代理")
    idx_direct = raw.find("中国大陆及私有地址直连")
    assert idx_proxy < idx_direct
    assert "default: direct" in raw

    # 4. Verify ordered categories now reflects the new order
    new_cats = mgr.get_ordered_categories()
    assert new_cats == ["自定义代理", "中国大陆及私有地址直连"]

    # 5. Verify rules parsed respect the category
    rules = mgr.parse_rules()
    ip138_rule = next(r for r in rules if r["target"] == "ip138.com")
    assert ip138_rule["category"] == "自定义代理"
    assert ip138_rule["action"] == "proxy"

def test_update_rule_move_to_new_category_and_deduplication(tmp_path):
    conf_file = tmp_path / "routinga.conf"
    conf_file.write_text("""# =========================================================
# 默认规则
# =========================================================
default: direct

# =========================================================
# 自定义需要代理的域名
# =========================================================
# Telegram
domain(domain:telegram.org) -> proxy

# =========================================================
# 自定义代理
# =========================================================
domain(domain:ip138.com) -> proxy
""", encoding="utf-8")

    mgr = V2RayAManager()
    mgr.backup_path = str(conf_file)
    mgr.db_path = "/nonexistent/path/db.sqlite"

    # 1. Update telegram.org and move to brand new category 'Telegram'
    success = mgr.update_rule(
        old_target="telegram.org",
        new_target="telegram.org",
        new_match_type="domain",
        new_action="proxy",
        new_category="Telegram",
        target_type="domain"
    )
    assert success is True
    raw = mgr.get_raw_routinga()
    assert "# Telegram" in raw
    
    rules = mgr.parse_rules()
    tg_rule = next(r for r in rules if r["target"] == "telegram.org")
    assert tg_rule["category"] == "Telegram"

    # 2. Update ip138.com to ip1138.com and ensure NO duplicates
    success = mgr.update_rule(
        old_target="ip138.com",
        new_target="ip1138.com",
        new_match_type="domain",
        new_action="proxy",
        new_category="自定义代理",
        target_type="domain"
    )
    assert success is True

    # 3. Simulate repeated click (same update request)
    success2 = mgr.update_rule(
        old_target="ip138.com",
        new_target="ip1138.com",
        new_match_type="domain",
        new_action="proxy",
        new_category="自定义代理",
        target_type="domain"
    )
    assert success2 is True

    # Verify ip1138.com appears EXACTLY ONCE
    rules = mgr.parse_rules()
    matches = [r for r in rules if r["target"] == "ip1138.com"]
    assert len(matches) == 1
    assert not any(r["target"] == "ip138.com" for r in rules)




