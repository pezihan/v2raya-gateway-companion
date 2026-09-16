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
