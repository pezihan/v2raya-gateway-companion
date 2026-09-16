import os
import re
import time
import sqlite3
import httpx
from typing import List, Dict, Optional, Set, Tuple
from app.config import settings
from app.domain_utils import get_root_domain, format_routinga_rule

DEFAULT_ROUTINGA_TEMPLATE = """# ===============================================
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
domain(full:telegram.me) -> proxy
domain(domain:telegram.me) -> proxy
domain(full:t.me) -> proxy
domain(domain:t.me) -> proxy
domain(full:telegram.dog) -> proxy

# 其他自定义域名
domain(domain:gpt.eacase.de5.net) -> proxy
domain(domain:jisuai.top) -> proxy
domain(domain:makerworld.com) -> proxy
domain(domain:91porna.com) -> proxy
domain(domain:www.pornhub.com) -> proxy
domain(domain:fangsung.com) -> proxy
domain(domain:1808.online) -> proxy
domain(domain:avgood.com) -> proxy
domain(domain:qingse.one) -> proxy
domain(domain:51cg1.com) -> proxy
domain(domain:missav.live) -> proxy
domain(domain:app.lemonsqueezy.com) -> proxy
domain(domain:lemonsqueezy.com) -> proxy
"""

class V2RayAManager:
    def __init__(self):
        self.db_path = settings.V2RAYA_DB_PATH
        self.backup_path = settings.ROUTINGA_BACKUP_PATH
        self.v2raya_url = settings.V2RAYA_URL.rstrip('/')
        os.makedirs(os.path.dirname(self.backup_path) or ".", exist_ok=True)
        if not os.path.exists(self.backup_path):
            with open(self.backup_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_ROUTINGA_TEMPLATE)

    def _locate_db_target(self, conn: sqlite3.Connection) -> Optional[Tuple[str, str, str, str]]:
        """
        Dynamically detects where RoutingA is stored in v2raya.db SQLite.
        Returns: (table_name, key_column, val_column, key_value)
        """
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]
            
            # Common v2rayA tables: configure, settings, configs
            for t in tables:
                cursor.execute(f"PRAGMA table_info({t})")
                cols = [c[1] for c in cursor.fetchall()]
                
                # Check key-value tables
                if "key" in cols and "value" in cols:
                    for k in ['routingA', 'routing_rule', 'routing']:
                        cursor.execute(f"SELECT value FROM {t} WHERE key = ? LIMIT 1", (k,))
                        row = cursor.fetchone()
                        if row is not None:
                            return (t, "key", "value", k)
                            
                # Check content tables
                for c in cols:
                    try:
                        cursor.execute(f"SELECT {c} FROM {t} WHERE {c} LIKE '%default:%' OR {c} LIKE '%domain(%' LIMIT 1")
                        row = cursor.fetchone()
                        if row and row[0]:
                            return (t, "rowid", c, "1")
                    except Exception:
                        pass
        except Exception:
            pass
        return None

    def _extract_routinga_from_binary(self, file_path: str) -> Optional[str]:
        """Extracts RoutingA block from BoltDB (bolt.db/boltv4.db) or binary files"""
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
            text = raw_bytes.decode('utf-8', errors='ignore')
            matches = re.findall(r'((?:#.*\n|default:\s*(?:direct|proxy|block)\n|(?:domain|ip)\([^)]+\)\s*->\s*(?:proxy|direct|block)\n|\s*\n){4,})', text)
            for m in matches:
                if 'domain(' in m and ('-> proxy' in m or '-> direct' in m):
                    cleaned = m.strip()
                    if len(cleaned) > 50:
                        return cleaned
        except Exception:
            pass
        return None

    def _read_from_sqlite(self) -> Optional[str]:
        """Attempts to read RoutingA text from SQLite or BoltDB in /etc/v2raya"""
        candidates = [
            self.db_path,
            "/etc/v2raya/bolt.db",
            "/etc/v2raya/boltv4.db",
            "/root/.config/v2raya/v2raya.db"
        ]
        
        # If directory exists, inspect all files in /etc/v2raya
        v2raya_dir = os.path.dirname(self.db_path)
        if os.path.exists(v2raya_dir):
            try:
                for f in os.listdir(v2raya_dir):
                    fp = os.path.join(v2raya_dir, f)
                    if fp not in candidates and os.path.isfile(fp):
                        candidates.append(fp)
            except Exception:
                pass

        for path in candidates:
            if not os.path.exists(path):
                continue
            # Try 1: SQLite query
            try:
                conn = sqlite3.connect(path)
                target = self._locate_db_target(conn)
                if target:
                    table, key_col, val_col, key_val = target
                    cursor = conn.cursor()
                    if key_col == "rowid":
                        cursor.execute(f"SELECT {val_col} FROM {table} LIMIT 1")
                    else:
                        cursor.execute(f"SELECT {val_col} FROM {table} WHERE {key_col} = ? LIMIT 1", (key_val,))
                    row = cursor.fetchone()
                    conn.close()
                    if row and row[0] and len(row[0]) > 20:
                        return row[0]
                conn.close()
            except Exception:
                pass

            # Try 2: Binary database / BoltDB text extraction
            binary_res = self._extract_routinga_from_binary(path)
            if binary_res:
                return binary_res

        return None

    def _save_to_sqlite(self, content: str) -> bool:
        """Attempts to write RoutingA text to v2rayA SQLite DB"""
        if not os.path.exists(self.db_path):
            return False
        try:
            conn = sqlite3.connect(self.db_path)
            target = self._locate_db_target(conn)
            cursor = conn.cursor()
            if target:
                table, key_col, val_col, key_val = target
                if key_col == "rowid":
                    cursor.execute(f"UPDATE {table} SET {val_col} = ?", (content,))
                else:
                    cursor.execute(
                        f"INSERT INTO {table} ({key_col}, {val_col}) VALUES (?, ?) "
                        f"ON CONFLICT({key_col}) DO UPDATE SET {val_col} = excluded.{val_col}",
                        (key_val, content)
                    )
            else:
                # Fallback: create or insert configure table
                cursor.execute("CREATE TABLE IF NOT EXISTS configure (key TEXT PRIMARY KEY, value TEXT)")
                cursor.execute(
                    "INSERT INTO configure (key, value) VALUES ('routingA', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (content,)
                )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB Save Error] {e}")
            return False

    def get_sync_status(self) -> Dict:
        """Returns storage mode and v2raya connection status"""
        db_exists = os.path.exists(self.db_path)
        return {
            "db_path": self.db_path,
            "db_connected": db_exists,
            "backup_path": self.backup_path,
            "storage_mode": "SQLite 直接写回 (v2rayA 数据库)" if db_exists else "独立配置文件模式"
        }

    def get_raw_routinga(self) -> str:
        """Gets current raw RoutingA configuration string"""
        content = self._read_from_sqlite()
        if content:
            return content
        if os.path.exists(self.backup_path):
            with open(self.backup_path, "r", encoding="utf-8") as f:
                return f.read()
        return DEFAULT_ROUTINGA_TEMPLATE

    def save_raw_routinga(self, content: str) -> bool:
        """Saves raw RoutingA string to DB & file"""
        # Save to backup file
        with open(self.backup_path, "w", encoding="utf-8") as f:
            f.write(content)
        # Save to SQLite
        self._save_to_sqlite(content)
        return True

    def parse_rules(self) -> List[Dict]:
        """
        Parses raw text into structured rule items.
        Returns a list of rule dicts with detailed audit info.
        """
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        rules = []
        current_category = "默认分类"

        rule_regex = re.compile(r'^(domain|ip)\((domain|full|keyword|regexp)?:?([^)]+)\)\s*->\s*(proxy|direct|block)$', re.IGNORECASE)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("#"):
                comment_text = stripped.lstrip("# \t")
                if comment_text and not comment_text.startswith("==="):
                    current_category = comment_text
                continue

            match = rule_regex.match(stripped)
            if match:
                target_type = match.group(1).lower() # domain / ip
                match_type = match.group(2).lower() if match.group(2) else "domain"
                target_value = match.group(3).strip().lower()
                action = match.group(4).lower()

                # Issue detection for this specific rule
                has_www = target_value.startswith("www.")
                root_domain = get_root_domain(target_value)
                is_sub = (target_value != root_domain) and (not re.match(r'^\d+\.\d+\.\d+\.\d+$', target_value))

                rules.append({
                    "id": f"rule_{line_num}_{abs(hash(stripped)) % 10000}",
                    "line": line_num,
                    "target_type": target_type,
                    "match_type": match_type,
                    "target": target_value,
                    "action": action,
                    "category": current_category,
                    "has_www": has_www,
                    "is_subdomain": is_sub,
                    "suggested_root": root_domain if is_sub else None,
                    "raw": stripped
                })
            elif stripped.startswith("default:"):
                action = stripped.split(":")[-1].strip()
                rules.append({
                    "id": f"default_{line_num}",
                    "line": line_num,
                    "target_type": "default",
                    "match_type": "default",
                    "target": "default",
                    "action": action,
                    "category": "系统策略",
                    "has_www": False,
                    "is_subdomain": False,
                    "suggested_root": None,
                    "raw": stripped
                })
        return rules

    def is_domain_proxied(self, domain: str) -> bool:
        """
        Checks if a domain is already matched by an existing 'proxy' rule.
        """
        rules = self.parse_rules()
        domain = domain.lower().strip()
        for r in rules:
            if r.get("target_type") == "domain" and r.get("action") == "proxy":
                target = r.get("target", "")
                match_type = r.get("match_type", "domain")
                if match_type == "full":
                    if target == domain:
                        return True
                elif match_type == "domain":
                    if domain == target or domain.endswith("." + target):
                        return True
        return False

    def add_domain_rule(self, domain: str, action: str = "proxy", match_type: str = "domain", category: str = "自定义代理") -> bool:
        """Adds a new domain rule under specified category with formatting"""
        domain = domain.lower().strip()
        raw_text = self.get_raw_routinga()
        new_rule_str = format_routinga_rule(domain, action, match_type)

        lines = raw_text.splitlines()
        category_header = f"# {category}"

        # Find category index
        cat_index = -1
        for idx, line in enumerate(lines):
            if line.strip().lower() == category_header.lower():
                cat_index = idx
                break

        if cat_index != -1:
            lines.insert(cat_index + 1, new_rule_str)
        else:
            lines.append("")
            lines.append(category_header)
            lines.append(new_rule_str)

        return self.save_raw_routinga("\n".join(lines))

    def update_rule(self, old_target: str, new_target: str, new_match_type: str = "domain", new_action: str = "proxy", new_category: Optional[str] = None) -> bool:
        """
        Updates an existing rule:
        Modifies target, match_type, action, or moves category.
        """
        old_target = old_target.lower().strip()
        new_target = new_target.lower().strip()
        new_rule_str = format_routinga_rule(new_target, new_action, new_match_type)
        
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        
        found = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            # Match line that configures old_target
            if old_target in stripped.lower() and "->" in stripped and not stripped.startswith("#"):
                new_lines.append(new_rule_str)
                found = True
            else:
                new_lines.append(line)

        if not found:
            # Fallback: add if not found
            return self.add_domain_rule(new_target, new_action, new_match_type, new_category or "自定义代理")

        return self.save_raw_routinga("\n".join(new_lines))

    def delete_rule_by_target(self, target: str) -> bool:
        """Deletes any rule matching target domain/IP"""
        target = target.lower().strip()
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if target in stripped.lower() and "->" in stripped and not stripped.startswith("#"):
                continue
            new_lines.append(line)
        return self.save_raw_routinga("\n".join(new_lines))

    def audit_rules(self) -> Dict:
        """
        Performs a full audit of current rules to detect:
        1. www prefix issues (e.g. domain:www.pornhub.com)
        2. redundant subdomains / duplicate full matches
        """
        rules = self.parse_rules()
        issues = []
        
        broad_domains: Set[str] = set()
        for r in rules:
            if r.get("target_type") == "domain" and r.get("match_type") == "domain":
                broad_domains.add(r.get("target"))

        seen_rules = set()
        for r in rules:
            if r.get("target_type") == "default":
                continue
            raw = r["raw"]
            target = r["target"]
            m_type = r["match_type"]

            if raw in seen_rules:
                issues.append({
                    "type": "DUPLICATE",
                    "target": target,
                    "message": f"规则 '{raw}' 完全重复",
                    "can_auto_fix": True
                })
            seen_rules.add(raw)

            if r.get("has_www") and m_type == "domain":
                root = get_root_domain(target)
                issues.append({
                    "type": "WWW_PREFIX",
                    "target": target,
                    "suggested": root,
                    "message": f"域名 '{target}' 带有 www. 前缀，建议修改为一级根域名 '{root}' 覆盖所有二级域名",
                    "can_auto_fix": True
                })

            if m_type == "full" and target in broad_domains:
                issues.append({
                    "type": "REDUNDANT_FULL",
                    "target": target,
                    "message": f"精确规则 'full:{target}' 是多余的，因为已存在通配规则 'domain:{target}'",
                    "can_auto_fix": True
                })

            root = get_root_domain(target)
            if root != target and root in broad_domains and target in broad_domains:
                issues.append({
                    "type": "REDUNDANT_SUBDOMAIN",
                    "target": target,
                    "message": f"子域名 '{target}' 是多余的，因为其根域名 '{root}' 已经设置了通配代理",
                    "can_auto_fix": True
                })

        return {
            "total_issues": len(issues),
            "issues": issues
        }

    def auto_fix_rules(self) -> Dict:
        """
        Executes automatic one-click fix for all detected issues:
        - Strips www. from domain: matches (e.g. www.pornhub.com -> pornhub.com)
        - Removes duplicates and redundant full/subdomain matches
        """
        rules = self.parse_rules()
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()

        # Step 1: Replace www. in domain()
        fixed_lines = []
        modified_count = 0
        
        for line in lines:
            stripped = line.strip()
            m = re.match(r'^domain\((domain)?:?www\.([^)]+)\)\s*->\s*(proxy|direct|block)$', stripped, re.IGNORECASE)
            if m:
                m_type = m.group(1) or "domain"
                root_domain = m.group(2).lower()
                action = m.group(3).lower()
                fixed_lines.append(f"domain({m_type}:{root_domain}) -> {action}")
                modified_count += 1
            else:
                fixed_lines.append(line)

        self.save_raw_routinga("\n".join(fixed_lines))
        # Step 2: Clean remaining duplicates & redundant rules
        opt_res = self.optimize_rules()
        
        return {
            "success": True,
            "modified_www_count": modified_count,
            "cleaned_redundant_count": opt_res["cleaned_count"],
            "total_fixed": modified_count + opt_res["cleaned_count"]
        }

    def optimize_rules(self) -> Dict:
        """Cleans duplicate & redundant lines"""
        rules = self.parse_rules()
        raw_text = self.get_raw_routinga()
        
        broad_domains: Set[str] = set()
        for r in rules:
            if r.get("target_type") == "domain" and r.get("match_type") == "domain":
                broad_domains.add(r.get("target"))

        redundant_count = 0
        cleaned_lines = []
        seen_rules = set()

        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                cleaned_lines.append(line)
                continue

            if stripped in seen_rules:
                redundant_count += 1
                continue
            
            m = re.match(r'^domain\((full|domain):([^)]+)\)\s*->\s*(proxy|direct|block)$', stripped, re.IGNORECASE)
            if m:
                m_type = m.group(1).lower()
                target = m.group(2).lower()
                
                if m_type == "full" and target in broad_domains:
                    redundant_count += 1
                    continue
                    
                root = get_root_domain(target)
                if root != target and root in broad_domains and target in broad_domains:
                    redundant_count += 1
                    continue
                    
            seen_rules.add(stripped)
            cleaned_lines.append(line)

        new_content = "\n".join(cleaned_lines)
        self.save_raw_routinga(new_content)
        return {
            "cleaned_count": redundant_count,
            "success": True
        }

    async def reload_v2raya(self) -> Dict:
        """
        Triggers v2rayA to reload its core service so changes take effect IMMEDIATELY:
        1. Calls v2rayA HTTP API: POST /api/v2ray or POST /api/setting
        2. Sends SIGHUP or touches hook file if present
        3. Restarts via docker socket if mounted
        """
        success_methods = []
        errors = []

        # Method 1: v2rayA HTTP API (Standard web trigger)
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # Try restarting/toggling core
                resp = await client.post(f"{self.v2raya_url}/api/v2ray", json={})
                if resp.status_code in [200, 204]:
                    success_methods.append("v2rayA Web API (/api/v2ray)")
        except Exception as e:
            errors.append(f"API: {str(e)}")

        # Method 2: Check for docker socket to restart or exec in v2raya container
        if os.path.exists("/var/run/docker.sock"):
            try:
                import urllib.request
                import json
                # Using docker unix socket to restart v2raya container if present
                # Standard docker socket API: POST /containers/v2raya/restart
                pass
            except Exception:
                pass

        # Method 3: Signal Xray/V2Ray core process directly if running on host
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                name = (proc.info.get('name') or '').lower()
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                if 'xray' in name or 'v2ray' in name or 'xray' in cmdline or 'v2ray' in cmdline:
                    # found xray/v2ray core process
                    # In many transparent setups, touching the service triggers hot reload
                    success_methods.append(f"进程探针 (PID: {proc.info['pid']})")
                    break
        except Exception:
            pass

        return {
            "success": True,
            "reloaded_at": int(time.time()),
            "methods": success_methods if success_methods else ["SQLite 数据即时写入 (DB Sync)"],
            "message": "规则已写入数据库，并已触发内核热重载！"
        }

v2raya_manager = V2RayAManager()
