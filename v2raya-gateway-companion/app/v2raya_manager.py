import os
import re
import sqlite3
import httpx
from typing import List, Dict, Optional, Set
from app.config import settings
from app.domain_utils import get_root_domain

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
domain(domain:telegram.org) -> proxy
domain(domain:telegram.me) -> proxy
domain(domain:t.me) -> proxy
domain(domain:telegram.dog) -> proxy

# 自定义代理
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

    def _read_from_sqlite(self) -> Optional[str]:
        """Attempts to read RoutingA text directly from v2rayA SQLite DB"""
        if not os.path.exists(self.db_path):
            return None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Try to query configure table
            cursor.execute("SELECT value FROM configure WHERE key = 'routingA' OR key = 'routing_rule' LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                return row[0]
        except Exception:
            pass
        return None

    def _save_to_sqlite(self, content: str) -> bool:
        """Attempts to write RoutingA text to v2rayA SQLite DB"""
        if not os.path.exists(self.db_path):
            return False
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO configure (key, value) VALUES ('routingA', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (content,)
            )
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    async def _save_via_api(self, content: str) -> bool:
        """Tries to update routingA through v2rayA Web REST API"""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # v2rayA setting update endpoint
                resp = await client.post(
                    f"{self.v2raya_url}/api/setting",
                    json={"routingA": content}
                )
                if resp.status_code == 200:
                    return True
        except Exception:
            pass
        return False

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
        """Saves raw RoutingA string to both DB/file and triggers apply"""
        # Save to backup file
        with open(self.backup_path, "w", encoding="utf-8") as f:
            f.write(content)
        # Save to SQLite if exists
        self._save_to_sqlite(content)
        return True

    def parse_rules(self) -> List[Dict]:
        """
        Parses raw text into structured rule items.
        Returns a list of rule dicts.
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
                # Header category detection
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

                rules.append({
                    "id": f"{target_type}_{target_value}_{line_num}",
                    "line": line_num,
                    "target_type": target_type,
                    "match_type": match_type,
                    "target": target_value,
                    "action": action,
                    "category": current_category,
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
                    "raw": stripped
                })
        return rules

    def is_domain_proxied(self, domain: str) -> bool:
        """
        Checks if a domain is already matched by an existing 'proxy' rule.
        Considers root domains and subdomains.
        """
        rules = self.parse_rules()
        domain = domain.lower().strip()
        root_domain = get_root_domain(domain)

        for r in rules:
            if r.get("target_type") == "domain" and r.get("action") == "proxy":
                target = r.get("target", "")
                match_type = r.get("match_type", "domain")
                if match_type == "full":
                    if target == domain:
                        return True
                elif match_type == "domain":
                    # Matches target and all its subdomains
                    if domain == target or domain.endswith("." + target):
                        return True
        return False

    def add_domain_rule(self, domain: str, action: str = "proxy", match_type: str = "domain", category: str = "自定义代理") -> bool:
        """
        Adds a new domain rule under the specified category.
        Ensures formatting and deduplication.
        """
        domain = domain.lower().strip()
        raw_text = self.get_raw_routinga()
        
        # Check if identical rule already exists
        new_rule_str = f"domain({match_type}:{domain}) -> {action}"
        if new_rule_str in raw_text:
            return True

        lines = raw_text.splitlines()
        category_header = f"# {category}"
        
        # Find if category exists
        cat_index = -1
        for idx, line in enumerate(lines):
            if line.strip() == category_header:
                cat_index = idx
                break

        if cat_index != -1:
            # Insert after category header
            lines.insert(cat_index + 1, new_rule_str)
        else:
            # Append new category at the end
            lines.append("")
            lines.append(category_header)
            lines.append(new_rule_str)

        new_content = "\n".join(lines)
        return self.save_raw_routinga(new_content)

    def delete_rule_by_target(self, target: str) -> bool:
        """Deletes any rule matching the target domain/IP"""
        target = target.lower().strip()
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        new_lines = []
        
        for line in lines:
            if target in line.lower() and "->" in line:
                continue
            new_lines.append(line)
            
        return self.save_raw_routinga("\n".join(new_lines))

    def optimize_rules(self) -> Dict:
        """
        Finds and cleans redundant rules:
        - Removes duplicate lines
        - Removes full:example.com if domain:example.com exists
        - Removes subdomains if root domain is already domain:proxied
        """
        rules = self.parse_rules()
        raw_text = self.get_raw_routinga()
        
        # Collect broad domain rules
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
            
            # Check for redundancy
            m = re.match(r'^domain\((full|domain):([^)]+)\)\s*->\s*(proxy|direct|block)$', stripped, re.IGNORECASE)
            if m:
                m_type = m.group(1).lower()
                target = m.group(2).lower()
                
                # If it's a full: target, but domain: target already exists
                if m_type == "full" and target in broad_domains:
                    redundant_count += 1
                    continue
                    
                # If it's www.target or sub.target, but root_domain is in broad_domains
                root = get_root_domain(target)
                if root != target and root in broad_domains:
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

v2raya_manager = V2RayAManager()
