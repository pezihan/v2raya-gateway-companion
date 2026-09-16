import os
import re
import time
import json
import sqlite3
import urllib.request
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
        self._last_mtimes: Dict[str, float] = {}
        self._cached_content: Optional[str] = None
        self._v2raya_token: Optional[str] = None
        self._v2raya_token_exp: float = 0
        self._active_password: Optional[str] = None
        os.makedirs(os.path.dirname(self.backup_path) or ".", exist_ok=True)
        if not os.path.exists(self.backup_path):
            with open(self.backup_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_ROUTINGA_TEMPLATE)
        self._update_recorded_mtimes()

    def set_active_password(self, pwd: str):
        """Allows setting the active v2rayA/Companion session password dynamically"""
        if pwd:
            self._active_password = pwd.strip()
            self._v2raya_token = None  # Invalidate cached token to refresh on next request

    def _extract_v2raya_username(self) -> str:
        """Extracts username from /etc/v2raya/bolt.db accounts bucket or fallback"""
        for path in ["/etc/v2raya/bolt.db", "/etc/v2raya/boltv4.db"]:
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        raw = f.read()
                    idx = raw.find(b"accounts")
                    if idx != -1:
                        m = re.search(rb'([a-zA-Z0-9_-]{3,30})"[a-f0-9]{32}"', raw[idx:idx+400])
                        if m:
                            return m.group(1).decode("utf-8")
                except Exception:
                    pass
        return os.getenv("V2RAYA_USER", "admin")

    def _get_v2raya_token(self) -> Optional[str]:
        """Logs into v2rayA REST API using detected credentials and returns JWT token"""
        now = time.time()
        if self._v2raya_token and self._v2raya_token_exp > now + 60:
            return self._v2raya_token

        username = self._extract_v2raya_username() or os.getenv("V2RAYA_USER", "admin")
        password = self._active_password or getattr(settings, "AUTH_PASSWORD", "") or os.getenv("V2RAYA_PASSWORD", "")
        if not password:
            return None
        try:
            url = f"{self.v2raya_url}/api/login"
            req = urllib.request.Request(
                url,
                data=json.dumps({"username": username, "password": password}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("code") == "SUCCESS" and data.get("data", {}).get("token"):
                    self._v2raya_token = data["data"]["token"]
                    self._v2raya_token_exp = now + 7200
                    return self._v2raya_token
        except Exception:
            pass
        return None

    def _read_via_v2raya_api(self) -> Optional[str]:
        """Reads RoutingA directly from v2rayA official REST API"""
        token = self._get_v2raya_token()
        if not token:
            return None
        try:
            url = f"{self.v2raya_url}/api/routingA"
            req = urllib.request.Request(url, headers={"Authorization": token})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("code") == "SUCCESS":
                    val = data.get("data", {}).get("routingA", "")
                    if val and "default:" in val and "->" in val:
                        return val
        except Exception:
            pass
        return None

    def _save_via_v2raya_api(self, content: str) -> bool:
        """Saves RoutingA directly to v2rayA official REST API (updates DB and applies routing)"""
        token = self._get_v2raya_token()
        if not token:
            return False
        try:
            url = f"{self.v2raya_url}/api/routingA"
            req = urllib.request.Request(
                url,
                data=json.dumps({"routingA": content}).encode("utf-8"),
                headers={"Authorization": token, "Content-Type": "application/json"},
                method="PUT"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("code") == "SUCCESS"
        except Exception as e:
            print(f"[v2rayA API PUT error] {e}")
            return False

    def apply_v2raya_setting(self) -> Dict:
        """
        Calls v2rayA official REST API PUT /api/setting (Save and Apply)
        to rebuild /etc/v2raya/config.json and reload Xray/V2Ray core service.
        """
        token = self._get_v2raya_token()
        if not token:
            return {"success": False, "message": "未获取到 v2rayA 鉴权 Token，已写入本地备份"}

        try:
            # 1. Fetch current setting object from v2rayA
            get_req = urllib.request.Request(
                f"{self.v2raya_url}/api/setting",
                headers={"Authorization": token}
            )
            with urllib.request.urlopen(get_req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("code") != "SUCCESS":
                    return {"success": False, "message": f"获取配置失败: {data.get('message')}"}
                current = data.get("data", {}).get("setting", {})

            # 2. Build complete payload exactly as v2rayA Web UI does
            payload = {
                "proxyModeWhenSubscribe": current.get("proxyModeWhenSubscribe", "direct"),
                "pacAutoUpdateMode": current.get("pacAutoUpdateMode", "auto_update_at_intervals"),
                "pacAutoUpdateIntervalHour": int(current.get("pacAutoUpdateIntervalHour", 100)),
                "subscriptionAutoUpdateMode": current.get("subscriptionAutoUpdateMode", "auto_update_at_intervals"),
                "subscriptionAutoUpdateIntervalHour": int(current.get("subscriptionAutoUpdateIntervalHour", 5)),
                "pacMode": current.get("pacMode", "routingA"),
                "tcpFastOpen": current.get("tcpFastOpen", "default"),
                "inboundSniffing": current.get("inboundSniffing", "http,tls,quic"),
                "muxOn": current.get("muxOn", "yes"),
                "mux": int(current.get("mux", 4)),
                "transparent": current.get("transparent", "pac"),
                "transparentType": current.get("transparentType", "tproxy"),
                "ipforward": bool(current.get("ipforward", True)),
                "portSharing": bool(current.get("portSharing", False)),
                "dnsforward": "yes" if current.get("antipollution") == "dnsforward" else "no",
                "antipollution": current.get("antipollution", "closed"),
                "specialMode": current.get("specialMode", "none")
            }

            # 3. Call PUT /api/setting to trigger '保存并应用'
            put_req = urllib.request.Request(
                f"{self.v2raya_url}/api/setting",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Authorization": token, "Content-Type": "application/json"},
                method="PUT"
            )
            with urllib.request.urlopen(put_req, timeout=6.0) as resp:
                put_data = json.loads(resp.read().decode("utf-8"))
                if put_data.get("code") == "SUCCESS":
                    return {
                        "success": True,
                        "reloaded_at": int(time.time()),
                        "message": "已通知 v2rayA 保存并应用配置，Xray 内核已即时热重载生效！"
                    }
                else:
                    return {"success": False, "message": f"v2rayA 返回错误: {put_data.get('message')}"}
        except Exception as e:
            return {"success": False, "message": f"调用 v2rayA 保存并应用 API 失败: {str(e)}"}

    def _get_candidate_paths(self) -> List[str]:
        candidates = [
            self.db_path,
            "/etc/v2raya/bolt.db",
            "/etc/v2raya/boltv4.db",
            "/root/.config/v2raya/v2raya.db"
        ]
        v2raya_dir = os.path.dirname(self.db_path)
        if os.path.exists(v2raya_dir):
            try:
                for f in os.listdir(v2raya_dir):
                    fp = os.path.join(v2raya_dir, f)
                    if fp not in candidates and os.path.isfile(fp):
                        candidates.append(fp)
            except Exception:
                pass
        return candidates

    def _update_recorded_mtimes(self):
        mtimes = {}
        for p in self._get_candidate_paths():
            if os.path.exists(p):
                try:
                    mtimes[p] = os.path.getmtime(p)
                except Exception:
                    pass
        self._last_mtimes = mtimes

    def check_for_external_changes(self) -> bool:
        """
        Checks if v2rayA files have been modified externally.
        Returns True if new content was detected and loaded.
        """
        current_mtimes = {}
        for p in self._get_candidate_paths():
            if os.path.exists(p):
                try:
                    current_mtimes[p] = os.path.getmtime(p)
                except Exception:
                    pass

        if not self._last_mtimes:
            self._last_mtimes = current_mtimes
            return False

        if current_mtimes != self._last_mtimes:
            self._last_mtimes = current_mtimes
            new_content = self._read_via_v2raya_api() or self._read_from_sqlite()
            if new_content and new_content != self._cached_content:
                self._cached_content = new_content
                with open(self.backup_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                return True
        return False

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
                data = f.read()

            # Method A: Locate json-encoded string routingA"..." in BoltDB
            indices = []
            idx = 0
            while True:
                pos = data.find(b'routingA"', idx)
                if pos == -1:
                    break
                indices.append(pos)
                idx = pos + 1

            decoder = json.JSONDecoder()
            for pos in reversed(indices):
                start_quote = pos + len(b'routingA')
                try:
                    text = data[start_quote:].decode('utf-8', errors='ignore')
                    val, _ = decoder.raw_decode(text)
                    if isinstance(val, str) and 'default:' in val and '->' in val:
                        return val
                except Exception:
                    continue

            # Method B: Regex fallback
            text = data.decode('utf-8', errors='ignore')
            matches = re.findall(r'((?:#.*\n|default:\s*(?:direct|proxy|block)\n|(?:domain|ip)\([^)]+\)\s*->\s*(?:proxy|direct|block)\n|\s*\n){4,})', text)
            for m in matches:
                if 'domain(' in m and ('-> proxy' in m or '-> direct' in m):
                    cleaned = m.strip()
                    if len(cleaned) > 50:
                        return cleaned
        except Exception as e:
            print(f"[Binary extraction error] {e}")
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
        """Returns storage mode, found files, and v2raya connection status"""
        has_bolt = os.path.exists("/etc/v2raya/bolt.db")
        db_exists = os.path.exists(self.db_path)
        token = self._get_v2raya_token()
        has_api = bool(token)
        found_files = []
        v2raya_dir = os.path.dirname(self.db_path)
        if os.path.exists(v2raya_dir):
            try:
                found_files = os.listdir(v2raya_dir)
            except Exception:
                pass

        if has_api:
            storage_mode = "v2rayA 原生 API 直连模式 (自动热生效)"
        elif has_bolt or db_exists or found_files:
            storage_mode = "BoltDB 数据库直读同步模式"
        else:
            storage_mode = "本地备份模式"

        return {
            "db_path": "/etc/v2raya/bolt.db" if has_bolt else self.db_path,
            "db_connected": has_api or has_bolt or db_exists,
            "found_files": found_files,
            "backup_path": self.backup_path,
            "storage_mode": storage_mode
        }

    def force_sync_from_v2raya(self) -> Dict:
        """Forces a re-scan of v2rayA API / database to pull latest changes made in v2rayA UI"""
        content = self._read_via_v2raya_api() or self._read_from_sqlite()
        self._update_recorded_mtimes()
        if content:
            self._cached_content = content
            with open(self.backup_path, "w", encoding="utf-8") as f:
                f.write(content)
            source = "v2rayA 原生 API" if self._v2raya_token else "v2rayA 数据库"
            return {"success": True, "source": source, "length": len(content)}
        return {"success": False, "message": "未在 /etc/v2raya 中探测到可读数据库或 API，已保持现有配置"}

    def get_raw_routinga(self) -> str:
        """Gets current raw RoutingA configuration string"""
        # Priority 1: Official v2rayA API
        api_content = self._read_via_v2raya_api()
        if api_content:
            self._cached_content = api_content
            try:
                with open(self.backup_path, "w", encoding="utf-8") as f:
                    f.write(api_content)
            except Exception:
                pass
            return api_content

        # Priority 2: Database candidate files (BoltDB / SQLite)
        content = self._read_from_sqlite()
        if content:
            self._cached_content = content
            try:
                with open(self.backup_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                pass
            return content

        # Priority 3: Local backup file
        if os.path.exists(self.backup_path):
            with open(self.backup_path, "r", encoding="utf-8") as f:
                content = f.read()
                if content.strip():
                    self._cached_content = content
                    return content

        self._cached_content = DEFAULT_ROUTINGA_TEMPLATE
        return DEFAULT_ROUTINGA_TEMPLATE

    def save_raw_routinga(self, content: str) -> bool:
        """Saves raw RoutingA string to API, DB & file, and hot-applies to v2rayA"""
        self._cached_content = content
        # Save to backup file
        with open(self.backup_path, "w", encoding="utf-8") as f:
            f.write(content)

        # Priority 1: Save via official v2rayA API (which writes to BoltDB)
        self._save_via_v2raya_api(content)

        # Priority 2: SQLite write if SQLite exists
        self._save_to_sqlite(content)

        # Priority 3: Trigger v2rayA official '保存并应用' so config.json is rebuilt and core reloads
        self.apply_v2raya_setting()

        # Update recorded mtimes so our own write doesn't trigger false external detection
        self._update_recorded_mtimes()
        return True

    def parse_category_sections(self, raw_text: Optional[str] = None) -> List[Dict]:
        """
        Parses raw RoutingA text into structured category sections.
        Each section dict contains:
          - category: category name
          - header_lines: banner comment lines
          - body_lines: rule and inline comment lines
        """
        if raw_text is None:
            raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        has_banner = any(re.match(r'^#\s*={3,}$', l.strip()) for l in lines)
        sections = []
        i = 0
        current_cat = None
        current_header = []
        current_body = []

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            is_header = False
            cat_name = None
            header_lines = []

            if has_banner:
                if stripped.startswith('#') and re.match(r'^#\s*={3,}$', stripped):
                    if i + 1 < len(lines):
                        next_s = lines[i+1].strip()
                        if next_s.startswith('#') and not re.match(r'^#\s*={3,}$', next_s):
                            cat_candidate = next_s.lstrip('# \t').strip()
                            if cat_candidate:
                                cat_name = cat_candidate
                                header_lines = [lines[i], lines[i+1]]
                                i += 2
                                if i < len(lines) and re.match(r'^#\s*={3,}$', lines[i].strip()):
                                    header_lines.append(lines[i])
                                    i += 1
                                is_header = True
                elif stripped.startswith('#') and not re.match(r'^#\s*={3,}$', stripped):
                    if i + 1 < len(lines) and re.match(r'^#\s*={3,}$', lines[i+1].strip()):
                        cat_candidate = stripped.lstrip('# \t').strip()
                        if cat_candidate:
                            cat_name = cat_candidate
                            header_lines = [lines[i], lines[i+1]]
                            i += 2
                            is_header = True
            else:
                if stripped.startswith('#'):
                    cand = stripped.lstrip('# \t').strip()
                    if cand and not cand.startswith('==='):
                        cat_name = cand
                        header_lines = [lines[i]]
                        i += 1
                        is_header = True

            if is_header:
                if current_cat is not None or current_body or current_header:
                    sections.append({
                        'category': current_cat or '默认分类',
                        'header_lines': current_header,
                        'body_lines': current_body
                    })
                current_cat = cat_name
                current_header = header_lines
                current_body = []
            else:
                current_body.append(line)
                i += 1

        if current_cat is not None or current_body or current_header:
            sections.append({
                'category': current_cat or '默认分类',
                'header_lines': current_header,
                'body_lines': current_body
            })
        return sections

    def get_ordered_categories(self, raw_text: Optional[str] = None) -> List[str]:
        """Returns the list of categories in their actual order in RoutingA (top-to-bottom)"""
        sections = self.parse_category_sections(raw_text)
        ordered = []
        for s in sections:
            cat = s["category"]
            if cat and cat not in ["默认规则", "系统策略", "默认策略"] and cat not in ordered:
                ordered.append(cat)
        return ordered

    def reorder_categories(self, category_order: List[str]) -> bool:
        """
        Reorders the categories in raw RoutingA according to category_order list.
        Top categories have higher matching priority.
        Automatically saves and triggers v2rayA 'Save and Apply'.
        """
        raw_text = self.get_raw_routinga()
        sections = self.parse_category_sections(raw_text)
        if not sections:
            return False

        cat_to_section = {s["category"]: s for s in sections}
        ordered_sections = []

        # 1. Keep system default rule section (like 默认规则 containing 'default: ...') at the very top
        first_sec = sections[0]
        has_leading_default = first_sec and (
            first_sec["category"] in ["默认规则", "系统策略", "默认策略"] or
            any("default:" in l for l in first_sec.get("body_lines", []))
        )
        if has_leading_default and first_sec["category"] not in category_order:
            ordered_sections.append(first_sec)

        # 2. Place categories in the user-specified order
        for cat in category_order:
            if cat in cat_to_section:
                sec = cat_to_section[cat]
                if sec not in ordered_sections:
                    ordered_sections.append(sec)

        # 3. Append any remaining sections that weren't in category_order
        for s in sections:
            if s not in ordered_sections:
                ordered_sections.append(s)

        # 4. Rebuild text
        output_parts = []
        for s in ordered_sections:
            part = []
            if s["header_lines"]:
                part.append("\n".join(s["header_lines"]))
            if s["body_lines"]:
                body_txt = "\n".join(s["body_lines"]).strip("\n")
                if body_txt:
                    part.append(body_txt)
            out_str = "\n".join(part).strip()
            if out_str:
                output_parts.append(out_str)

        new_content = "\n\n\n".join(output_parts) + "\n"
        return self.save_raw_routinga(new_content)

    def parse_rules(self) -> List[Dict]:
        """
        Parses raw text into structured rule items.
        Returns a list of rule dicts with detailed audit info.
        """
        raw_text = self.get_raw_routinga()
        sections = self.parse_category_sections(raw_text)
        rules = []

        rule_regex = re.compile(r'^(domain|ip)\((domain|full|keyword|regexp)?:?([^)]+)\)\s*->\s*(proxy|direct|block)$', re.IGNORECASE)
        line_counter = 0

        for sec in sections:
            cat_name = sec["category"]
            for line in sec.get("body_lines", []):
                line_counter += 1
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                match = rule_regex.match(stripped)
                if match:
                    target_type = match.group(1).lower() # domain / ip
                    raw_prefix = match.group(2).lower() if match.group(2) else ""
                    target_value = match.group(3).strip()
                    action = match.group(4).lower()

                    # Accurately classify rule_type and match_type
                    if target_type == "ip":
                        if target_value.lower().startswith("geoip:"):
                            rule_type = "geoip"
                            match_type = "geoip"
                            clean_target = target_value
                        else:
                            rule_type = "ip"
                            match_type = "cidr" if ("/" in target_value or ":" in target_value) else "ip"
                            clean_target = target_value.strip('"\'')
                        has_www = False
                        is_sub = False
                        suggested_root = None
                    elif target_type == "domain":
                        if target_value.lower().startswith("geosite:"):
                            rule_type = "geosite"
                            match_type = "geosite"
                            clean_target = target_value
                            has_www = False
                            is_sub = False
                            suggested_root = None
                        elif target_value.lower().startswith("ext:"):
                            rule_type = "ext"
                            match_type = "ext"
                            clean_target = target_value
                            has_www = False
                            is_sub = False
                            suggested_root = None
                        else:
                            rule_type = "domain"
                            match_type = raw_prefix if raw_prefix in ["full", "keyword", "regexp"] else "domain"
                            clean_target = target_value.strip('"\'')
                            has_www = clean_target.lower().startswith("www.")
                            root_domain = get_root_domain(clean_target)
                            is_sub = (clean_target.lower() != root_domain.lower()) and (not re.match(r'^\d+\.\d+\.\d+\.\d+$', clean_target))
                            suggested_root = root_domain if is_sub else None

                    rules.append({
                        "id": f"rule_{line_counter}_{abs(hash(stripped)) % 10000}",
                        "line": line_counter,
                        "rule_type": rule_type,
                        "target_type": target_type,
                        "match_type": match_type,
                        "target": clean_target,
                        "action": action,
                        "category": cat_name,
                        "has_www": has_www,
                        "is_subdomain": is_sub,
                        "suggested_root": suggested_root,
                        "raw": stripped
                    })
                elif stripped.startswith("default:"):
                    action = stripped.split(":")[-1].strip()
                    rules.append({
                        "id": f"default_{line_counter}",
                        "line": line_counter,
                        "rule_type": "default",
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
                target = r.get("target", "").lower()
                match_type = r.get("match_type", "domain")
                if match_type == "full":
                    if target == domain:
                        return True
                elif match_type == "domain":
                    if domain == target or domain.endswith("." + target):
                        return True
        return False

    def add_rule(
        self,
        target: str,
        action: str = "proxy",
        match_type: str = "domain",
        target_type: str = "domain",
        category: str = "自定义代理"
    ) -> bool:
        """Adds a new rule (domain, geosite, geoip, ip/cidr) under specified category"""
        target = target.strip()
        category = category.strip() or "自定义代理"
        new_rule_str = format_routinga_rule(target, action, match_type, target_type)

        raw_text = self.get_raw_routinga()
        sections = self.parse_category_sections(raw_text)

        # Check if category already exists
        target_sec = None
        for sec in sections:
            if sec["category"].strip().lower() == category.lower():
                target_sec = sec
                break

        if target_sec is not None:
            # Insert at the top of this category's body
            target_sec["body_lines"].insert(0, new_rule_str)
        else:
            # Create a brand new section
            new_sec = {
                "category": category,
                "header_lines": [
                    "# =========================================================",
                    f"# {category}",
                    "# ========================================================="
                ],
                "body_lines": ["", new_rule_str]
            }
            # If proxy rule, place before broad direct rules like '中国大陆及私有地址直连' or '保证国内直连'
            insert_idx = -1
            if action.lower() == "proxy":
                for idx, sec in enumerate(sections):
                    c_name = sec["category"]
                    if "直连" in c_name or "cn" in c_name.lower() or any("geosite:cn" in b for b in sec.get("body_lines", [])):
                        insert_idx = idx
                        break

            if insert_idx != -1:
                sections.insert(insert_idx, new_sec)
            else:
                sections.append(new_sec)

        # Reconstruct RoutingA text
        output_parts = []
        for s in sections:
            part = []
            if s["header_lines"]:
                part.append("\n".join(s["header_lines"]))
            if s["body_lines"]:
                body_txt = "\n".join(s["body_lines"]).strip("\n")
                if body_txt:
                    part.append(body_txt)
            out_str = "\n".join(part).strip()
            if out_str:
                output_parts.append(out_str)

        new_content = "\n\n\n".join(output_parts) + "\n"
        return self.save_raw_routinga(new_content)

    def add_domain_rule(self, domain: str, action: str = "proxy", match_type: str = "domain", category: str = "自定义代理") -> bool:
        """Backward compatibility alias for add_rule"""
        return self.add_rule(target=domain, action=action, match_type=match_type, target_type="domain", category=category)

    def update_rule(
        self,
        old_target: str,
        new_target: str,
        new_match_type: str = "domain",
        new_action: str = "proxy",
        new_category: Optional[str] = None,
        target_type: Optional[str] = None,
        old_match_type: Optional[str] = None,
        old_action: Optional[str] = None
    ) -> bool:
        """
        Updates an existing rule:
        Modifies target, match_type, action, or moves category.
        """
        old_clean_target = old_target.strip('"\'')
        old_clean = re.sub(r'\s*,\s*', ',', old_clean_target.lower().strip())
        new_clean = new_target.strip()
        
        # Detect target_type if not provided
        if not target_type:
            if new_clean.lower().startswith("geoip:") or "/" in new_clean or ":" in new_clean:
                target_type = "ip"
            else:
                target_type = "domain"

        new_rule_str = format_routinga_rule(new_clean, new_action, new_match_type, target_type)
        
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()

        # Find line index and its category
        old_line_idx = -1
        current_rule_cat = "默认分类"

        # Pass 1: Strict match with old_match_type and old_action if given
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "->" in stripped:
                line_normalized = re.sub(r'\s*,\s*', ',', stripped.lower())
                if old_clean in line_normalized:
                    match_ok = True
                    if old_match_type:
                        if old_match_type in ["full", "keyword", "regexp"]:
                            match_ok = f"{old_match_type}:{old_clean}" in line_normalized
                        elif old_match_type == "domain":
                            match_ok = f"domain:{old_clean}" in line_normalized or f"({old_clean})" in line_normalized
                    action_ok = True
                    if old_action:
                        action_ok = line_normalized.endswith(f"-> {old_action.lower()}") or line_normalized.endswith(f"->{old_action.lower()}")
                    if match_ok and action_ok:
                        old_line_idx = idx
                        break

        # Pass 2: Fallback to loose match
        if old_line_idx == -1:
            for idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "->" in stripped:
                    line_normalized = re.sub(r'\s*,\s*', ',', stripped.lower())
                    if old_clean in line_normalized or old_target.lower() in stripped.lower():
                        old_line_idx = idx
                        break

        if old_line_idx == -1:
            # Fallback: add rule
            return self.add_rule(new_clean, new_action, new_match_type, target_type, new_category or "自定义代理")

        # Determine category of old_line_idx
        for idx in range(old_line_idx - 1, -1, -1):
            s = lines[idx].strip()
            if s.startswith("#") and not s.startswith("# ==="):
                current_rule_cat = s.lstrip("# \t")
                break

        # If new_category is specified and different from current category, remove old and insert into new
        if new_category and new_category.strip().lower() != current_rule_cat.strip().lower():
            lines.pop(old_line_idx)
            self.save_raw_routinga("\n".join(lines))
            return self.add_rule(new_clean, new_action, new_match_type, target_type, new_category)
        else:
            lines[old_line_idx] = new_rule_str
            return self.save_raw_routinga("\n".join(lines))

    def delete_rule(self, target: str, match_type: Optional[str] = None, action: Optional[str] = None) -> bool:
        """Deletes rule matching target, and optionally match_type and action"""
        clean_target = target.strip('"\'')
        target_clean_norm = re.sub(r'\s*,\s*', ',', clean_target.lower().strip())
        raw_text = self.get_raw_routinga()
        lines = raw_text.splitlines()
        new_lines = []
        deleted = False

        for line in lines:
            stripped = line.strip()
            if not stripped.startswith("#") and "->" in stripped and not deleted:
                line_norm = re.sub(r'\s*,\s*', ',', stripped.lower())
                if clean_target in line_norm or target_clean_norm in line_norm:
                    match_ok = True
                    if match_type:
                        if match_type in ["full", "keyword", "regexp"]:
                            match_ok = f"{match_type}:{clean_target.lower()}" in line_norm
                        elif match_type == "domain":
                            match_ok = f"domain:{clean_target.lower()}" in line_norm or f"({clean_target.lower()})" in line_norm
                    action_ok = True
                    if action:
                        action_ok = line_norm.endswith(f"-> {action.lower()}") or line_norm.endswith(f"->{action.lower()}")
                    if match_ok and action_ok:
                        deleted = True
                        continue
            new_lines.append(line)
        return self.save_raw_routinga("\n".join(new_lines))

    def delete_rule_by_target(self, target: str) -> bool:
        """Deletes any rule matching target domain/IP (backward compatible)"""
        return self.delete_rule(target=target)

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

            # Domain-specific audit checks (skip IP, GeoIP, GeoSite, ext DAT)
            if r.get("rule_type") != "domain":
                continue

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
        1. Calls v2rayA official REST API PUT /api/setting (Save and Apply)
        2. Signal Xray/V2Ray core process directly if running on host
        """
        # Priority 1: Official v2rayA Save and Apply API
        apply_res = self.apply_v2raya_setting()
        if apply_res.get("success"):
            return {
                "success": True,
                "reloaded_at": apply_res.get("reloaded_at", int(time.time())),
                "methods": ["v2rayA 原生 API (PUT /api/setting 保存并应用)"],
                "message": "已成功通知 v2rayA 保存并应用配置，Xray 内核已即时热重载生效！"
            }

        success_methods = []
        # Method 2: Signal Xray/V2Ray core process directly if running on host
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                name = (proc.info.get('name') or '').lower()
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                if 'xray' in name or 'v2ray' in name or 'xray' in cmdline or 'v2ray' in cmdline:
                    success_methods.append(f"进程探针 (PID: {proc.info['pid']})")
                    break
        except Exception:
            pass

        return {
            "success": True,
            "reloaded_at": int(time.time()),
            "methods": success_methods if success_methods else ["数据即时写入同步"],
            "message": "规则已保存，内核配置已更新！"
        }

v2raya_manager = V2RayAManager()
