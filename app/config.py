import os
import sys
from pydantic import BaseModel

def resolve_auth_password() -> str:
    # 1. CLI flag: --no-auth disables password
    if "--no-auth" in sys.argv:
        return ""
    # 2. CLI flag: --password <val> or -p <val> or --password=<val>
    for idx, arg in enumerate(sys.argv):
        if arg in ("--password", "-p") and idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
        if arg.startswith("--password="):
            return arg.split("=", 1)[1]
    # 3. Environment variables
    for k in ("AUTH_PASSWORD", "PASSWORD", "APP_PASSWORD"):
        if k in os.environ:
            return os.environ[k]
    # 4. Default as requested by user
    return "433127"

class Settings(BaseModel):
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "2018"))
    
    # Authentication
    AUTH_PASSWORD: str = resolve_auth_password()
    SECRET_KEY: str = os.getenv("SECRET_KEY", "v2raya-gateway-companion-secret-key-salt")
    
    # v2rayA connections
    V2RAYA_URL: str = os.getenv("V2RAYA_URL", "http://127.0.0.1:2017")
    V2RAYA_DB_PATH: str = os.getenv("V2RAYA_DB_PATH", "/etc/v2raya/v2raya.db")
    ROUTINGA_BACKUP_PATH: str = os.getenv("ROUTINGA_BACKUP_PATH", "./data/routinga.conf")
    SYNC_INTERVAL: int = int(os.getenv("SYNC_INTERVAL", "60"))  # Background auto-sync interval in seconds (default: 60s)
    
    # GFW Probing settings
    DOMESTIC_DNS: str = os.getenv("DOMESTIC_DNS", "223.5.5.5")
    OVERSEAS_DOH: str = os.getenv("OVERSEAS_DOH", "https://1.1.1.1/dns-query")
    PROBE_TIMEOUT: float = float(os.getenv("PROBE_TIMEOUT", "3.0"))
    
    # Sniffing settings
    SNIFF_INTERFACE: str = os.getenv("SNIFF_INTERFACE", "")  # empty means auto-detect

settings = Settings()
