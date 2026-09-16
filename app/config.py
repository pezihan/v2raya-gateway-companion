import os
from pydantic import BaseModel

class Settings(BaseModel):
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "2018"))
    
    # v2rayA connections
    V2RAYA_URL: str = os.getenv("V2RAYA_URL", "http://127.0.0.1:2017")
    V2RAYA_DB_PATH: str = os.getenv("V2RAYA_DB_PATH", "/etc/v2raya/v2raya.db")
    ROUTINGA_BACKUP_PATH: str = os.getenv("ROUTINGA_BACKUP_PATH", "./data/routinga.conf")
    
    # GFW Probing settings
    DOMESTIC_DNS: str = os.getenv("DOMESTIC_DNS", "223.5.5.5")
    OVERSEAS_DOH: str = os.getenv("OVERSEAS_DOH", "https://1.1.1.1/dns-query")
    PROBE_TIMEOUT: float = float(os.getenv("PROBE_TIMEOUT", "3.0"))
    
    # Sniffing settings
    SNIFF_INTERFACE: str = os.getenv("SNIFF_INTERFACE", "")  # empty means auto-detect

settings = Settings()
