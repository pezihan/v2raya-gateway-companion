import asyncio
import json
from typing import Optional, List, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import settings
from app.domain_utils import extract_domain, get_root_domain, analyze_domain, format_routinga_rule
from app.gfw_prober import prober
from app.v2raya_manager import v2raya_manager
from app.sniffer import sniffer
from app.lan_scanner import get_lan_devices

app = FastAPI(title="v2rayA Gateway Companion", version="1.0.0")

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Hook sniffer callback to WebSocket broadcast
async def on_sniffer_alert(alert: dict):
    await ws_manager.broadcast({
        "type": "NEW_BLOCKED_DOMAIN",
        "data": alert
    })

sniffer.set_broadcast_callback(on_sniffer_alert)

# Request Models
class AnalyzeRequest(BaseModel):
    url: str

class CheckDomainRequest(BaseModel):
    domain: str
    force_refresh: bool = False

class AddRuleRequest(BaseModel):
    domain: str
    action: str = "proxy" # proxy, direct, block
    match_type: str = "domain" # domain, full
    category: str = "自定义代理"

class RawRuleRequest(BaseModel):
    content: str

class StartMonitorRequest(BaseModel):
    target_ip: str
    duration_seconds: int = 0

class SimulateTrafficRequest(BaseModel):
    domain: str
    target_ip: Optional[str] = "192.168.1.50"

# --- API Endpoints ---

@app.get("/api/status")
async def get_system_status():
    return {
        "status": "online",
        "v2raya_url": settings.V2RAYA_URL,
        "sniffer": sniffer.get_status(),
        "total_rules": len(v2raya_manager.parse_rules())
    }

@app.get("/api/devices")
async def list_lan_devices():
    return get_lan_devices()

@app.post("/api/domain/analyze")
async def api_analyze_domain(req: AnalyzeRequest):
    return analyze_domain(req.url)

@app.post("/api/domain/check")
async def api_check_domain(req: CheckDomainRequest):
    domain = extract_domain(req.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="无效的域名或URL")
        
    analysis = analyze_domain(domain)
    probe_result = await prober.check_domain(domain, req.force_refresh)
    
    # Check if currently proxied
    is_proxied = v2raya_manager.is_domain_proxied(domain)
    
    return {
        **analysis,
        "probe": probe_result,
        "already_proxied": is_proxied
    }

@app.get("/api/rules")
async def get_rules():
    return {
        "rules": v2raya_manager.parse_rules(),
        "raw": v2raya_manager.get_raw_routinga()
    }

@app.post("/api/rules/add")
async def add_rule(req: AddRuleRequest):
    domain = extract_domain(req.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="无效的域名")
        
    success = v2raya_manager.add_domain_rule(
        domain=domain,
        action=req.action,
        match_type=req.match_type,
        category=req.category
    )
    
    # Notify WebSocket clients
    await ws_manager.broadcast({
        "type": "RULES_UPDATED",
        "domain": domain,
        "action": req.action
    })
    
    return {
        "success": success,
        "domain": domain,
        "rule": format_routinga_rule(domain, req.action, req.match_type)
    }

@app.delete("/api/rules")
async def delete_rule(target: str):
    success = v2raya_manager.delete_rule_by_target(target)
    await ws_manager.broadcast({"type": "RULES_UPDATED"})
    return {"success": success}

@app.post("/api/rules/optimize")
async def optimize_rules():
    result = v2raya_manager.optimize_rules()
    await ws_manager.broadcast({"type": "RULES_UPDATED"})
    return result

@app.post("/api/rules/raw")
async def save_raw_rules(req: RawRuleRequest):
    success = v2raya_manager.save_raw_routinga(req.content)
    await ws_manager.broadcast({"type": "RULES_UPDATED"})
    return {"success": success}

# --- Monitoring Endpoints ---

@app.post("/api/monitor/start")
async def start_monitor(req: StartMonitorRequest):
    result = sniffer.start(req.target_ip, req.duration_seconds)
    await ws_manager.broadcast({
        "type": "MONITOR_STATUS_CHANGED",
        "data": sniffer.get_status()
    })
    return result

@app.post("/api/monitor/stop")
async def stop_monitor():
    result = sniffer.stop()
    await ws_manager.broadcast({
        "type": "MONITOR_STATUS_CHANGED",
        "data": sniffer.get_status()
    })
    return result

@app.get("/api/monitor/status")
async def get_monitor_status():
    return sniffer.get_status()

@app.get("/api/monitor/alerts")
async def get_alerts():
    return sniffer.detected_alerts

@app.delete("/api/monitor/alerts")
async def clear_alerts():
    sniffer.detected_alerts.clear()
    await ws_manager.broadcast({"type": "ALERTS_CLEARED"})
    return {"success": True}

@app.post("/api/monitor/simulate")
async def simulate_traffic(req: SimulateTrafficRequest):
    """Simulates an incoming request from the target IP for demonstration/verification"""
    domain = extract_domain(req.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    await sniffer.handle_observed_domain(domain, req.target_ip or "192.168.1.50")
    return {"success": True, "domain": domain}

# --- WebSocket ---

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive heartbeat
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Serve static frontend
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/")
async def index():
    return FileResponse("app/static/index.html")
