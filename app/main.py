from contextlib import asynccontextmanager
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

async def v2raya_auto_sync_loop():
    """Background task checking for external v2rayA rule changes every 4 seconds"""
    while True:
        try:
            await asyncio.sleep(4)
            if v2raya_manager.check_for_external_changes():
                await ws_manager.broadcast({
                    "type": "RULES_UPDATED",
                    "source": "v2rayA_auto_sync"
                })
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(4)

@asynccontextmanager
async def lifespan(app: FastAPI):
    sync_task = asyncio.create_task(v2raya_auto_sync_loop())
    yield
    sync_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="v2rayA Gateway Companion", version="1.0.0", lifespan=lifespan)

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

class UpdateRuleRequest(BaseModel):
    old_target: str
    new_target: str
    new_match_type: str = "domain"
    new_action: str = "proxy"
    new_category: Optional[str] = None

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
    storage_info = v2raya_manager.get_sync_status()
    return {
        "status": "online",
        "v2raya_url": settings.V2RAYA_URL,
        "storage": storage_info,
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
        "raw": v2raya_manager.get_raw_routinga(),
        "audit": v2raya_manager.audit_rules(),
        "storage": v2raya_manager.get_sync_status()
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
    
    reload_res = await v2raya_manager.reload_v2raya()
    
    await ws_manager.broadcast({
        "type": "RULES_UPDATED",
        "domain": domain,
        "action": req.action,
        "reload": reload_res
    })
    
    return {
        "success": success,
        "domain": domain,
        "rule": format_routinga_rule(domain, req.action, req.match_type),
        "reload": reload_res
    }

@app.post("/api/rules/update")
async def update_rule(req: UpdateRuleRequest):
    new_domain = extract_domain(req.new_target)
    if not new_domain:
        raise HTTPException(status_code=400, detail="新域名格式无效")
        
    success = v2raya_manager.update_rule(
        old_target=req.old_target,
        new_target=new_domain,
        new_match_type=req.new_match_type,
        new_action=req.new_action,
        new_category=req.new_category
    )
    reload_res = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED", "reload": reload_res})
    return {"success": success, "new_domain": new_domain, "reload": reload_res}

@app.delete("/api/rules")
async def delete_rule(target: str):
    success = v2raya_manager.delete_rule_by_target(target)
    reload_res = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED", "reload": reload_res})
    return {"success": success, "reload": reload_res}

@app.get("/api/rules/audit")
async def audit_rules():
    return v2raya_manager.audit_rules()

@app.post("/api/rules/auto-fix")
async def auto_fix_rules():
    result = v2raya_manager.auto_fix_rules()
    reload_res = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED", "reload": reload_res})
    return {**result, "reload": reload_res}

@app.post("/api/rules/optimize")
async def optimize_rules():
    result = v2raya_manager.optimize_rules()
    reload_res = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED", "reload": reload_res})
    return {**result, "reload": reload_res}

@app.post("/api/rules/raw")
async def save_raw_rules(req: RawRuleRequest):
    success = v2raya_manager.save_raw_routinga(req.content)
    reload_res = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED", "reload": reload_res})
    return {"success": success, "reload": reload_res}

@app.post("/api/rules/sync")
async def sync_from_v2raya():
    result = v2raya_manager.force_sync_from_v2raya()
    await ws_manager.broadcast({"type": "RULES_UPDATED"})
    return result

@app.post("/api/v2ray/reload")
async def reload_v2ray():
    result = await v2raya_manager.reload_v2raya()
    await ws_manager.broadcast({"type": "V2RAY_RELOADED", "data": result})
    return result

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
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/")
async def index():
    return FileResponse("app/static/index.html")
