import json
import asyncio
import random
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import insert, select, update, desc, func
from sqlalchemy.engine import Connection
from pydantic import BaseModel

from database import engine, metadata, get_db
import models
from log_parser import LogParser
from threat_detector import threat_detector

# Automatically create tables if not existing
metadata.create_all(bind=engine)

app = FastAPI(title="Real-Time Threat Intelligence & Monitoring System", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# -------------------------------------------------------------
# WebSocket Connection Manager
# -------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: dict):
        payload = json.dumps({"event": event_type, "data": data})
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# -------------------------------------------------------------
# Pydantic Schemas
# -------------------------------------------------------------
class LogIngestRequest(BaseModel):
    raw_log: str
    log_format: str = "auto"

class BlacklistRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = "Security violation"

# -------------------------------------------------------------
# Base & UI Endpoints
# -------------------------------------------------------------
@app.get("/")
def read_root():
    return FileResponse("frontend/dist/index.html")

@app.get("/live")
def serve_dashboard():
    return FileResponse("frontend/dist/index.html")

@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# -------------------------------------------------------------
# Log Ingestion & Query Endpoints
# -------------------------------------------------------------
@app.post("/api/ingest/log")
async def ingest_log(payload: LogIngestRequest, conn: Connection = Depends(get_db)):
    parsed = LogParser.parse(payload.raw_log, payload.log_format)
    now = datetime.utcnow()

    stmt = insert(models.logs_table).values(
        timestamp=now,
        source_ip=parsed["source_ip"],
        destination_ip=parsed["destination_ip"],
        event_type=parsed["event_type"],
        severity=parsed["severity"],
        raw_message=payload.raw_log,
        parsed_data=parsed["parsed_data"],
        created_at=now
    )
    
    result = conn.execute(stmt)
    conn.commit()
    inserted_id = result.inserted_primary_key[0]

    log_data = {
        "id": inserted_id,
        "timestamp": now.isoformat(),
        "source_ip": parsed["source_ip"],
        "destination_ip": parsed["destination_ip"],
        "event_type": parsed["event_type"],
        "severity": parsed["severity"],
        "raw_message": payload.raw_log,
        "parsed_data": parsed["parsed_data"]
    }

    # Broadcast new log via WebSocket
    await manager.broadcast("new_log", log_data)

    # Run Threat Detection Engine
    threat_eval = threat_detector.evaluate(parsed, conn)
    if threat_eval:
        alert_stmt = insert(models.threat_alerts_table).values(
            log_id=inserted_id,
            source_ip=threat_eval["source_ip"],
            threat_type=threat_eval["threat_type"],
            threat_score=threat_eval["threat_score"],
            severity=threat_eval["severity"],
            description=threat_eval["description"],
            is_resolved=False,
            created_at=now
        )
        alert_res = conn.execute(alert_stmt)
        conn.commit()
        alert_id = alert_res.inserted_primary_key[0]

        alert_data = {
            "id": alert_id,
            "log_id": inserted_id,
            "source_ip": threat_eval["source_ip"],
            "threat_type": threat_eval["threat_type"],
            "threat_score": threat_eval["threat_score"],
            "severity": threat_eval["severity"],
            "description": threat_eval["description"],
            "is_resolved": False,
            "created_at": now.isoformat()
        }

        # Broadcast threat alert via WebSocket
        await manager.broadcast("threat_alert", alert_data)
        log_data["threat_alert"] = alert_data

    return {"status": "success", "log": log_data}

@app.get("/api/logs/recent")
def get_recent_logs(limit: int = 50, conn: Connection = Depends(get_db)):
    stmt = select(models.logs_table).order_by(desc(models.logs_table.c.timestamp)).limit(limit)
    result = conn.execute(stmt)
    return [dict(row) for row in result.mappings()]

# -------------------------------------------------------------
# Threat Detection Endpoints
# -------------------------------------------------------------
@app.get("/api/threats")
def get_threats(
    severity: Optional[str] = None,
    is_resolved: Optional[bool] = None,
    limit: int = 50,
    conn: Connection = Depends(get_db)
):
    stmt = select(models.threat_alerts_table)
    if severity:
        stmt = stmt.where(models.threat_alerts_table.c.severity == severity.capitalize())
    if is_resolved is not None:
        stmt = stmt.where(models.threat_alerts_table.c.is_resolved == is_resolved)

    stmt = stmt.order_by(desc(models.threat_alerts_table.c.created_at)).limit(limit)
    result = conn.execute(stmt)
    return [dict(row) for row in result.mappings()]

@app.get("/api/threats/stats")
def get_threat_stats(conn: Connection = Depends(get_db)):
    # Aggregated stats by severity
    sev_stmt = select(
        models.threat_alerts_table.c.severity,
        func.count().label("count")
    ).group_by(models.threat_alerts_table.c.severity)
    sev_res = conn.execute(sev_stmt).mappings().all()

    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in sev_res:
        severity_counts[r["severity"]] = r["count"]

    # Total and unresolved counts
    total_stmt = select(func.count()).select_from(models.threat_alerts_table)
    total_threats = conn.execute(total_stmt).scalar() or 0

    unresolved_stmt = select(func.count()).select_from(models.threat_alerts_table).where(
        models.threat_alerts_table.c.is_resolved == False
    )
    unresolved_threats = conn.execute(unresolved_stmt).scalar() or 0

    return {
        "total_threats": total_threats,
        "unresolved_threats": unresolved_threats,
        "by_severity": severity_counts
    }

@app.get("/api/threats/{threat_id}")
def get_threat_detail(threat_id: int, conn: Connection = Depends(get_db)):
    stmt = select(models.threat_alerts_table).where(models.threat_alerts_table.c.id == threat_id)
    threat = conn.execute(stmt).mappings().first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    return dict(threat)

@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat(threat_id: int, conn: Connection = Depends(get_db)):
    stmt = update(models.threat_alerts_table).where(
        models.threat_alerts_table.c.id == threat_id
    ).values(is_resolved=True)
    res = conn.execute(stmt)
    conn.commit()
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    return {"status": "success", "message": f"Threat alert {threat_id} resolved"}

# -------------------------------------------------------------
# Analytics Endpoints
# -------------------------------------------------------------
@app.get("/api/analytics/timeline")
def get_analytics_timeline(conn: Connection = Depends(get_db)):
    """Generates timeline dataset for dashboard charts."""
    logs_stmt = select(
        models.logs_table.c.timestamp,
        models.logs_table.c.severity
    ).order_by(models.logs_table.c.timestamp.asc()).limit(100)
    
    rows = conn.execute(logs_stmt).mappings().all()

    timeline_data = []
    for r in rows:
        timeline_data.append({
            "timestamp": str(r["timestamp"]),
            "severity": r["severity"]
        })

    return {"timeline": timeline_data}

@app.get("/api/analytics/top-sources")
def get_top_threat_sources(limit: int = 5, conn: Connection = Depends(get_db)):
    stmt = select(
        models.threat_alerts_table.c.source_ip,
        func.count().label("threat_count"),
        func.max(models.threat_alerts_table.c.threat_score).label("max_score")
    ).group_by(models.threat_alerts_table.c.source_ip).order_by(desc("threat_count")).limit(limit)
    
    result = conn.execute(stmt).mappings().all()
    return [dict(r) for r in result]

# -------------------------------------------------------------
# IP Intelligence Endpoints
# -------------------------------------------------------------
@app.get("/api/ip/{ip_address}/info")
def get_ip_intelligence(ip_address: str, conn: Connection = Depends(get_db)):
    log_count_stmt = select(func.count()).select_from(models.logs_table).where(
        models.logs_table.c.source_ip == ip_address
    )
    total_logs = conn.execute(log_count_stmt).scalar() or 0

    threat_stmt = select(models.threat_alerts_table).where(
        models.threat_alerts_table.c.source_ip == ip_address
    )
    threats = [dict(r) for r in conn.execute(threat_stmt).mappings().all()]

    is_blacklisted = threat_detector.is_blacklisted(ip_address, conn)
    max_score = max([t["threat_score"] for t in threats], default=0)

    return {
        "ip_address": ip_address,
        "total_logs": total_logs,
        "threat_count": len(threats),
        "max_threat_score": max_score,
        "is_blacklisted": is_blacklisted,
        "recent_threats": threats[:5]
    }

@app.post("/api/ip/blacklist")
def blacklist_ip(payload: BlacklistRequest, conn: Connection = Depends(get_db)):
    stmt = select(models.blacklisted_ips_table).where(
        models.blacklisted_ips_table.c.ip_address == payload.ip_address
    )
    existing = conn.execute(stmt).mappings().first()
    if existing:
        return {"status": "already_blacklisted", "ip": payload.ip_address}

    ins = insert(models.blacklisted_ips_table).values(
        ip_address=payload.ip_address,
        reason=payload.reason,
        added_at=datetime.utcnow()
    )
    conn.execute(ins)
    conn.commit()

    return {"status": "success", "message": f"IP {payload.ip_address} added to blacklist"}

# -------------------------------------------------------------
# pfSense Integration Endpoints
# -------------------------------------------------------------
@app.post("/api/ingest/pfsense")
async def ingest_pfsense_log(payload: LogIngestRequest, conn: Connection = Depends(get_db)):
    payload.log_format = "pfsense"
    return await ingest_log(payload, conn)

@app.get("/api/pfsense/firewall-rules")
def get_pfsense_rule_stats(conn: Connection = Depends(get_db)):
    stmt = select(models.logs_table).where(
        models.logs_table.c.event_type.in_(["firewall_block", "firewall_pass"])
    ).limit(100)
    
    rows = conn.execute(stmt).mappings().all()
    rule_counts = {}
    for r in rows:
        parsed = r.get("parsed_data") or {}
        rule_id = parsed.get("rule_id", "Default Rule")
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

    return {"top_rules": [{"rule_id": k, "hits": v} for k, v in rule_counts.items()]}

# -------------------------------------------------------------
# Live Traffic Simulator
# -------------------------------------------------------------
simulator_running = False

async def run_traffic_simulator():
    global simulator_running
    sample_ips = ["192.168.1.50", "10.0.0.15", "185.220.101.4", "45.33.32.156", "192.168.1.102"]
    sample_logs = [
        "Failed password for invalid user admin from {ip} port 22 ssh2",
        "filterlog: 1000000103,em0,match,block,in,4,tcp,{ip},10.0.0.1,44321,80",
        "TRAFFIC SRC={ip} DST=10.0.0.1 PROTO=TCP PORT=443",
        "Accepted password for user root from {ip} port 54321 ssh2"
    ]

    while simulator_running:
        await asyncio.sleep(random.uniform(2.0, 4.0))
        ip = random.choice(sample_ips)
        log_str = random.choice(sample_logs).format(ip=ip)
        
        with engine.connect() as conn:
            parsed = LogParser.parse(log_str)
            now = datetime.utcnow()
            stmt = insert(models.logs_table).values(
                timestamp=now,
                source_ip=parsed["source_ip"],
                destination_ip=parsed["destination_ip"],
                event_type=parsed["event_type"],
                severity=parsed["severity"],
                raw_message=log_str,
                parsed_data=parsed["parsed_data"],
                created_at=now
            )
            res = conn.execute(stmt)
            conn.commit()
            inserted_id = res.inserted_primary_key[0]

            log_data = {
                "id": inserted_id,
                "timestamp": now.isoformat(),
                "source_ip": parsed["source_ip"],
                "destination_ip": parsed["destination_ip"],
                "event_type": parsed["event_type"],
                "severity": parsed["severity"],
                "raw_message": log_str
            }
            await manager.broadcast("new_log", log_data)

            threat_eval = threat_detector.evaluate(parsed, conn)
            if threat_eval:
                alert_stmt = insert(models.threat_alerts_table).values(
                    log_id=inserted_id,
                    source_ip=threat_eval["source_ip"],
                    threat_type=threat_eval["threat_type"],
                    threat_score=threat_eval["threat_score"],
                    severity=threat_eval["severity"],
                    description=threat_eval["description"],
                    is_resolved=False,
                    created_at=now
                )
                alert_res = conn.execute(alert_stmt)
                conn.commit()
                alert_data = {
                    "id": alert_res.inserted_primary_key[0],
                    "source_ip": threat_eval["source_ip"],
                    "threat_type": threat_eval["threat_type"],
                    "threat_score": threat_eval["threat_score"],
                    "severity": threat_eval["severity"],
                    "description": threat_eval["description"],
                    "created_at": now.isoformat()
                }
                await manager.broadcast("threat_alert", alert_data)

@app.post("/api/simulator/start")
async def start_simulator():
    global simulator_running
    if not simulator_running:
        simulator_running = True
        asyncio.create_task(run_traffic_simulator())
    return {"status": "running", "message": "Live traffic simulator started"}

@app.post("/api/simulator/stop")
async def stop_simulator():
    global simulator_running
    simulator_running = False
    return {"status": "stopped", "message": "Traffic simulator stopped"}

@app.get("/api/simulator/status")
def simulator_status():
    return {"simulator_running": simulator_running}
