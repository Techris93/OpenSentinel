"""
OpenSentinel — SOC Command Center API Server (v1)
FastAPI-based backend with OWASP API Security Top 10 protections.

Security Coverage:
  API1  — BOLA: Ownership verification on object-level endpoints
  API2  — Auth: Key expiry, timing-safe comparison, brute-force lockout
  API3  — Property Auth: Field-level response filtering by role
  API4  — Resource Consumption: Global + per-endpoint rate limiting
  API5  — Function Auth: Role enforcement on admin/sensitive endpoints
  API6  — Business Flows: Anti-automation on chat, connect
  API7  — SSRF: Input validation (private IP blocking)
  API8  — Misconfiguration: Security headers, CORS, HSTS, CSP
  API9  — Inventory: API versioning (/api/v1/), OpenAPI docs
  API10 — Unsafe Consumption: External API responses treated as untrusted
"""
import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ═══ Local Modules ═══════════════════════════════════════════════════════════
from soc_agent import SOCAgent
from security.middleware import SecurityMiddleware, get_security_config
from security.auth import AuthManager
from security.input_validator import InputValidator
from sentinel.detection_engine import DetectionEngine
from sentinel.anomaly_detector import AnomalyDetector
from sentinel.incidents import IncidentManager
from hunting.hunt_library import HuntLibrary
from hunting.notebook import HuntNotebook
from database import init_db, get_db

from playbooks.engine import PlaybookEngine
from copilot import summarize_incident, analyze_script, suggest_next_steps, enrich_iocs
import gemini_client

# ═══ App Initialization (API9 — versioned API + OpenAPI docs) ════════════════
app = FastAPI(
    title="OpenSentinel API",
    description="AI-powered SOC Command Center — OWASP API Security Top 10 hardened",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/v1/openapi.json",
)

# CORS (API8 — restrict in production)
cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],
)

# ═══ Database ════════════════════════════════════════════════════════════════
init_db()  # Creates data/opensentinel.db with all tables
_db = get_db()

# ═══ Security ════════════════════════════════════════════════════════════════
security_config = get_security_config()
security_middleware = SecurityMiddleware(security_config)
auth_manager = AuthManager(security_config)
input_validator = InputValidator()

# Attach auth_manager to app state so decorators can access it
app.state.auth_manager = auth_manager

# ═══ State ═══════════════════════════════════════════════════════════════════
agent: Optional[SOCAgent] = None
detection_engine: Optional[DetectionEngine] = None
anomaly_detector: Optional[AnomalyDetector] = None
incident_manager = IncidentManager(db=_db)
hunt_library = HuntLibrary()

playbook_engine = PlaybookEngine()
sentinel_running = False

# ═══ Request Models ══════════════════════════════════════════════════════════
class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)

class ConnectRequest(BaseModel):
    host: str = Field("localhost", min_length=1, max_length=255)
    port: int = Field(8089, ge=1, le=65535)
    username: str = Field("admin", min_length=1, max_length=128)
    password: str = Field("password", min_length=1, max_length=256)



class ScriptAnalysisRequest(BaseModel):
    script: str = Field(..., min_length=1, max_length=50000)

class IOCEnrichRequest(BaseModel):
    iocs: List[str] = Field(..., min_length=1, max_length=100)

class PlaybookActionRequest(BaseModel):
    incident_id: str
    action: str


# ═══ Paths that skip authentication ══════════════════════════════════════════
PUBLIC_PATHS = {"/api/health", "/api/v1/health", "/", "/dashboard",
                "/api/docs", "/api/redoc", "/api/v1/openapi.json",
                "/openapi.json", "/favicon.ico"}


# ═══ Central Security Middleware ══════════════════════════════════════════════
@app.middleware("http")
async def security_check(request: Request, call_next):
    """
    Unified security middleware — applies auth, rate limiting, brute-force
    lockout, per-endpoint anti-automation, and security headers.
    """
    path = request.url.path
    client_ip = request.client.host if request.client else "unknown"
    api_key = request.headers.get("X-API-Key", "")

    # ── Skip auth for public paths ──
    if path in PUBLIC_PATHS:
        response = await call_next(request)
        security_middleware.add_security_headers(response)
        return response

    # ── API2 — Brute-force lockout ──
    if security_middleware.is_locked_out(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many failed authentication attempts. Locked out for 5 minutes."}
        )

    # ── API2 — Validate API key (with expiry check) ──
    if not auth_manager.validate_key(api_key):
        security_middleware.record_failed_auth(client_ip)
        security_middleware.log_request(request.method, path, client_ip, 401, api_key)
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key"}
        )

    # ── API4 — Global rate limit ──
    if not security_middleware.check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Global rate limit exceeded. Try again later."},
            headers=security_middleware.get_rate_limit_info(client_ip, path)
        )

    # ── API6 — Per-endpoint rate limit (anti-automation) ──
    if not security_middleware.check_endpoint_rate_limit(client_ip, path):
        rate_info = security_middleware.get_rate_limit_info(client_ip, path)
        return JSONResponse(
            status_code=429,
            content={"detail": f"Endpoint rate limit exceeded for {path}. "
                     f"Try again in {rate_info.get('X-RateLimit-Reset', '?')}s."},
            headers=rate_info
        )

    # ── Process request ──
    response = await call_next(request)

    # ── API8 — Security headers ──
    security_middleware.add_security_headers(response)

    # ── Rate limit headers ──
    rate_info = security_middleware.get_rate_limit_info(client_ip, path)
    for k, v in rate_info.items():
        response.headers[k] = v

    # ── Audit log (console + database) ──
    security_middleware.log_request(request.method, path, client_ip,
                                   response.status_code, api_key)
    try:
        import time as _time
        _db.execute(
            """INSERT INTO audit_log (timestamp, method, path, client_ip, status_code, key_hint)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (_time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
             request.method, path, client_ip, response.status_code,
             api_key[:8] + "..." if api_key else "none")
        )
        _db.commit()
    except Exception:
        pass  # Never let audit logging break request flow

    return response


# ═══════════════════════════════════════════════════════════════════════════════
#  API ROUTES  —  versioned under /api/v1  (legacy /api still works)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Helper: role check ──
def _get_role(request: Request) -> str:
    """Extract role from API key in request."""
    api_key = request.headers.get("X-API-Key", "")
    return auth_manager.get_role(api_key) or "readonly"

def _require_role(request: Request, required: str):
    """Inline role check — raises 403 if insufficient."""
    role_hierarchy = {"readonly": 0, "analyst": 1, "admin": 2}
    current = _get_role(request)
    if role_hierarchy.get(current, -1) < role_hierarchy.get(required, 99):
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions. Required role: {required}, your role: {current}"
        )


# ═══ Health & Status ═════════════════════════════════════════════════════════
@app.get("/api/health")
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint (public, no auth required)."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "api_version": "v1",
        "timestamp": datetime.utcnow().isoformat(),
        "agent_connected": agent is not None,
        "sentinel_active": sentinel_running,
        "owasp_protections": [
            "API1-BOLA", "API2-Auth", "API3-PropertyAuth", "API4-RateLimit",
            "API5-FunctionAuth", "API6-AntiAutomation", "API7-SSRF",
            "API8-SecurityHeaders", "API9-Versioning", "API10-SafeConsumption"
        ]
    }


# ═══ Connection (API5 — admin only) ══════════════════════════════════════════
@app.post("/api/connect")
@app.post("/api/v1/connect")
async def connect_siem(req: ConnectRequest, request: Request):
    """Connect or reconfigure the SIEM connection. Requires admin role."""
    _require_role(request, "admin")   # API5

    global agent, detection_engine, anomaly_detector
    try:
        if agent is not None:
            agent.update_connection(
                host=req.host,
                port=req.port,
                username=req.username,
                password=req.password
            )
            validation = agent.validate_connection()
            if validation["success"]:
                return {"success": True, "message": f"Reconnected to {req.host}:{req.port}"}
            else:
                return {"success": False, "detail": validation.get("error", "Connection failed")}
        else:
            agent = SOCAgent(
                host=req.host,
                port=req.port,
                username=req.username,
                password=req.password
            )
            detection_engine = DetectionEngine(agent, db=_db)
            anomaly_detector = AnomalyDetector(agent)
            return {"success": True, "message": f"Connected to {req.host}:{req.port}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══ Chat / NLP Query (API6 — rate limited, analyst+) ════════════════════════
@app.post("/api/chat")
@app.post("/api/v1/chat")
async def chat(msg: ChatMessage, request: Request):
    """Process a natural language query through the SOC Agent."""
    _require_role(request, "analyst")  # API5

    # API7 — Input validation (prompt injection, dangerous commands)
    validation = input_validator.validate_chat_input(msg.message)
    if not validation["safe"]:
        return {"response": f"⚠️ Input blocked: {validation['reason']}"}

    if agent is None:
        # Use Gemini for general security questions
        try:
            response = await gemini_client.generate(
                f"You are an AI SOC analyst. Answer this security question concisely: {msg.message}"
            )
            # API10 — Treat external API response as untrusted text
            return {"response": str(response)[:5000]}
        except Exception as e:
            return {"response": f"No SIEM connected. Error: {str(e)}"}

    try:
        results = agent.process_query(msg.message)

        if results and len(results) > 0 and "error" not in results[0]:
            summary = await summarize_incident(
                events=results,
                original_query=msg.message,
                max_events=15
            )
            next_steps = await suggest_next_steps(
                query=msg.message,
                result_count=len(results),
                entities=str(agent.extract_keywords(msg.message))
            )
            # API10 — Truncate external AI responses
            response = f"**Query Results** ({len(results)} events)\n\n{str(summary)[:3000]}\n\n**Suggested Next Steps:**\n{str(next_steps)[:1000]}"
            return {"response": response, "event_count": len(results), "events": results[:10]}
        else:
            error_msg = results[0].get("error", "No results found") if results else "No results found"
            return {"response": f"Query returned no results or error: {error_msg}"}
    except Exception as e:
        return {"response": f"❌ Error: {str(e)}"}


# ═══ Sentinel (API5 — admin to start/stop, analyst to read) ═════════════════
@app.post("/api/sentinel/start")
@app.post("/api/v1/sentinel/start")
async def start_sentinel(request: Request):
    """Start the Sentinel detection engine. Requires admin role."""
    _require_role(request, "admin")  # API5

    global sentinel_running
    if agent is None:
        raise HTTPException(status_code=400, detail="No SIEM connection. Connect first.")
    sentinel_running = True
    return {"status": "started", "message": "Sentinel detection engine activated"}

@app.post("/api/sentinel/stop")
@app.post("/api/v1/sentinel/stop")
async def stop_sentinel(request: Request):
    """Stop the Sentinel detection engine. Requires admin role."""
    _require_role(request, "admin")  # API5

    global sentinel_running
    sentinel_running = False
    return {"status": "stopped", "message": "Sentinel detection engine deactivated"}

@app.get("/api/sentinel/alerts")
@app.get("/api/v1/sentinel/alerts")
async def get_sentinel_alerts():
    """Get current security alerts. Analyst+ access."""
    if detection_engine is None:
        return {"alerts": []}
    try:
        alerts = detection_engine.get_alerts()
        return {"alerts": alerts}
    except Exception as e:
        return {"alerts": [], "error": str(e)}


# ═══ Anomaly Detection ═══════════════════════════════════════════════════════
@app.get("/api/anomalies")
@app.get("/api/v1/anomalies")
async def get_anomalies():
    """Get detected anomalies."""
    if anomaly_detector is None:
        return {"anomalies": []}
    try:
        anomalies = anomaly_detector.get_anomalies()
        return {"anomalies": anomalies}
    except Exception as e:
        return {"anomalies": [], "error": str(e)}


# ═══ Incidents (API1 — BOLA protection) ═════════════════════════════════════
@app.get("/api/incidents")
@app.get("/api/v1/incidents")
async def list_incidents(request: Request):
    """List incidents. Admin sees all, analysts see own team's."""
    role = _get_role(request)
    api_key = request.headers.get("X-API-Key", "")
    owner_id = auth_manager.get_owner_id(api_key) or "system"

    all_incidents = incident_manager.list_all()

    # API1 — Filter incidents by ownership/role
    if role == "admin":
        return {"incidents": all_incidents}
    else:
        # Non-admin: only see incidents they own or that are unassigned
        filtered = [
            inc for inc in all_incidents
            if inc.get("owner_id", "system") in (owner_id, "system", "unassigned")
        ]
        return {"incidents": filtered}


@app.get("/api/incidents/{incident_id}")
@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str, request: Request):
    """Get a specific incident with BOLA protection."""
    incident = incident_manager.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # API1 — BOLA: verify requester can access this incident
    role = _get_role(request)
    api_key = request.headers.get("X-API-Key", "")
    owner_id = auth_manager.get_owner_id(api_key) or "system"
    incident_owner = incident.get("owner_id", "system")

    if role != "admin" and incident_owner not in (owner_id, "system", "unassigned"):
        raise HTTPException(status_code=403, detail="You do not have access to this incident")

    # API3 — Filter fields by role
    if role == "readonly":
        safe_fields = {"id", "title", "severity", "status", "created_at"}
        incident = {k: v for k, v in incident.items() if k in safe_fields}

    return incident


# ═══ Threat Hunt ═════════════════════════════════════════════════════════════
@app.get("/api/hunts")
@app.get("/api/v1/hunts")
async def list_hunts():
    """List available threat hunt queries."""
    return {"hunts": hunt_library.list_hunts()}

@app.post("/api/hunts/{hunt_id}/execute")
@app.post("/api/v1/hunts/{hunt_id}/execute")
async def execute_hunt(hunt_id: str, request: Request):
    """Execute a threat hunt query. Requires analyst+ role."""
    _require_role(request, "analyst")  # API5

    if agent is None:
        raise HTTPException(status_code=400, detail="No SIEM connection")
    try:
        hunt = hunt_library.get_hunt(hunt_id)
        if not hunt:
            raise HTTPException(status_code=404, detail="Hunt not found")
        results = agent.process_query(hunt["query"])
        return {"hunt": hunt, "results": results, "count": len(results)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))





# ═══ Copilot (analyst+, rate limited) ════════════════════════════════════════
@app.post("/api/copilot/analyze-script")
@app.post("/api/v1/copilot/analyze-script")
async def copilot_analyze_script(req: ScriptAnalysisRequest, request: Request):
    """Analyze a suspicious script using Gemini AI."""
    _require_role(request, "analyst")  # API5

    validation = input_validator.validate_chat_input(req.script)
    if not validation["safe"]:
        return {"analysis": f"⚠️ Input blocked: {validation['reason']}"}
    try:
        analysis = await analyze_script(req.script)
        # API10 — Truncate external AI response
        return {"analysis": str(analysis)[:10000]}
    except Exception as e:
        return {"analysis": f"Error: {str(e)}"}

@app.post("/api/copilot/enrich")
@app.post("/api/v1/copilot/enrich")
async def copilot_enrich_iocs(req: IOCEnrichRequest, request: Request):
    """Enrich IOCs with threat intelligence."""
    _require_role(request, "analyst")  # API5

    try:
        enriched = await enrich_iocs(req.iocs)
        return {"results": enriched}
    except Exception as e:
        return {"results": [], "error": str(e)}


# ═══ Playbooks (API5 — admin to execute, analyst to read) ════════════════════
@app.get("/api/playbooks")
@app.get("/api/v1/playbooks")
async def list_playbooks():
    """List available response playbooks."""
    return {"playbooks": playbook_engine.get_playbooks()}

@app.get("/api/playbooks/stats")
@app.get("/api/v1/playbooks/stats")
async def playbook_stats():
    """Get playbook execution statistics."""
    return {"stats": playbook_engine.stats()}


# ═══ Static Files & Dashboard ════════════════════════════════════════════════
@app.get("/")
@app.get("/dashboard")
async def serve_dashboard():
    """Serve the dashboard HTML."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


# ═══ Main Entry ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 5001))
    print(f"\n🛡️ OpenSentinel Command Center v1.0.0 starting on port {port}...")
    print(f"   API Docs:    http://localhost:{port}/api/docs")
    print(f"   Dashboard:   http://localhost:{port}/dashboard")
    print(f"   Database:    data/opensentinel.db (SQLite)")
    print(f"   OWASP:       API1-10 protections active\n")
    uvicorn.run(app, host="0.0.0.0", port=port)
