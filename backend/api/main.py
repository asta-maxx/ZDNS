from pathlib import Path

from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Get the absolute path to the block-pages directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BLOCK_PAGES_DIR = BASE_DIR / "frontend" / "block-pages"
DASHBOARD_DIR = BASE_DIR / "frontend" / "dashboard"

app = FastAPI(title="ZDNS")

# Point templates to frontend/block-pages
templates = Jinja2Templates(directory=str(BLOCK_PAGES_DIR))

# Dashboard templates
dashboard_templates = Jinja2Templates(directory=str(DASHBOARD_DIR))

# Serve static assets (CSS, JS, images)
app.mount(
    "/static",
    StaticFiles(directory=str(BLOCK_PAGES_DIR / "static")),
    name="static"
)

def _render_sinkhole_for_host(request: Request, host: str):
    domain = host.split(":")[0].lower()
    if not domain or domain in ("localhost", "127.0.0.1"):
        return None

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM events WHERE domain = ? ORDER BY timestamp DESC LIMIT 1",
        (domain,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return templates.TemplateResponse(
            "dns-error.html",
            {
                "request": request,
                "domain": domain,
                "error_code": "NO_DECISION",
                "timestamp": current_timestamp(),
                "ray_id": "RAY-unknown",
                "edge_loc": "EDGE"
            },
            status_code=404,
        )

    action = row["action"]
    ray_id = row["ray_id"]
    client_ip = row["client_ip"] or request.client.host
    decision_source = row["source"] or "unknown"
    decision_label = row["label"] or "Threat"
    if action == "BLOCK":
        return templates.TemplateResponse(
            "blocked.html",
            {
                "request": request,
                "domain": domain,
                "ray_id": ray_id,
                "edge_loc": "EDGE",
                "client_ip": client_ip,
                "category": decision_label,
                "rule_id": row["rule_id"] or "MODEL",
                "decision_source": decision_source,
                "timestamp": row["timestamp"]
            },
        )
    if action == "WARN":
        return templates.TemplateResponse(
            "warning.html",
            {
                "request": request,
                "domain": domain,
                "category": decision_label if decision_label else "Suspicious",
                "risk_score": row["score"],
                "client_ip": client_ip,
                "ray_id": ray_id,
                "decision_source": decision_source,
                "timestamp": row["timestamp"]
            },
        )
    return None


@app.get("/")
def root(request: Request):
    host = request.headers.get("host", "")
    sinkhole = _render_sinkhole_for_host(request, host)
    if sinkhole is not None:
        return sinkhole
    return {"status": "ZDNS running"}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return dashboard_templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard/analytics", response_class=HTMLResponse)
def dashboard_analytics(request: Request):
    return dashboard_templates.TemplateResponse("analytics.html", {"request": request})

@app.get("/dashboard/rules", response_class=HTMLResponse)
def dashboard_rules(request: Request):
    return dashboard_templates.TemplateResponse("rules.html", {"request": request})

@app.get("/dashboard/settings", response_class=HTMLResponse)
def dashboard_settings(request: Request):
    return dashboard_templates.TemplateResponse("settings.html", {"request": request})

@app.get("/block/malicious", response_class=HTMLResponse)
def block_malicious(
    request: Request,
    domain: str = Query("unknown"),
    ray_id: str = Query("RAY-unknown")
):
    return templates.TemplateResponse(
        "blocked.html",
        {
            "request": request,
            "domain": domain,
            "ray_id": ray_id,
            "edge_loc": "BLR",
            "client_ip": "192.168.1.10",
            "category": "DGA Malware",
            "rule_id": "DGA-TCN-009",
            "timestamp": "2026-01-29 19:40 IST"
        }
    )

@app.get("/block/warning", response_class=HTMLResponse)
def block_warning(
    request: Request,
    domain: str = Query("unknown"),
    ray_id: str = Query("RAY-unknown")
):
    return templates.TemplateResponse(
        "warning.html",
        {
            "request": request,
            "domain": domain,
            "category": "Unusual Entropy",
            "risk_score": 0.71,
            "client_ip": "192.168.1.10",
            "ray_id": ray_id,
            "timestamp": "2026-01-29 19:42 IST"
        }
    )

@app.get("/block/error", response_class=HTMLResponse)
def dns_error(
    request: Request,
    domain: str = Query("unknown"),
    ray_id: str = Query("RAY-unknown")
):
    return templates.TemplateResponse(
        "dns-error.html",
        {
            "request": request,
            "domain": domain,
            "error_code": "NXDOMAIN",
            "timestamp": "2026-01-29 19:43 IST",
            "ray_id": ray_id,
            "edge_loc": "BLR"
        }
    )

@app.get("/block/maintenance", response_class=HTMLResponse)
def maintenance(request: Request):
    return templates.TemplateResponse(
        "maintenance.html",
        {
            "request": request,
            "duration": "15 minutes",
            "ray_id": "RAY-00ab19c",
            "timestamp": "2026-01-29 19:45 IST"
        }
    )

from backend.inference.model import infer, get_status
from backend.utils.tracing import generate_ray_id, current_timestamp
from backend.utils.events import log_event, get_events, get_db
from backend.utils.metrics import inc, get_metrics
from backend.utils.rules import list_rules, create_rule, update_rule, delete_rule, evaluate_domain
from backend.utils.devices import list_devices, update_device, count_active_devices
from backend.models.train_model import main as train_model_main

@app.get("/model/status")
def model_status():
    return get_status()

@app.post("/dns/query")
def dns_query(data: dict):
    domain = data.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")
    client_ip = data.get("client_ip")
    qtype = data.get("qtype")
    ray_id = generate_ray_id()
    timestamp = current_timestamp()

    rule = evaluate_domain(domain)
    if rule:
        result = {
            "label": "ADMIN_RULE",
            "score": 1.0 if rule["action"] == "BLOCK" else 0.7 if rule["action"] == "WARN" else 0.0,
            "source": "admin",
        }
        action = rule["action"]
    else:
        result = infer(domain)
        action = None
    inc("total_queries")

    if action is None and result["score"] >= 0.9:
        action = "BLOCK"
        inc("blocked")
    elif action is None and result["score"] >= 0.6:
        action = "WARN"
        inc("warnings")
    elif action is None:
        action = "ALLOW"
        inc("allowed")

    update_device(client_ip, action)

    log_event({
        "ray_id": ray_id,
        "domain": domain,
        "score": result["score"],
        "action": action,
        "timestamp": timestamp,
        "source": result.get("source", "baseline"),
        "client_ip": client_ip,
        "rule_id": rule["id"] if rule else None,
        "rule_action": rule["action"] if rule else None,
        "label": result.get("label"),
        "qtype": qtype,
    })
    if action == "BLOCK":
        return {
            "action": action,
            "ray_id": ray_id,
            "timestamp": timestamp,
            "score": result["score"],
            "label": result.get("label"),
            "source": result.get("source", "baseline"),
            "redirect": f"/block/malicious?domain={domain}&ray_id={ray_id}"
        }

    if action == "WARN":
        return {
            "action": action,
            "ray_id": ray_id,
            "timestamp": timestamp,
            "score": result["score"],
            "label": result.get("label"),
            "source": result.get("source", "baseline"),
            "redirect": f"/block/warning?domain={domain}&ray_id={ray_id}"
        }

    return {
        "action": action,
        "ray_id": ray_id,
        "timestamp": timestamp,
        "score": result["score"],
        "label": result.get("label"),
        "source": result.get("source", "baseline")
    }


@app.get("/events")
def events():
    return get_events()


@app.get("/metrics")
def metrics():
    data = dict(get_metrics())
    data["active_devices"] = count_active_devices()
    return data


@app.get("/rules")
def rules_list():
    return list_rules()


@app.post("/rules")
def rules_create(data: dict):
    required = ["name", "pattern", "match_type", "action"]
    for field in required:
        if not data.get(field):
            raise HTTPException(status_code=400, detail=f"{field} is required")
    return create_rule(data)


@app.put("/rules/{rule_id}")
def rules_update(rule_id: int, data: dict):
    return update_rule(rule_id, data)


@app.delete("/rules/{rule_id}")
def rules_delete(rule_id: int):
    return {"deleted": delete_rule(rule_id)}


@app.get("/devices")
def devices_list():
    return list_devices()


@app.get("/analytics")
def analytics():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT domain, COUNT(*) as total FROM events GROUP BY domain ORDER BY total DESC LIMIT 10")
    top_domains = [{"domain": row["domain"], "count": row["total"]} for row in cursor.fetchall()]
    cursor.execute("SELECT action, COUNT(*) as total FROM events GROUP BY action")
    actions = {row["action"]: row["total"] for row in cursor.fetchall()}
    conn.close()
    return {
        "top_domains": top_domains,
        "action_breakdown": actions
    }


@app.post("/model/train")
def train_model():
    try:
        train_model_main()
        return {"status": "ok", "message": "Model trained and saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/{full_path:path}", response_class=HTMLResponse)
def sinkhole_block_page(request: Request, full_path: str):
    if full_path.startswith(("dashboard", "block", "static", "metrics", "events", "rules", "devices", "analytics", "model")):
        raise HTTPException(status_code=404, detail="Not found")

    host = request.headers.get("host", "")
    sinkhole = _render_sinkhole_for_host(request, host)
    if sinkhole is not None:
        return sinkhole

    raise HTTPException(status_code=404, detail="Not found")
