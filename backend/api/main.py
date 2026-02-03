from pathlib import Path

from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Get the absolute path to the block-pages directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BLOCK_PAGES_DIR = BASE_DIR / "frontend" / "block-pages"
DASHBOARD_DIR = BASE_DIR / "frontend" / "dashboard"

app = FastAPI(title="DNS Threat Platform")

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

@app.get("/")
def root():
    return {"status": "DNS Threat Platform running"}

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
from backend.utils.events import log_event, get_events
from backend.utils.metrics import inc, get_metrics

@app.get("/model/status")
def model_status():
    return get_status()

@app.post("/dns/query")
def dns_query(data: dict):
    domain = data.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")
    ray_id = generate_ray_id()
    timestamp = current_timestamp()

    result = infer(domain)
    inc("total_queries")

    if result["score"] >= 0.9:
        action = "BLOCK"
        inc("blocked")
        log_event({
            "ray_id": ray_id,
            "domain": domain,
            "score": result["score"],
            "action": action,
            "timestamp": timestamp,
            "source": result.get("source", "baseline")
        })
        return {
            "action": action,
            "ray_id": ray_id,
            "timestamp": timestamp,
            "score": result["score"],
            "label": result.get("label"),
            "source": result.get("source", "baseline"),
            "redirect": f"/block/malicious?domain={domain}&ray_id={ray_id}"
        }

    if result["score"] >= 0.6:
        action = "WARN"
        inc("warnings")
        log_event({
            "ray_id": ray_id,
            "domain": domain,
            "score": result["score"],
            "action": action,
            "timestamp": timestamp,
            "source": result.get("source", "baseline")
        })
        return {
            "action": action,
            "ray_id": ray_id,
            "timestamp": timestamp,
            "score": result["score"],
            "label": result.get("label"),
            "source": result.get("source", "baseline"),
            "redirect": f"/block/warning?domain={domain}&ray_id={ray_id}"
        }

    action = "ALLOW"
    inc("allowed")
    log_event({
        "ray_id": ray_id,
        "domain": domain,
        "score": result["score"],
        "action": action,
        "timestamp": timestamp,
        "source": result.get("source", "baseline")
    })
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
    return get_metrics()
