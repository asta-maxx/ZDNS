from pathlib import Path
import os

from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
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
# Serve frontend assets (logo, favicon)
app.mount(
    "/assets",
    StaticFiles(directory=str(BASE_DIR / "frontend")),
    name="assets"
)

def _start_auto_sync():
    interval = int(os.getenv("ZDNS_STIX_SYNC_INTERVAL_MIN", "0"))
    if interval <= 0:
        return

    def loop():
        while True:
            try:
                _sync_indicators()
            except Exception:
                pass
            time.sleep(interval * 60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

@app.on_event("startup")
def on_startup():
    _start_auto_sync()

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

@app.get("/dashboard/lists", response_class=HTMLResponse)
def dashboard_lists(request: Request):
    return dashboard_templates.TemplateResponse("lists.html", {"request": request})

@app.get("/dashboard/settings", response_class=HTMLResponse)
def dashboard_settings(request: Request):
    return dashboard_templates.TemplateResponse("settings.html", {"request": request})

@app.get("/dashboard/threat-intel", response_class=HTMLResponse)
def dashboard_threat_intel(request: Request):
    return dashboard_templates.TemplateResponse("threat-intel.html", {"request": request})

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
from backend.utils.rules import list_rules, create_rule, update_rule, delete_rule, evaluate_domain, export_rpz
from backend.utils.devices import list_devices, update_device, count_active_devices
from backend.models.train_model import main as train_model_main
from backend.utils.stix_store import (
    list_collections,
    get_collection,
    add_objects,
    get_objects,
    get_manifest,
    list_indicator_patterns,
)
from backend.utils.taxii_client import pull_taxii_objects
from backend.utils.threat_feeds import pull_otx_domains, pull_misp_domains
from backend.utils.list_sources import (
    list_sources as list_list_sources,
    create_source as create_list_source,
    update_source as update_list_source,
    delete_source as delete_list_source,
    pull_all_sources,
    list_status as list_sources_status,
)
from backend.utils.rules import upsert_rule_by_pattern

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
            "source": "threat_intel" if rule.get("source") == "threat_intel" else "admin",
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

@app.get("/rules/rpz", response_class=PlainTextResponse)
def rules_rpz(
    zone: str = "zdns.rpz",
    sinkhole: str | None = None,
    include_disabled: bool = False,
):
    sinkhole_value = sinkhole or os.getenv("ZDNS_RPZ_SINKHOLE", "sinkhole.zdns.local")
    text = export_rpz(zone_name=zone, sinkhole=sinkhole_value, include_disabled=include_disabled)
    return PlainTextResponse(text, media_type="text/plain")


@app.get("/lists")
def lists_sources():
    return list_list_sources()


@app.post("/lists")
def lists_create(data: dict):
    required = ["name", "list_type", "url"]
    for field in required:
        if not data.get(field):
            raise HTTPException(status_code=400, detail=f"{field} is required")
    return create_list_source(data)


@app.put("/lists/{source_id}")
def lists_update(source_id: int, data: dict):
    return update_list_source(source_id, data)


@app.delete("/lists/{source_id}")
def lists_delete(source_id: int):
    return {"deleted": delete_list_source(source_id)}


@app.post("/lists/pull")
def lists_pull():
    return pull_all_sources()


@app.get("/lists/status")
def lists_status():
    return list_sources_status()


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

def _require_taxii_key(request: Request):
    expected = os.getenv("ZDNS_TAXII_API_KEY", "zdns-dev-key")
    provided = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if not provided or provided != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


# TAXII 2.1 (minimal server)
@app.get("/taxii2")
def taxii_discovery(request: Request):
    _require_taxii_key(request)
    base = str(request.base_url).rstrip("/")
    return {
        "title": "ZDNS TAXII 2.1",
        "description": "ZDNS Threat Intelligence TAXII server",
        "default": f"{base}/taxii2/api1",
        "api_roots": [f"{base}/taxii2/api1"],
    }


@app.get("/taxii2/api1")
def taxii_api_root(request: Request):
    _require_taxii_key(request)
    return {
        "title": "ZDNS API Root",
        "versions": ["taxii-2.1"],
        "max_content_length": 10485760,
    }


@app.get("/taxii2/api1/collections")
def taxii_collections(request: Request):
    _require_taxii_key(request)
    return {"collections": list_collections()}


@app.get("/taxii2/api1/collections/{collection_id}")
def taxii_collection(request: Request, collection_id: str):
    _require_taxii_key(request)
    col = get_collection(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    return col


@app.get("/taxii2/api1/collections/{collection_id}/manifest")
def taxii_manifest(request: Request, collection_id: str):
    _require_taxii_key(request)
    return {"objects": get_manifest(collection_id)}


@app.get("/taxii2/api1/collections/{collection_id}/objects")
def taxii_objects(request: Request, collection_id: str, added_after: str | None = None, limit: int = 500):
    _require_taxii_key(request)
    objects = get_objects(collection_id, limit=limit, after=added_after)
    return {"objects": objects}


@app.post("/taxii2/api1/collections/{collection_id}/objects")
def taxii_add_objects(request: Request, collection_id: str, data: dict):
    _require_taxii_key(request)
    objects = data.get("objects", [])
    if not isinstance(objects, list):
        raise HTTPException(status_code=400, detail="objects must be a list")
    return add_objects(collection_id, objects)


@app.post("/taxii2/import")
def taxii_import_bundle(request: Request, data: dict):
    _require_taxii_key(request)
    collection_id = data.get("collection_id", "zdns-threat-intel")
    if data.get("type") != "bundle":
        raise HTTPException(status_code=400, detail="Expected STIX bundle")
    objects = data.get("objects", [])
    return add_objects(collection_id, objects)


@app.post("/taxii2/pull")
def taxii_pull(request: Request, data: dict):
    _require_taxii_key(request)
    url = data.get("url")
    api_root = data.get("api_root")
    collection_id = data.get("collection_id")
    headers = data.get("headers") or {}
    added_after = data.get("added_after")
    if not url or not collection_id:
        raise HTTPException(status_code=400, detail="url and collection_id are required")
    return pull_taxii_objects(url, api_root, collection_id, added_after=added_after, headers=headers)


@app.get("/stix/objects")
def stix_objects(limit: int = 200, only_indicators: bool = False):
    objects = get_objects("zdns-threat-intel", limit=limit)
    if only_indicators:
        objects = [o for o in objects if o.get("type") == "indicator"]
    return {"objects": objects}


def _sync_indicators() -> int:
    indicators = list_indicator_patterns("zdns-threat-intel")
    synced = 0
    for indicator in indicators:
        pattern = indicator.get("pattern", "")
        if "domain-name:value" not in pattern:
            continue
        try:
            domain = pattern.split("domain-name:value")[1].split("'")[1]
        except Exception:
            continue
        name = indicator.get("name") or "STIX Indicator"
        valid_until = indicator.get("valid_until") or indicator.get("expiration")
        rule = {
            "name": name,
            "pattern": domain,
            "match_type": "EXACT",
            "action": "BLOCK",
            "enabled": True,
            "priority": 50,
            "notes": "STIX Indicator",
            "source": "threat_intel",
            "expires_at": valid_until,
        }
        upsert_rule_by_pattern(rule)
        synced += 1
    return synced


@app.post("/stix/sync")
def stix_sync(request: Request):
    _require_taxii_key(request)
    return {"synced": _sync_indicators()}


@app.post("/feeds/otx/pull")
def otx_pull(request: Request, data: dict):
    _require_taxii_key(request)
    api_key = data.get("api_key")
    limit = int(data.get("limit", 1000))
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    result = pull_otx_domains(api_key, limit=limit)
    synced = _sync_indicators()
    return {"imported": result.get("added"), "synced": synced}


@app.post("/feeds/misp/pull")
def misp_pull(request: Request, data: dict):
    _require_taxii_key(request)
    base_url = data.get("base_url")
    api_key = data.get("api_key")
    limit = int(data.get("limit", 1000))
    if not base_url or not api_key:
        raise HTTPException(status_code=400, detail="base_url and api_key required")
    result = pull_misp_domains(base_url, api_key, limit=limit)
    synced = _sync_indicators()
    return {"imported": result.get("added"), "synced": synced}


@app.get("/{full_path:path}", response_class=HTMLResponse)
def sinkhole_block_page(request: Request, full_path: str):
    if full_path.startswith(("dashboard", "block", "static", "metrics", "events", "rules", "devices", "analytics", "model")):
        raise HTTPException(status_code=404, detail="Not found")

    host = request.headers.get("host", "")
    sinkhole = _render_sinkhole_for_host(request, host)
    if sinkhole is not None:
        return sinkhole

    raise HTTPException(status_code=404, detail="Not found")
import threading
import time
