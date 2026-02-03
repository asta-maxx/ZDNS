import os
from datetime import datetime

import requests
from mitmproxy import http

API_BASE = os.getenv("DNS_THREAT_API_BASE", "http://127.0.0.1")
API_PORT = os.getenv("DNS_THREAT_API_PORT", "80")


def _call_decision(host: str, client_ip: str) -> dict:
    url = f"{API_BASE}:{API_PORT}/dns/query"
    try:
        resp = requests.post(url, json={"domain": host, "client_ip": client_ip}, timeout=2)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {"action": "ALLOW"}


def _fetch_block_page(path: str) -> bytes:
    url = f"{API_BASE}:{API_PORT}{path}"
    try:
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            return resp.content
    except Exception:
        pass
    return b"<h1>Blocked</h1>"


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.host
    path = flow.request.path or "/"
    client_ip = flow.client_conn.address[0] if flow.client_conn and flow.client_conn.address else ""

    if path.startswith("/static/"):
        asset = _fetch_block_page(path)
        flow.response = http.Response.make(
            200,
            asset,
            {"Content-Type": _guess_content_type(path)},
        )
        return

    decision = _call_decision(host, client_ip)
    action = decision.get("action", "ALLOW")

    if action == "BLOCK":
        ray_id = decision.get("ray_id", "RAY-unknown")
        html = _fetch_block_page(f"/block/malicious?domain={host}&ray_id={ray_id}")
        flow.response = http.Response.make(
            451,
            html,
            {"Content-Type": "text/html; charset=utf-8"},
        )
        return

    if action == "WARN":
        ray_id = decision.get("ray_id", "RAY-unknown")
        html = _fetch_block_page(f"/block/warning?domain={host}&ray_id={ray_id}")
        flow.response = http.Response.make(
            200,
            html,
            {"Content-Type": "text/html; charset=utf-8"},
        )


def _guess_content_type(path: str) -> str:
    if path.endswith(".css"):
        return "text/css; charset=utf-8"
    if path.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if path.endswith(".png"):
        return "image/png"
    if path.endswith(".jpg") or path.endswith(".jpeg"):
        return "image/jpeg"
    if path.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"
