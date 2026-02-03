import json
import requests
from typing import Dict, List

from backend.utils.stix_store import add_objects, build_domain_indicator


def pull_otx_domains(api_key: str, limit: int = 1000) -> Dict:
    # AlienVault OTX export endpoint (domains only)
    url = "https://otx.alienvault.com/api/v1/indicators/export"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"type": "domain", "limit": limit}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    # OTX export is often plain text (newline-delimited), but may also be JSON.
    # Be defensive and handle either.
    domains: List[str] = []
    data = None
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = None

    if data is not None:
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    val = item.get("indicator") or item.get("domain") or item.get("value")
                    if val:
                        domains.append(str(val))
                elif isinstance(item, str):
                    domains.append(item)
        elif isinstance(data, dict):
            for item in data.get("results", []):
                val = item.get("indicator") or item.get("domain") or item.get("value")
                if val:
                    domains.append(str(val))
    else:
        # Plain text export: one indicator per line, sometimes CSV-ish.
        for line in resp.text.splitlines():
            val = line.strip()
            if not val:
                continue
            # If CSV-like, take the first token.
            if "," in val:
                val = val.split(",", 1)[0].strip()
            domains.append(val)

    indicators = [build_domain_indicator(d, source="otx") for d in domains]
    return add_objects("zdns-threat-intel", indicators)


def pull_misp_domains(base_url: str, api_key: str, limit: int = 1000) -> Dict:
    # MISP restSearch for domain indicators
    url = f"{base_url.rstrip('/')}/attributes/restSearch"
    headers = {"Authorization": api_key, "Accept": "application/json"}
    payload = {
        "type": ["domain", "hostname", "domain|ip"],
        "limit": limit,
        "returnFormat": "json",
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    attributes = data.get("response", {}).get("Attribute", []) or data.get("Attribute", [])
    domains: List[str] = []
    for attr in attributes:
        val = attr.get("value")
        if not val:
            continue
        # Handle domain|ip format
        if "|" in val:
            val = val.split("|")[0]
        domains.append(str(val))

    indicators = [build_domain_indicator(d, source="misp") for d in domains]
    return add_objects("zdns-threat-intel", indicators)
