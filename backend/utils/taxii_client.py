import requests
from typing import Dict, Optional
from urllib.parse import urljoin

from backend.utils.stix_store import add_objects


def pull_taxii_objects(
    url: str,
    api_root: Optional[str],
    collection_id: str,
    added_after: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
):
    hdrs = {"Accept": "application/taxii+json;version=2.1"}
    if headers:
        hdrs.update(headers)

    if not api_root:
        discovery = requests.get(url.rstrip("/"), headers=hdrs, timeout=10)
        discovery.raise_for_status()
        data = discovery.json()
        api_roots = data.get("api_roots") or []
        if not api_roots:
            raise ValueError("No api_roots found in TAXII discovery")
        api_root = api_roots[0]

    # If api_root is relative, join with discovery base URL
    if api_root.startswith("/"):
        api_root = urljoin(url, api_root)

    objects_url = f"{api_root.rstrip('/')}/collections/{collection_id}/objects/"
    params = {}
    if added_after:
        params["added_after"] = added_after

    resp = requests.get(objects_url, headers=hdrs, params=params, timeout=20)
    resp.raise_for_status()
    payload = resp.json()
    objects = payload.get("objects", [])
    return add_objects("zdns-threat-intel", objects)
