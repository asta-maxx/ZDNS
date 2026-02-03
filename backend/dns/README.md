DNS Data Plane (Python)

This module runs a minimal DNS server that forwards queries to the threat API
and then either resolves upstream, returns NXDOMAIN, or sinkholes the response.

Run:
- Set the API host (if the FastAPI app runs elsewhere):
  - export DNS_THREAT_API="http://127.0.0.1:8000/dns/query"
- Choose upstream resolver (default: 1.1.1.1:53):
  - export DNS_UPSTREAM="8.8.8.8:53"
- Start server (needs port 53 access):
  - python backend/dns/server.py

Behavior:
- BLOCK: DNS_BLOCK_MODE=SINKHOLE (default) or NXDOMAIN
- WARN: DNS_WARN_MODE=ALLOW (default), SINKHOLE, or NXDOMAIN
- Fail-open: DNS_FAIL_OPEN=true (default); set false to fail-closed

Sinkhole IPs:
- DNS_SINKHOLE_IPV4=0.0.0.0
- DNS_SINKHOLE_IPV6=::
