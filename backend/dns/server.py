import os
import socket
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import requests
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE
from dnslib.server import DNSServer, BaseResolver, DNSLogger


DEFAULT_API_URL = "http://127.0.0.1:8000/dns/query"
DEFAULT_UPSTREAM = "1.1.1.1:53"
DEFAULT_SINKHOLE_IPV4 = "0.0.0.0"
DEFAULT_SINKHOLE_IPV6 = "::"


@dataclass
class DnsDecision:
    action: str
    score: float
    ray_id: str
    timestamp: str
    source: Optional[str] = None


def _parse_upstream(upstream: str) -> Tuple[str, int]:
    if ":" in upstream:
        host, port_str = upstream.rsplit(":", 1)
        return host.strip(), int(port_str)
    return upstream.strip(), 53


def _forward_udp(request: DNSRecord, upstream: Tuple[str, int], timeout: float) -> DNSRecord:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request.pack(), upstream)
        data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(data)
    finally:
        sock.close()


class ThreatResolver(BaseResolver):
    def __init__(self):
        self.api_url = os.getenv("DNS_THREAT_API", DEFAULT_API_URL)
        self.api_timeout = float(os.getenv("DNS_THREAT_TIMEOUT", "1.5"))
        self.upstream = _parse_upstream(os.getenv("DNS_UPSTREAM", DEFAULT_UPSTREAM))
        self.upstream_timeout = float(os.getenv("DNS_UPSTREAM_TIMEOUT", "2.0"))
        self.block_mode = os.getenv("DNS_BLOCK_MODE", "SINKHOLE").upper()
        self.warn_mode = os.getenv("DNS_WARN_MODE", "ALLOW").upper()
        self.fail_open = os.getenv("DNS_FAIL_OPEN", "true").lower() == "true"
        self.sinkhole_ipv4 = os.getenv("DNS_SINKHOLE_IPV4", DEFAULT_SINKHOLE_IPV4)
        self.sinkhole_ipv6 = os.getenv("DNS_SINKHOLE_IPV6", DEFAULT_SINKHOLE_IPV6)

    def _classify(self, domain: str, client_ip: Optional[str], qtype: str) -> DnsDecision:
        payload = {
            "domain": domain,
            "client_ip": client_ip,
            "qtype": qtype,
        }
        try:
            resp = requests.post(self.api_url, json=payload, timeout=self.api_timeout)
            resp.raise_for_status()
            data = resp.json()
            return DnsDecision(
                action=data.get("action", "ALLOW"),
                score=float(data.get("score", 0.0)),
                ray_id=data.get("ray_id", "RAY-unknown"),
                timestamp=data.get("timestamp", ""),
                source=data.get("source"),
            )
        except Exception:
            if self.fail_open:
                return DnsDecision(action="ALLOW", score=0.0, ray_id="RAY-fail-open", timestamp="")
            return DnsDecision(action="BLOCK", score=1.0, ray_id="RAY-fail-closed", timestamp="")

    def _sinkhole_reply(self, request: DNSRecord, qtype: str) -> DNSRecord:
        reply = request.reply()
        if qtype in ("A", "ANY"):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.sinkhole_ipv4), ttl=30))
        if qtype in ("AAAA", "ANY"):
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(self.sinkhole_ipv6), ttl=30))
        if qtype not in ("A", "AAAA", "ANY"):
            reply.header.rcode = RCODE.NOERROR
        return reply

    def resolve(self, request: DNSRecord, handler):  # type: ignore[override]
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        domain = str(qname).rstrip(".")
        client_ip = None
        if handler and hasattr(handler, "client_address"):
            client_ip = handler.client_address[0]

        decision = self._classify(domain, client_ip, qtype)
        action = decision.action.upper()

        if action == "BLOCK":
            if self.block_mode == "NXDOMAIN":
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                return reply
            return self._sinkhole_reply(request, qtype)

        if action == "WARN":
            if self.warn_mode == "SINKHOLE":
                return self._sinkhole_reply(request, qtype)
            if self.warn_mode == "NXDOMAIN":
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

        try:
            return _forward_udp(request, self.upstream, self.upstream_timeout)
        except Exception:
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def run_server():
    host = os.getenv("DNS_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("DNS_LISTEN_PORT", "53"))
    resolver = ThreatResolver()
    logger = DNSLogger(prefix=False)
    udp_server = DNSServer(resolver, port=port, address=host, logger=logger)
    tcp_server = DNSServer(resolver, port=port, address=host, logger=logger, tcp=True)
    udp_server.start_thread()
    tcp_server.start_thread()

    print(f"ZDNS server listening on {host}:{port}")
    print(f"Upstream resolver: {resolver.upstream[0]}:{resolver.upstream[1]}")
    print(f"Threat API: {resolver.api_url}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run_server()
