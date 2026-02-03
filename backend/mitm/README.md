MITM HTTPS Block Page (Lab Only)

This adds HTTPS block pages using mitmproxy. It requires installing a custom CA
certificate on the client, which is how enterprise proxies work. Use only on
networks and devices you own or have explicit permission to test.

High-level flow:
1) DNS sinkhole sends blocked/warned domains to the VM IP.
2) mitmproxy terminates TLS and serves the HTML block page.
3) Client trusts the mitmproxy CA, so the browser shows the page without TLS errors.

Install mitmproxy on the VM:
- sudo apt update
- sudo apt install -y mitmproxy

Run mitmproxy (transparent listener on 443 -> mitm proxy on 8080):
- sudo sysctl -w net.ipv4.ip_forward=1
- sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
- sudo mitmproxy --mode transparent --listen-port 8080 -s backend/mitm/mitm_block.py

Client setup (macOS):
1) Open mitmproxy on the Mac via browser:
   - http://mitm.it
2) Install the macOS CA certificate.
3) Trust the cert:
   - Keychain Access -> System -> Certificates -> mitmproxy -> Always Trust

Notes:
- Keep DNS_WARN_MODE=SINKHOLE for warning pages.
- For BLOCK, use NXDOMAIN (DNS) or keep SINKHOLE if you want the block page.
- If you want HTTPS pages for BLOCK too, use SINKHOLE for BLOCK (DNS_BLOCK_MODE=SINKHOLE).
