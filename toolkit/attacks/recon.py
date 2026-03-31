"""
recon.py - Passive mDNS reconnaissance.

Silently monitors all mDNS traffic on the link and builds a map of:
  - Hostnames and IP addresses
  - Services (PTR/SRV/TXT)
  - Device presence (probes, goodbyes)
  - Query patterns (what each host is looking for)

Sends zero packets. Completely undetectable.
"""

import time
import json
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, recv_mdns, parse_packet,
                       A, AAAA, PTR, SRV, TXT, HINFO)


class NetworkMap:
    def __init__(self):
        self.hosts = defaultdict(lambda: {
            "ips_v4": set(),
            "ips_v6": set(),
            "names": set(),
            "services_published": [],
            "services_queried": set(),
            "first_seen": None,
            "last_seen": None,
            "probes": [],
            "goodbyes": [],
        })
        self.services = defaultdict(list)  # service_type -> [instances]
        self.queries_seen = []

    def _touch(self, src_ip: str):
        h = self.hosts[src_ip]
        now = time.time()
        if h["first_seen"] is None:
            h["first_seen"] = now
        h["last_seen"] = now

    def process_packet(self, data: bytes, src_ip: str, src_port: int):
        pkt = parse_packet(data)
        if not pkt:
            return
        self._touch(src_ip)

        # Questions reveal what the host is interested in
        for q in pkt["questions"]:
            self.hosts[src_ip]["services_queried"].add(q["name"])
            self.queries_seen.append({
                "time": time.time(), "src": src_ip,
                "name": q["name"], "type": q["type"], "qu": q["qu"]
            })

        # Process all record sections
        for section in ("answers", "authority", "additional"):
            for rec in pkt[section]:
                self._process_record(rec, src_ip, pkt)

    def _process_record(self, rec: dict, src_ip: str, pkt: dict):
        rtype = rec["type_int"]
        name = rec["name"]
        ttl = rec["ttl"]

        if rtype == A and "rdata" in rec:
            ip = rec["rdata"]
            self.hosts[src_ip]["ips_v4"].add(ip)
            self.hosts[src_ip]["names"].add(name)
            if ttl == 0:
                self.hosts[src_ip]["goodbyes"].append({"name": name, "time": time.time()})

        elif rtype == AAAA and "rdata" in rec:
            self.hosts[src_ip]["ips_v6"].add(rec["rdata"])
            self.hosts[src_ip]["names"].add(name)

        elif rtype == PTR and "rdata" in rec:
            self.services[name].append({
                "instance": rec["rdata"], "src": src_ip, "ttl": ttl
            })

        elif rtype == SRV and "rdata" in rec:
            srv = rec["rdata"]
            self.hosts[src_ip]["services_published"].append({
                "name": name, "target": srv["target"],
                "port": srv["port"], "ttl": ttl
            })

        elif rtype == TXT and "rdata" in rec:
            pass  # Stored alongside SRV in service discovery

        # Detect probes (queries with authority section records)
        if not pkt["is_response"]:
            for auth in pkt["authority"]:
                self.hosts[src_ip]["probes"].append({
                    "name": auth["name"], "type": auth["type"], "time": time.time()
                })

    def summary(self) -> str:
        lines = ["\n╔══════════════════════════════════════════════════════════════╗",
                 "║                  mDNS NETWORK RECONNAISSANCE                ║",
                 "╚══════════════════════════════════════════════════════════════╝\n"]

        lines.append(f"  Hosts discovered: {len(self.hosts)}")
        lines.append(f"  Service types:    {len(self.services)}")
        lines.append(f"  Queries observed: {len(self.queries_seen)}\n")

        for src_ip, info in sorted(self.hosts.items()):
            lines.append(f"  ┌─ Host: {src_ip}")
            if info["names"]:
                lines.append(f"  │  Names:    {', '.join(sorted(info['names']))}")
            if info["ips_v4"]:
                lines.append(f"  │  IPv4:     {', '.join(sorted(info['ips_v4']))}")
            if info["ips_v6"]:
                lines.append(f"  │  IPv6:     {', '.join(sorted(info['ips_v6']))}")
            if info["services_published"]:
                for svc in info["services_published"]:
                    lines.append(f"  │  Service:  {svc['name']} -> {svc['target']}:{svc['port']}")
            if info["services_queried"]:
                for q in sorted(info["services_queried"]):
                    lines.append(f"  │  Queries:  {q}")
            if info["probes"]:
                lines.append(f"  │  Probes:   {len(info['probes'])} seen")
            if info["goodbyes"]:
                lines.append(f"  │  Goodbyes: {len(info['goodbyes'])} seen")

            duration = (info["last_seen"] or 0) - (info["first_seen"] or 0)
            lines.append(f"  │  Active:   {duration:.0f}s")
            lines.append(f"  └─")

        if self.services:
            lines.append("\n  ── Service Types ──")
            for stype, instances in sorted(self.services.items()):
                unique = set(i["instance"] for i in instances)
                lines.append(f"  {stype}")
                for inst in sorted(unique):
                    lines.append(f"    └─ {inst}")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Serialize for machine consumption."""
        def serialize(obj):
            if isinstance(obj, set):
                return sorted(obj)
            return obj
        return json.dumps({"hosts": dict(self.hosts), "services": dict(self.services)},
                          default=serialize, indent=2)


def run(iface: str | None = None, duration: int = 30, quiet: bool = False):
    """Run passive recon for `duration` seconds."""
    sock = make_mdns_socket(iface)
    sock.settimeout(1.0)
    netmap = NetworkMap()
    start = time.time()

    if not quiet:
        print(f"[*] Passive mDNS recon started (duration={duration}s)")
        print(f"[*] Listening on {iface or 'all interfaces'}...")

    try:
        while time.time() - start < duration:
            try:
                data, (src_ip, src_port) = sock.recvfrom(9000)
                netmap.process_packet(data, src_ip, src_port)
                if not quiet:
                    pkt = parse_packet(data)
                    if pkt:
                        kind = "RESP" if pkt["is_response"] else "QUERY"
                        names = [q["name"] for q in pkt["questions"]]
                        names += [r["name"] for r in pkt["answers"]]
                        print(f"  [{kind}] {src_ip} -> {', '.join(names[:3])}")
            except OSError:
                continue
    except KeyboardInterrupt:
        pass

    print(netmap.summary())
    sock.close()
    return netmap
