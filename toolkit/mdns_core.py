"""
mdns_core.py - Low-level mDNS packet crafting and socket management.

Builds DNS packets from scratch using struct. No dependency on scapy or
dnslib so the toolkit stays lightweight and runs inside minimal containers.
"""

import socket
import struct
import time
import os
import fcntl

# ── Constants ────────────────────────────────────────────────────────────────

MDNS_ADDR  = "224.0.0.251"
MDNS_PORT  = 5353

# DNS record types
A     = 1
PTR   = 12
HINFO = 13
TXT   = 16
AAAA  = 28
SRV   = 33
OPT   = 41
ANY   = 255

# DNS classes
IN          = 1
CACHE_FLUSH = 0x8001        # IN class with cache-flush bit set

# Flags
QR_RESPONSE   = 0x8400      # QR=1, AA=1
QR_QUERY      = 0x0000
QU_BIT        = 0x8000      # unicast-response requested
TC_BIT        = 0x0200      # truncated


# ── Name encoding / decoding ────────────────────────────────────────────────

def encode_name(name: str) -> bytes:
    """Encode a DNS name into wire format (no compression)."""
    parts = name.rstrip(".").split(".")
    out = b""
    for label in parts:
        encoded = label.encode("utf-8")
        if len(encoded) > 63:
            raise ValueError(f"Label too long: {label}")
        out += struct.pack("B", len(encoded)) + encoded
    out += b"\x00"
    return out


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, handling compression pointers."""
    labels = []
    jumped = False
    original_offset = offset
    max_offset = offset

    for _ in range(128):  # safety limit
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            if not jumped:
                max_offset = offset + 1
            break

        # compression pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                max_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(data[offset:offset+length].decode("utf-8", errors="replace"))
        offset += length

    return ".".join(labels) + ".", max_offset if not jumped else max_offset


# ── Record data helpers ─────────────────────────────────────────────────────

def rdata_a(ip: str) -> bytes:
    return socket.inet_aton(ip)


def rdata_aaaa(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def rdata_ptr(name: str) -> bytes:
    return encode_name(name)


def rdata_srv(priority: int, weight: int, port: int, target: str) -> bytes:
    return struct.pack("!HHH", priority, weight, port) + encode_name(target)


def rdata_txt(kv: dict[str, str] | list[str]) -> bytes:
    """Encode TXT record. Accepts dict of k=v or list of strings."""
    out = b""
    if isinstance(kv, dict):
        items = [f"{k}={v}" for k, v in kv.items()]
    else:
        items = kv
    for item in items:
        encoded = item.encode("utf-8")
        out += struct.pack("B", len(encoded)) + encoded
    if not out:
        out = b"\x00"  # empty TXT record still needs a zero-length string
    return out


# ── Packet building ─────────────────────────────────────────────────────────

class DNSPacket:
    """Builds a raw DNS/mDNS packet."""

    def __init__(self, tx_id: int = 0, flags: int = QR_RESPONSE):
        self.tx_id = tx_id
        self.flags = flags
        self.questions: list[bytes] = []
        self.answers: list[bytes] = []
        self.authority: list[bytes] = []
        self.additional: list[bytes] = []

    # ── Adding sections ──────────────────────────────────────────────────

    def add_question(self, name: str, qtype: int = A, qclass: int = IN):
        self.questions.append(encode_name(name) + struct.pack("!HH", qtype, qclass))
        return self

    def add_answer(self, name: str, rtype: int, rdata: bytes,
                   ttl: int = 120, rclass: int = IN):
        self.answers.append(self._encode_rr(name, rtype, rclass, ttl, rdata))
        return self

    def add_authority(self, name: str, rtype: int, rdata: bytes,
                      ttl: int = 120, rclass: int = IN):
        self.authority.append(self._encode_rr(name, rtype, rclass, ttl, rdata))
        return self

    def add_additional(self, name: str, rtype: int, rdata: bytes,
                       ttl: int = 120, rclass: int = IN):
        self.additional.append(self._encode_rr(name, rtype, rclass, ttl, rdata))
        return self

    @staticmethod
    def _encode_rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
        header = encode_name(name) + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata))
        return header + rdata

    # ── Serialization ────────────────────────────────────────────────────

    def build(self) -> bytes:
        header = struct.pack("!HHHHHH",
                             self.tx_id,
                             self.flags,
                             len(self.questions),
                             len(self.answers),
                             len(self.authority),
                             len(self.additional))
        body = b""
        for section in (self.questions, self.answers, self.authority, self.additional):
            for entry in section:
                body += entry
        return header + body


# ── Convenience packet builders ─────────────────────────────────────────────

def build_response(name: str, rtype: int, rdata: bytes,
                   ttl: int = 120, cache_flush: bool = False) -> bytes:
    """Build a simple single-record mDNS response."""
    rclass = CACHE_FLUSH if cache_flush else IN
    pkt = DNSPacket(flags=QR_RESPONSE)
    pkt.add_answer(name, rtype, rdata, ttl=ttl, rclass=rclass)
    return pkt.build()


def build_query(name: str, qtype: int = A, qu: bool = False) -> bytes:
    """Build a simple single-question mDNS query."""
    qclass = IN | QU_BIT if qu else IN
    pkt = DNSPacket(flags=QR_QUERY)
    pkt.add_question(name, qtype, qclass)
    return pkt.build()


def build_goodbye(name: str, rtype: int, rdata: bytes) -> bytes:
    """Build a goodbye packet (TTL=0) for a specific record."""
    return build_response(name, rtype, rdata, ttl=0, cache_flush=False)


def build_probe(name: str, rtype: int, rdata: bytes,
                ttl: int = 120, rclass: int = IN) -> bytes:
    """Build a probe query with the proposed record in the authority section."""
    pkt = DNSPacket(flags=QR_QUERY)
    pkt.add_question(name, ANY, IN | QU_BIT)
    pkt.add_authority(name, rtype, rdata, ttl=ttl, rclass=rclass)
    return pkt.build()


def build_service_announcement(service_type: str, instance_name: str,
                               hostname: str, ip: str, port: int,
                               txt: dict[str, str] | None = None,
                               ttl: int = 4500) -> bytes:
    """Build a complete service announcement (PTR + SRV + TXT + A)."""
    fqdn = f"{instance_name}.{service_type}.local."
    pkt = DNSPacket(flags=QR_RESPONSE)
    # PTR (shared, no cache-flush)
    pkt.add_answer(f"{service_type}.local.", PTR, rdata_ptr(fqdn), ttl=ttl, rclass=IN)
    # SRV (unique, cache-flush)
    pkt.add_answer(fqdn, SRV, rdata_srv(0, 0, port, f"{hostname}.local."),
                   ttl=ttl, rclass=CACHE_FLUSH)
    # TXT
    pkt.add_answer(fqdn, TXT, rdata_txt(txt or {}), ttl=ttl, rclass=CACHE_FLUSH)
    # A record for the hostname
    pkt.add_additional(f"{hostname}.local.", A, rdata_a(ip), ttl=ttl, rclass=CACHE_FLUSH)
    return pkt.build()


# ── Packet parsing (for recon / sniffing) ───────────────────────────────────

RTYPE_NAMES = {A: "A", PTR: "PTR", TXT: "TXT", AAAA: "AAAA", SRV: "SRV",
               HINFO: "HINFO", ANY: "ANY", OPT: "OPT"}


def parse_packet(data: bytes) -> dict | None:
    """Parse an mDNS packet into a structured dict. Returns None on malformed."""
    if len(data) < 12:
        return None
    tx_id, flags, qcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    result = {
        "id": tx_id,
        "flags": flags,
        "is_response": bool(flags & 0x8000),
        "is_truncated": bool(flags & TC_BIT),
        "questions": [],
        "answers": [],
        "authority": [],
        "additional": [],
    }

    try:
        for _ in range(qcount):
            name, offset = decode_name(data, offset)
            qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
            offset += 4
            result["questions"].append({
                "name": name, "type": RTYPE_NAMES.get(qtype & 0x7FFF, str(qtype)),
                "type_int": qtype & 0x7FFF,
                "qu": bool(qclass & QU_BIT),
                "class": qclass & 0x7FFF,
            })

        for section_name, count in [("answers", ancount), ("authority", nscount),
                                     ("additional", arcount)]:
            for _ in range(count):
                name, offset = decode_name(data, offset)
                rtype, rclass, ttl, rdlen = struct.unpack("!HHiH", data[offset:offset+10])
                offset += 10
                rd = data[offset:offset+rdlen]
                offset += rdlen

                rec = {
                    "name": name,
                    "type": RTYPE_NAMES.get(rtype, str(rtype)),
                    "type_int": rtype,
                    "class": rclass & 0x7FFF,
                    "cache_flush": bool(rclass & 0x8000),
                    "ttl": ttl,
                    "rdlen": rdlen,
                    "rdata_raw": rd,
                }

                # Decode common types
                if rtype == A and rdlen == 4:
                    rec["rdata"] = socket.inet_ntoa(rd)
                elif rtype == AAAA and rdlen == 16:
                    rec["rdata"] = socket.inet_ntop(socket.AF_INET6, rd)
                elif rtype == PTR:
                    rec["rdata"], _ = decode_name(data, offset - rdlen)
                elif rtype == SRV and rdlen >= 6:
                    pri, wt, port = struct.unpack("!HHH", rd[:6])
                    target, _ = decode_name(data, offset - rdlen + 6)
                    rec["rdata"] = {"priority": pri, "weight": wt, "port": port, "target": target}
                elif rtype == TXT:
                    txts = []
                    i = 0
                    while i < rdlen:
                        slen = rd[i]; i += 1
                        txts.append(rd[i:i+slen].decode("utf-8", errors="replace"))
                        i += slen
                    rec["rdata"] = txts

                result[section_name].append(rec)
    except (struct.error, IndexError):
        pass  # return what we have

    return result


# ── Socket management ───────────────────────────────────────────────────────

def make_mdns_socket(iface: str | None = None, bind_port: int = MDNS_PORT) -> socket.socket:
    """
    Create a UDP socket bound to the mDNS multicast group.
    Joins 224.0.0.251 on the specified interface (or all interfaces).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass

    sock.bind(("", bind_port))

    # Set TTL to 255 (required by RFC 6762)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    # Enable loopback so we see our own packets in the test environment
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    # Join multicast group
    if iface:
        ip = get_iface_ip(iface)
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton(ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
    else:
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def get_iface_ip(iface: str) -> str:
    """Get the IPv4 address of a network interface via ioctl."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SIOCGIFADDR = 0x8915
        result = fcntl.ioctl(s.fileno(), 0x8915,
                             struct.pack('256s', iface[:15].encode('utf-8')))
        return socket.inet_ntoa(result[20:24])
    finally:
        s.close()


def send_mdns(sock: socket.socket, packet: bytes):
    """Send a packet to the mDNS multicast address."""
    sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))


def send_mdns_unicast(sock: socket.socket, packet: bytes, dest_ip: str):
    """Send a packet directly to a specific host (unicast)."""
    sock.sendto(packet, (dest_ip, MDNS_PORT))


def recv_mdns(sock: socket.socket, timeout: float = 2.0) -> tuple[bytes, tuple[str, int]] | None:
    """Receive an mDNS packet. Returns (data, (src_ip, src_port)) or None on timeout."""
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(9000)
        return data, addr
    except socket.timeout:
        return None
