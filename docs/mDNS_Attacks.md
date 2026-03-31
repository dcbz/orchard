# mDNS Protocol-Level Network Attacks

Security analysis of Multicast DNS (RFC 6762) and its implementations (Apple mDNSResponder, Avahi) from the perspective of an attacker on the local network. Focus is on protocol-level logic attacks that enable traffic interception, service impersonation, and denial of service -- not memory corruption.

**Threat model:** Attacker has unprivileged access to the local network segment. mDNS uses UDP port 5353, which is above the privileged port range -- no root/admin required. On Avahi, the IP TTL=255 check is disabled by default, meaning off-link attackers who can route packets to 224.0.0.251 may also be in scope.

---

## Table of Contents

1. [Foundational Weakness: Zero Authentication](#1-foundational-weakness-zero-authentication)
2. [Cache Poisoning via Unsolicited Responses](#2-cache-poisoning-via-unsolicited-responses)
3. [Cache-Flush Bit: Single-Packet Record Takeover](#3-cache-flush-bit-single-packet-record-takeover)
4. [Goodbye Packet Abuse: Forced Cache Eviction](#4-goodbye-packet-abuse-forced-cache-eviction)
5. [Name Hijacking via Conflict Resolution Gaming](#5-name-hijacking-via-conflict-resolution-gaming)
6. [Probe Suppression and Denial](#6-probe-suppression-and-denial)
7. [Service Discovery Poisoning](#7-service-discovery-poisoning)
8. [Unicast Response Exploitation (Stealth Poisoning)](#8-unicast-response-exploitation-stealth-poisoning)
9. [Duplicate Suppression Abuse (Silencing Legitimate Hosts)](#9-duplicate-suppression-abuse-silencing-legitimate-hosts)
10. [POOF Abuse: Query-Triggered Cache Eviction](#10-poof-abuse-query-triggered-cache-eviction)
11. [TC-Bit Flood: Global Response Suppression](#11-tc-bit-flood-global-response-suppression)
12. [TTL Manipulation](#12-ttl-manipulation)
13. [Passive Reconnaissance](#13-passive-reconnaissance)
14. [Global Name Hijacking During Outages](#14-global-name-hijacking-during-outages)
15. [Cross-Segment Attacks via Bridges and Reflectors](#15-cross-segment-attacks-via-bridges-and-reflectors)
16. [Legacy Unicast Query Race](#16-legacy-unicast-query-race)
17. [TSR Timestamp Manipulation (mDNSResponder-specific)](#17-tsr-timestamp-manipulation-mdnsresponder-specific)
18. [Avahi Off-Link Cache Poisoning](#18-avahi-off-link-cache-poisoning)
19. [Compound Attack Chains](#19-compound-attack-chains)

---

## 1. Foundational Weakness: Zero Authentication

**RFC Section:** Section 21 (Security Considerations)

> "The algorithm for detecting and resolving name conflicts is, by its very nature, an algorithm that assumes cooperating participants."

mDNS has **no authentication, no authorization, and no integrity protection**. Any host on the local link can:
- Respond to any query with arbitrary data
- Claim any `.local.` hostname
- Advertise any service
- Evict any cached record

The Query ID field is explicitly ignored (Section 18.1), eliminating even the weak protection that unicast DNS derives from transaction ID matching. The RFC suggests IPsec/DNSSEC as mitigations, but neither is implemented by any mainstream mDNS stack.

**Why this matters:** Every attack below is enabled by this fundamental design choice. There is no "fix" within the protocol -- all mitigations are external (TLS on application layer, network segmentation, etc.).

---

## 2. Cache Poisoning via Unsolicited Responses

**RFC Section:** Section 18.1

> "Multicast DNS implementations SHOULD examine all received Multicast DNS response messages for useful answers, without regard to the contents of the ID field or the Question Section."

> "Multicast DNS implementations MAY cache data from any or all Multicast DNS response messages they receive, for possible future use."

**How it works:**

1. Attacker sends an unsolicited mDNS response to 224.0.0.251:5353 containing a crafted A record: `target.local. -> <attacker_ip>`
2. All hosts on the link cache this record (opportunistic caching)
3. When any host later resolves `target.local.`, the poisoned cache entry is returned immediately -- no query is ever sent

**Key differences from unicast DNS cache poisoning:**
- No query to race against
- No transaction ID to guess
- No source port randomization to defeat
- Works preemptively (before the victim even wants to resolve the name)

**Implementation details:**

In mDNSResponder (`mDNSCore/mDNS.c:10070`):
```c
mDNSBool AcceptableResponse = ResponseMCast || !dstaddr || LLQType || recordAcceptedInResponse;
```
All multicast responses are unconditionally accepted.

In Avahi (`avahi-core/cache.c:316-370`): Records are replaced without verifying the source matches the original publisher:
```c
avahi_record_unref(e->record);
e->record = avahi_record_ref(r);
```

**Impact:** Pre-emptive, network-wide redirection of any `.local.` name. Victims never send a query, so no observable network activity indicates the attack.

**Severity:** Critical | **Complexity:** Trivial | **Stealth:** High

---

## 3. Cache-Flush Bit: Single-Packet Record Takeover

**RFC Section:** Section 10.2

> "When a resource record appears [...] with the cache-flush bit set, it means, 'This is an assertion that this information is the truth and the whole truth, and anything you may have heard more than a second ago regarding records of this name/rrtype/rrclass is no longer true'."

**How it works:**

1. Attacker sends one mDNS response with the cache-flush bit (bit 15 of the rrclass field) set
2. Every host on the network flushes ALL cached records of that name/rrtype/rrclass older than 1 second
3. The attacker's record replaces them

**This is strictly more powerful than goodbye packets** (Attack #4) because:
- Goodbye packets require the attacker to know the exact rdata being evicted
- Cache-flush replaces ALL records of that name/type regardless of rdata content
- The attacker's replacement record is cached simultaneously with the flush

**Implementation:**

mDNSResponder (`mDNSCore/mDNS.c:10525-10677`): All cached records older than 1 second with matching name/type/class/interface are set to expire in 1 second. The attacker's record is cached in the same operation.

Avahi (`avahi-core/cache.c:302-311`):
```c
if (cache_flush) {
    for (e = first; e; e = e->by_key_next) {
        t = avahi_timeval_diff(&now, &e->timestamp);
        if (t > 1000000)  // older than 1 second
            expire_in_one_second(c, e, AVAHI_CACHE_REPLACE_FINAL);
    }
}
```

**Attack scenario -- AirPlay/Printer hijacking:**
1. Victim has cached: `MyPrinter._ipp._tcp.local. SRV 0 0 631 realprinter.local.`
2. Attacker sends: `MyPrinter._ipp._tcp.local. SRV 0 0 631 evil.local.` with cache-flush bit
3. All hosts on the network now route print jobs to the attacker

**Impact:** Immediate, network-wide, single-packet takeover of any unique record.

**Severity:** Critical | **Complexity:** Trivial | **Stealth:** Medium

---

## 4. Goodbye Packet Abuse: Forced Cache Eviction

**RFC Section:** Section 10.1

> "the host SHOULD send an unsolicited Multicast DNS response packet [...] but an RR TTL of zero. This has the effect of updating the TTL stored in neighboring hosts' cache entries to zero, causing that cache entry to be promptly deleted."

**How it works:**

1. Attacker sends a response with TTL=0 for a target record (must match name, rrtype, rrclass, AND rdata)
2. All hosts schedule that cache entry for deletion in 1 second
3. The legitimate owner has 1 second to send a "rescue" announcement -- but may not be monitoring

**Requirement:** The attacker must know the exact rdata. For A/AAAA records, this is the victim's IP address -- trivially obtained via passive observation (Attack #13).

**Avahi implementation** (`avahi-core/cache.c:284-290`):
```c
if (r->ttl == 0) {
    if ((e = lookup_record(c, r)))
        expire_in_one_second(c, e, AVAHI_CACHE_GOODBYE_FINAL);
```
No source validation. Any host can goodbye any record.

**Two-step hijack pattern:**
1. Send goodbye packet for `victim.local. A 192.168.1.10` (legitimate record evicted in 1s)
2. Immediately send response for `victim.local. A <attacker_ip>` (attacker's record cached)

**Impact:** Targeted cache eviction followed by replacement. Effective for denial-of-service (repeated goodbyes) or as setup for hijacking.

**Severity:** High | **Complexity:** Low | **Stealth:** Medium

---

## 5. Name Hijacking via Conflict Resolution Gaming

**RFC Section:** Section 8.2, Section 9

> "the rdata is compared [...] the lexicographically later data wins."

> "Whenever a Multicast DNS responder receives any Multicast DNS response [...] containing a conflicting resource record [...] the Multicast DNS responder MUST immediately reset its conflicted unique record to probing state"

**How it works (Method A -- Force re-probe and win):**

1. Attacker observes `victim.local.` resolving to `192.168.1.10`
2. Attacker sends an mDNS response with `victim.local. A 192.168.1.200` (different rdata)
3. Victim detects conflict, enters re-probing state
4. During simultaneous probe tiebreaking, rdata is compared lexicographically
5. `192.168.1.200` > `192.168.1.10` -- attacker wins deterministically
6. Victim is forced to rename to `victim (2).local.`
7. All existing connections/bookmarks/configs pointing to `victim.local.` now resolve to attacker

**How it works (Method B -- Exhaustion DoS):**

Per RFC Section 9: after 15 conflicts in 10 seconds, the host rate-limits to one probe every 5 seconds. The attacker continuously sends conflicts, preventing the victim from ever successfully registering.

**Implementation specifics:**

mDNSResponder (`mDNSCore/mDNS.c:929`): Only allows `kMaxAllowedMCastProbingConflicts = 1` multicast conflict during probing before deregistering. Unicast conflicts during probing cause **immediate deregistration** with zero tolerance (line 10358-10367).

Avahi (`avahi-core/server.c:234`): Calls `withdraw_rrset` when an incoming probe has lexicographically-higher rdata. Rate limits after 15 failures with a 20-second holdoff.

**Impact:** Permanent takeover of any hostname. The legitimate host renames itself and all traffic for the original name goes to the attacker.

**Severity:** High | **Complexity:** Low | **Stealth:** Low (generates visible conflict traffic)

---

## 6. Probe Suppression and Denial

**RFC Section:** Section 8.1

> "the time window for probing is intentionally set quite short [...] another device on the network using that name has just 750 ms to respond"

**How it works:**

The probing window is ~1000ms total (0-250ms random delay + 3 probes at 250ms intervals). An attacker can:

**Attack A -- Block all new registrations:**
Monitor for probe queries. Immediately respond with a conflicting record for every observed probe. No host on the network can ever successfully claim a new name.

**Attack B -- Deterministic tiebreak win:**
Always probe with rdata that is lexicographically maximal (e.g., IP `255.255.255.254` for A records). The attacker wins every simultaneous probe tiebreak.

**Attack C -- Probe authority section suppression (mDNSResponder-specific):**
In mDNSResponder (`mDNSCore/mDNS.c:8495-8498`), if a probe's authority section contains a record identical to the responder's own record, the responder suppresses its response. An attacker who knows the victim's records can craft probes that silence the victim's probe responses, causing the victim to lose the probing race.

**Impact:** Denial of service (no new services can register) or targeted name theft.

**Severity:** High | **Complexity:** Low | **Stealth:** Low

---

## 7. Service Discovery Poisoning

**RFC Section:** Section 2, Section 8.1

> "'shared' resource record set is one where several Multicast DNS responders may have records with the same name, rrtype, and rrclass"

> Shared records do not require probing.

**How it works:**

DNS-SD service discovery relies on PTR records, which are **shared records** -- they require no probing and no uniqueness verification. An attacker simply multicasts:

1. PTR record: `_ipp._tcp.local. -> Fake Printer._ipp._tcp.local.`
2. SRV record: `Fake Printer._ipp._tcp.local. -> evil.local:631`
3. TXT record: `Fake Printer._ipp._tcp.local. -> "ty=LaserJet" "pdl=application/postscript"`
4. A record: `evil.local. -> <attacker_ip>`

The fake service appears in every device's service browser alongside legitimate services. No conflict resolution occurs because PTR records are shared.

**High-value targets:**
| Service Type | mDNS Name | Attack |
|---|---|---|
| Printers (IPP) | `_ipp._tcp.local.` | Capture printed documents |
| AirPlay | `_airplay._tcp.local.` | Intercept screen mirroring |
| AirDrop | `_airdrop._tcp.local.` | Intercept file transfers |
| SMB/AFP shares | `_smb._tcp.local.` / `_afpovertcp._tcp.local.` | Harvest credentials via fake auth |
| SSH | `_ssh._tcp.local.` | Capture credentials (users often click through host key warnings) |
| HTTP | `_http._tcp.local.` | Phishing via fake web services |
| Chromecast | `_googlecast._tcp.local.` | Intercept cast sessions |
| MQTT/IoT | `_mqtt._tcp.local.` | Intercept IoT telemetry |

**Reverse PTR records** (Section 4) skip probing entirely because "the host can reasonably assume that no other host will be trying to create those same PTR records." An attacker exploits this assumption to spoof reverse DNS lookups for any link-local address.

**Impact:** Users connect to attacker-controlled services, enabling credential theft, data interception, and phishing.

**Severity:** High | **Complexity:** Trivial | **Stealth:** Medium (services appear in browsers)

---

## 8. Unicast Response Exploitation (Stealth Poisoning)

**RFC Section:** Section 5.4

> "When receiving a question with the unicast-response bit set, a responder SHOULD usually respond with a unicast packet directed back to the querier."

**How it works:**

When a querier sets the QU (unicast-response) bit -- typically on first query after wake-from-sleep or interface activation -- responders send answers via unicast directly to the querier. This creates a stealth poisoning vector:

1. Victim wakes from sleep and sends a QU query for `printer.local.`
2. Attacker races to respond with a unicast packet directly to the victim
3. The poisoned response is **invisible to all other hosts** on the network
4. No other host can detect, counter, or even observe the attack
5. Passive conflict detection (POOF) does not function for unicast-only exchanges

**Critical timing:** QU queries happen precisely when the victim is most vulnerable -- its cache is empty after sleep/boot, and it has no prior knowledge to compare against.

**mDNSResponder specifics** (`mDNSCore/mDNS.c:9028-9031`): Accepts unicast responses from any local subnet host within 2 seconds of a QU query. Any host on the subnet qualifies.

**Impact:** Targeted, undetectable cache poisoning of individual hosts. Perfect for surgical MITM attacks.

**Severity:** High | **Complexity:** Low | **Stealth:** High

---

## 9. Duplicate Suppression Abuse (Silencing Legitimate Hosts)

**RFC Section:** Section 7.3, Section 7.4

> "If a host is planning to send an answer, and it sees another host on the network send a response message containing the same answer record [...] then this host SHOULD treat its own answer as having been sent"

**How it works:**

**Answer suppression:** The attacker sends a response with the same name/rrtype/rrclass as a legitimate responder's record but with the attacker's rdata, using a TTL >= the legitimate one. The legitimate responder observes this and **suppresses its own answer**, believing it's already been sent. Victims cache the attacker's data.

**Query suppression:** The attacker sends a query identical to one a victim is about to send, but includes a large Known-Answer list containing the attacker's fabricated answer. The victim suppresses its own query, believing it's been asked. The attacker controls which responses arrive.

**Impact:** Legitimate responders voluntarily go silent, ceding the network to attacker-controlled responses. The victim host believes everything is normal.

**Severity:** High | **Complexity:** Medium | **Stealth:** High

---

## 10. POOF Abuse: Query-Triggered Cache Eviction

**RFC Section:** Section 10.5

> "If a host sees queries, for which a record in its cache would be expected to be given as an answer in a multicast response, but no such answer is seen [...] that record SHOULD be flushed from the cache."

> Hosts "SHOULD NOT perform its own queries to reconfirm that the record is truly gone."

**How it works:**

1. Attacker sends multicast queries for a target name
2. Attacker simultaneously suppresses the legitimate response (via Answer Suppression from Attack #9, or via flooding)
3. All hosts on the network observe the query going unanswered
4. After 2+ unanswered observations within 10 seconds, all hosts flush the legitimate record
5. The RFC explicitly says hosts should NOT independently verify -- they just trust the POOF observation

**Avahi implementation** (`avahi-core/cache.c:442-512`): After 4 unanswered observations with 1-second minimum intervals, the entry is expired.

**mDNSResponder** (`mDNSCore/mDNS.c:8854-8886`): Uses `MaxUnansweredQueries` threshold before eviction.

**Advantage over goodbye packets:** Does not require knowing the victim's rdata. The attacker only needs to query for the name and prevent the legitimate answer.

**Impact:** Network-wide cache eviction of any record, without knowing its rdata.

**Severity:** High | **Complexity:** Medium | **Stealth:** High

---

## 11. TC-Bit Flood: Global Response Suppression

**RFC Section:** Section 7.2

> "A Multicast DNS responder seeing a Multicast DNS query with the TC bit set defers its response for a time period randomly selected in the interval 400-500 ms."

> "If the responder receives additional Known-Answer packets with the TC bit set, it SHOULD extend the delay"

> "This opens the potential risk that a continuous stream of Known-Answer packets could, theoretically, prevent a responder from answering indefinitely."

**How it works:**

The attacker sends a continuous stream of packets with the TC (Truncated) bit set, each appearing to be a continuation of a multi-packet Known-Answer list. Every responder on the network keeps deferring, waiting for the stream to end. The RFC explicitly acknowledges this vulnerability.

**Impact:** Complete suppression of all mDNS responses on the network. No host can discover any service or resolve any `.local.` name for the duration of the attack.

**Severity:** High | **Complexity:** Trivial | **Stealth:** Low (generates visible traffic)

---

## 12. TTL Manipulation

**RFC Section:** Section 10, Section 6.6

**Long TTL poisoning:**

An attacker sets extremely high TTL values (up to ~68 years for mDNSResponder which caps at 4500s, or effectively unlimited on Avahi which has **no TTL cap on incoming records**). Once cached, malicious records persist long after the attacker leaves the network.

mDNSResponder caps multicast TTLs to 4500 seconds (`DNSCommon.h:247`). Avahi does NOT cap incoming TTLs (`avahi-core/cache.c:276`) -- a critical difference.

**TTL/2 forced re-announcement:**

Per Section 6.6, when a responder sees its own record advertised with a TTL less than half its true TTL, it MUST immediately re-announce. An attacker can force continuous re-announcements by repeatedly sending records with TTL just under half the legitimate value, creating a traffic amplification loop and wasting victim CPU/bandwidth.

**Impact:** Persistent poisoning surviving attacker departure (especially on Avahi), or resource exhaustion via forced re-announcements.

**Severity:** Medium | **Complexity:** Trivial | **Stealth:** High (long TTL) / Low (forced re-announce)

---

## 13. Passive Reconnaissance

**RFC Section:** Sections 5.2, 7.1, 8.3

**How it works:**

A completely passive attacker (zero packets sent) learns:

| Information | Source |
|---|---|
| All hostnames | Announcement packets, probe queries |
| All IP addresses (v4 + v6) | A/AAAA records in responses |
| All running services per host | PTR/SRV/TXT records |
| OS/hardware info | HINFO records, TXT metadata (e.g., `model=MacBookPro`) |
| Device presence patterns | Probe timing (join), goodbye timing (leave), sleep/wake cycles |
| What each host is interested in | Query patterns, Known-Answer lists (Section 7.1) |
| Network topology | Source addresses, interface information |

Known-Answer suppression (Section 7.1) is particularly revealing: a host populates the answer section of its query with everything it already knows, giving the passive observer a complete view of each host's cache state.

**Impact:** Complete network map with zero detection risk. Ideal for targeting subsequent active attacks.

**Severity:** Medium | **Complexity:** Trivial | **Stealth:** Perfect (purely passive)

---

## 14. Global Name Hijacking During Outages

**RFC Section:** Section 3, Section 21

> "DNS queries for names that do not end with '.local.' MAY be sent to the mDNS multicast address, if no other conventional DNS server is available."

> "A malicious host could masquerade as 'www.example.com.' by answering the resulting Multicast DNS query"

**How it works:**

1. Attacker disrupts upstream DNS (ARP spoofing, deauthenticating the gateway, etc.)
2. Implementations may fall back to resolving global names via mDNS multicast
3. Attacker responds to mDNS queries for `www.bank.com.`, `mail.google.com.`, etc.
4. Victims connect to attacker-controlled IP for what they believe are global services

**Search-list attack variant:** If `.local.` is in the DNS search list, a query for `intranet` may be expanded to `intranet.local.` and resolved via mDNS. The RFC's mitigation (MUST NOT append `.local.` to names with 2+ labels) only works if implementations comply.

**Impact:** During network outages (which the attacker may trigger), victims can be redirected to impersonations of any global service.

**Severity:** Critical | **Complexity:** Low | **Stealth:** Medium

---

## 15. Cross-Segment Attacks via Bridges and Reflectors

### 15a. Bridged Network Cache-Flush Propagation

**RFC Section:** Section 10.2, Section 14

> "a host's address record announcement on a wireless interface may be bridged onto a wired Ethernet and may cause that same host's Ethernet address records to be flushed from peer caches."

In bridged environments (extremely common with WiFi-to-Ethernet bridges), mDNS packets from the wireless segment reach the wired segment and vice versa. Cache-flush attacks (Attack #3) propagate across the bridge, enabling cross-segment takeover.

### 15b. Source Address Bypass for Multicast

**RFC Section:** Section 11

> "All responses received with a destination address in the IP header that is the mDNS IPv4 link-local multicast address 224.0.0.251 [...] are necessarily deemed to have originated on the local link, regardless of source IP address."

Multicast responses are accepted regardless of source IP. An attacker on an overlapping subnet (different IP range, same physical link) can still poison caches.

### 15c. Avahi Reflector Abuse

**Avahi-specific** (`avahi-core/server.c:499-569`): When `enable_reflector=yes`, queries, responses, and probes are forwarded between all interfaces. An attacker on one segment can:
- Query and receive responses from all segments
- Inject poisoned responses that propagate to all segments
- Trigger conflicts on remote segments

The reflector's `reflect_filters` uses `strstr()` substring matching (`server.c:685-686`), which is trivially bypassed by embedding the filter string within a longer name.

**Impact:** mDNS attacks cross router/VLAN boundaries.

**Severity:** Medium-High | **Complexity:** Medium | **Stealth:** Medium

---

## 16. Legacy Unicast Query Race

**RFC Section:** Section 5.1, Section 6.7

> "A simple DNS resolver like this will typically just take the first response it receives."

Legacy resolvers (using ephemeral source ports instead of 5353) accept the first response. The attacker races to respond before the legitimate responder. Since legacy unicast responses go directly to the querier via unicast, other hosts cannot observe or counter the attack.

**Avahi-specific** (`avahi-core/server.c:737-875`): The legacy unicast reflector uses only 100 slots with a 2-second timeout. An attacker sending >100 legacy queries in 2 seconds exhausts all slots, causing legitimate queries to be silently dropped.

**Impact:** Trivial first-response-wins race for embedded devices and simple resolvers.

**Severity:** High | **Complexity:** Low | **Stealth:** High

---

## 17. TSR Timestamp Manipulation (mDNSResponder-specific)

**File:** `mDNSResponder/mDNSCore/mDNS.c:8005-8041`

mDNSResponder implements a Timestamp-based Record (TSR) conflict resolution mechanism. The comparison uses `mDNSPlatformContinuousTimeSeconds() - pktTimeSinceReceived` to determine who held the record first.

**Attack:** An attacker crafts TSR OPT records with `pktTimeSinceReceived = 0` (claiming the record was just received at current time). Since "newer wins" in TSR conflict resolution (`ourTimeOfReceipt < pktTimeOfReceipt` = we lose), the attacker always wins. The 2-second quantization guard (`TSR_QUANTIZATION_SECS`) provides minimal protection.

Out-of-range `pktTimeSinceReceived` values are clamped rather than rejected (line 8023), adding leniency.

**Impact:** Deterministic win in TSR-based conflict resolution, bypassing the normal lexicographic comparison.

**Severity:** Medium-High | **Complexity:** Medium | **Stealth:** Medium

---

## 18. Avahi Off-Link Cache Poisoning

**File:** `avahi/avahi-core/server.c:1012-1015, 1652`

Avahi's `check_response_ttl` defaults to `0` (disabled):
```c
c->check_response_ttl = 0;
```

RFC 6762 originally required IP TTL=255 for mDNS to ensure link-local scope. With this check disabled, **any attacker who can route UDP packets to 224.0.0.251:5353 can inject mDNS responses from anywhere on the network path**. This is NOT a local-link-only attack on Avahi.

Apple's mDNSResponder enforces TTL=255 unconditionally. This is a critical security posture difference.

**Combined with no source address validation for multicast responses** (`server.c:932-1033`), this means remote attackers can:
- Poison Avahi caches from across the internet (if multicast routing or tunneling is available)
- Inject records from adjacent network segments without physical access to the target link

**Impact:** Remote cache poisoning of all Avahi instances on networks where multicast routing reaches.

**Severity:** Critical (for affected configurations) | **Complexity:** Low | **Stealth:** High

---

## 19. Compound Attack Chains

### Chain A: Full Service MITM

1. **Recon** (Attack #13): Passively identify target host, its IP, and services
2. **Evict** (Attack #3 or #4): Cache-flush or goodbye the target's A record
3. **Replace** (Attack #2): Inject attacker's A record for the target's hostname
4. **Proxy**: Forward traffic to the real host, intercepting/modifying in transit

### Chain B: Credential Harvesting via Fake Services

1. **Recon** (Attack #13): Identify popular service types on the network
2. **Poison** (Attack #7): Advertise fake services (printers, file shares, SSH)
3. **Harvest**: Capture credentials when users connect to fake services
4. **Persist** (Attack #12): Use high TTLs so fake services survive in caches

### Chain C: Targeted Stealth Takeover

1. **Wait** for victim to sleep (observable via goodbye packets)
2. **Claim** the victim's hostname via probing (Attack #5) while victim is offline
3. **Serve** poisoned QU responses (Attack #8) to hosts waking up and querying
4. All traffic for victim silently redirected; victim wakes up and is forced to rename

### Chain D: Network-Wide Service Denial

1. **TC-flood** (Attack #11) to suppress all responses
2. Simultaneously **goodbye-flood** (Attack #4) all known cached records
3. **Probe-deny** (Attack #6) to prevent any re-registration
4. Complete mDNS service blackout on the network segment

### Chain E: Outage-Triggered Global Hijack

1. **Disrupt** upstream DNS (ARP spoof the gateway, deauth, etc.)
2. **Wait** for clients to fall back to mDNS for global names (Attack #14)
3. **Respond** to mDNS queries for `login.microsoftonline.com.`, `imap.gmail.com.`, etc.
4. **Serve** credential-harvesting pages on the attacker's IP

---

## Implementation Comparison: Security Posture

| Feature | mDNSResponder | Avahi |
|---|---|---|
| IP TTL=255 check | Always enforced | **Off by default** |
| Source address validation | Subnet check for unicast | Minimal |
| Incoming rate limiting | Response-level (1s between identical responses) | **None** |
| TTL capping | 4500s multicast, 3600s unicast | **None** |
| Conflict tolerance (probing) | 1 multicast, 0 unicast | 15 before holdoff |
| Cache size limit | 2000 per RRSet, 4000 per question | 4096 per interface |
| Record class validation | Enforced | **Not enforced on incoming** |
| Random number quality | `arc4random()` | **`rand()` fallback** |
| Reflector feature | N/A | Available (expands attack surface) |
| TrustedSource() | Compiled out (`#if 0`) | N/A |

---

## Mitigations (for defenders)

These are outside the mDNS protocol itself, which has no internal security:

1. **Network segmentation**: Isolate trust domains. mDNS is link-local by design -- but bridges and reflectors break this.
2. **Enable Avahi's `check_response_ttl`**: Set to 1 in `avahi-daemon.conf` to require TTL=255.
3. **Application-layer TLS**: Services discovered via mDNS should use TLS with certificate pinning. mDNS is a discovery mechanism, not a security mechanism.
4. **Disable mDNS reflector**: Unless strictly required, `enable-reflector=no` in Avahi.
5. **Monitor for anomalies**: Rapid cache-flush bursts, goodbye floods, or probe storms indicate active attacks.
6. **Firewall port 5353**: Block mDNS at VLAN boundaries if cross-segment discovery isn't needed.
7. **Disable wide-area mDNS**: Avahi's `enable-wide-area` expands the attack surface to include DNS spoofing.
