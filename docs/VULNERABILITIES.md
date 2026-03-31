# mDNS Implementation Vulnerabilities (Memory Safety & Code-Level Bugs)

Non-logic bugs found during security review of mDNSResponder and Avahi. These are memory corruption, integer overflow, weak crypto, and similar implementation-level issues -- distinct from the protocol-level network attacks documented in `mDNS_Attacks.md`.

---

## mDNSResponder

### 1. CompareRData Silent Conflict Bypass for Large Records

**File:** `mDNSResponder/mDNSCore/mDNS.c:7895-7917`

```c
mDNSu8 ourdata[256], pktdata[256];
```

`CompareRData()` uses fixed 256-byte stack buffers for rdata serialization. When `putRData()` is called and the rdata exceeds 256 bytes, it returns NULL. Both `ourend` and `pktend` become NULL, causing the comparison at lines 7908-7914 to evaluate as `ourptr >= ourend` AND `pktptr >= pktend` (both true since both are NULL vs the buffer start), returning 0 (no conflict detected).

**Impact:** Conflict detection silently fails for any record with rdata > 256 bytes. An attacker can craft records with large rdata that bypass all conflict resolution. This is a logic bug with potential security impact -- it does not cause a crash but causes the conflict detection state machine to make incorrect decisions.

**Risk:** Medium (requires large rdata, but TXT records can easily exceed 256 bytes)

### 2. TrustedSource() Compiled Out

**File:** `mDNSResponder/mDNSCore/mDNS.c:8951-8961`

The `TrustedSource()` function is entirely wrapped in `#if 0`:
```c
#if 0
mDNSlocal mDNSBool TrustedSource(const mDNS *const m, const mDNSAddr *const srcaddr) { ... }
#endif
```

Additionally, source address verification in `ExpectingUnicastResponseForRecord()` is commented out (line ~9020):
```c
//  if (mDNSSameAddress(srcaddr, &q->Target))  return(mDNStrue);
```

**Impact:** No verification that unicast DNS responses come from the expected server. Enables trivial unicast response spoofing if an attacker can guess the ephemeral port and transaction ID (or if these are predictable).

**Risk:** Medium (defense-in-depth removal)

### 3. DSO Session Establishment Without TLS

**File:** `mDNSResponder/DSO/dso.c:74, 876-886`

```c
// TODO: TLS support
```

DSO (DNS Stateful Operations) sessions are established on the first non-response message with no authentication. Without the planned TLS support, DSO sessions are vulnerable to connection hijacking and injection on the transport layer.

**Risk:** Low-Medium (DSO is not widely deployed)

---

## Avahi

### 4. Weak Random Number Generation

**File:** `avahi/avahi-core/server.c:1504`

```c
s->local_service_cookie = (uint32_t) rand() * (uint32_t) rand();
```

The service cookie (used to identify whether a service is local) is generated from `rand()`, which is seeded once and predictable. An attacker who can predict the seed can determine whether services are locally published -- useful for fingerprinting and targeting.

Cache expiry jitter (`avahi-core/cache.c:251-256`) also uses `rand()` with coarse 10-second re-seeding, making expiry timing predictable.

**Risk:** Low-Medium (information disclosure, aids attacker targeting)

### 5. No TTL Cap on Incoming Records (Integer Overflow Potential)

**File:** `avahi/avahi-core/cache.c:276, 244`

Avahi accepts any TTL value from incoming records with no maximum enforcement. The cache expiry calculation:

```c
usec = (AvahiUsec) e->record->ttl * 10000;
```

`AvahiUsec` is typically `long long` (64-bit), so overflow is unlikely on 64-bit platforms. However, on 32-bit platforms where `AvahiUsec` might be 32-bit, a TTL of ~214748 seconds (2.5 days) would cause overflow in the multiplication by 10000, resulting in a negative or wrapped expiry time. Records could expire immediately or behave unpredictably.

**Risk:** Low (most modern deployments are 64-bit, but embedded/IoT may be 32-bit)

### 6. Reflector Filter Bypass via Substring Matching

**File:** `avahi/avahi-core/server.c:685-686`

```c
if (strstr(record->data.ptr.name, (char*) l->text) != NULL) {
    match = 1;
```

The reflector filter uses `strstr()` for substring matching rather than exact or anchored matching. A filter intended to allow `_http._tcp` would also match `evil_http._tcp`, `not_http._tcp.evil`, or any crafted name containing the filter string as a substring.

**Risk:** Medium (filter bypass, but requires reflector to be enabled with filters configured)

### 7. Legacy Unicast Slot Exhaustion

**File:** `avahi/avahi-core/server.c:737-875`

The legacy unicast reflector uses a fixed array of `AVAHI_LEGACY_UNICAST_REFLECT_SLOTS_MAX` (100) slots with 2-second timeout. Slot lookup uses modular indexing:

```c
idx = id % AVAHI_LEGACY_UNICAST_REFLECT_SLOTS_MAX;
```

An attacker sending >100 legacy unicast queries in 2 seconds fills all slots. Subsequent legitimate queries are silently dropped. The modular indexing also means that specific query IDs can be chosen to collide with and overwrite in-progress legitimate queries.

**Risk:** Medium (denial of service for legacy unicast resolution)

### 8. No Record Class Validation on Incoming Packets

**File:** `avahi/avahi-core/server.c:658-728`

In `handle_response_packet()`, records are processed and cached without verifying the DNS class is IN (Internet). While `server_add_internal()` in `entry.c:214` checks `r->key->clazz == AVAHI_DNS_CLASS_IN` for locally published records, this check is absent for incoming records.

An attacker could inject records with unusual class values (CH, HS, etc.) that may interact unexpectedly with cache lookups or cause confusion in client applications that don't expect non-IN class records from mDNS.

**Risk:** Low (most code paths implicitly assume IN class, but edge cases may exist)

---

## Summary

| # | Bug | Implementation | Type | Risk |
|---|---|---|---|---|
| 1 | CompareRData 256-byte bypass | mDNSResponder | Logic (silent failure) | Medium |
| 2 | TrustedSource compiled out | mDNSResponder | Missing defense | Medium |
| 3 | DSO without TLS | mDNSResponder | Missing auth | Low-Medium |
| 4 | Weak PRNG for cookies | Avahi | Weak crypto | Low-Medium |
| 5 | No TTL cap (overflow on 32-bit) | Avahi | Integer overflow | Low |
| 6 | strstr() filter bypass | Avahi | Input validation | Medium |
| 7 | Legacy unicast slot exhaustion | Avahi | Resource exhaustion | Medium |
| 8 | Missing class validation | Avahi | Input validation | Low |
