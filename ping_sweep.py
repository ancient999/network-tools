#!/usr/bin/env python3
"""
Ping Sweep — network host discovery
Usage:
    python ping_sweep.py 192.168.1.0/24
    python ping_sweep.py 10.0.0.0/24 -t 150
    python ping_sweep.py 192.168.1.1-192.168.1.50
"""

import subprocess
import platform
import argparse
import socket
import sys
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

MAX_THREADS = 150


def parse_target(target: str) -> list[IPv4Address]:
    """
    Accept:
      - CIDR: 192.168.1.0/24
      - Range: 192.168.1.1-192.168.1.50
      - Single IP: 192.168.1.1
    """
    # Range: x.x.x.x-x.x.x.x
    if "-" in target and "/" not in target:
        parts = target.split("-")
        if len(parts) == 2:
            try:
                start = int(IPv4Address(parts[0].strip()))
                end = int(IPv4Address(parts[1].strip()))
                return [IPv4Address(i) for i in range(start, end + 1)]
            except AddressValueError:
                pass

    # CIDR or single IP
    try:
        net = IPv4Network(target, strict=False)
        return list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    except ValueError:
        print(f"[!] Invalid target: {target}")
        sys.exit(1)


def ping(ip: IPv4Address) -> tuple[IPv4Address, bool]:
    """Send one ICMP ping. Returns (ip, is_alive)."""
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        # Linux / macOS
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return ip, result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ip, False


def resolve_hostname(ip: IPv4Address) -> str:
    """Try reverse DNS lookup. Returns hostname or empty string."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        return ""


def main():
    parser = argparse.ArgumentParser(description="Ping Sweep — network host discovery")
    parser.add_argument(
        "target",
        help="Target: CIDR (192.168.1.0/24), range (192.168.1.1-192.168.1.50), or single IP"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=MAX_THREADS,
        help=f"Number of threads (default: {MAX_THREADS})"
    )
    parser.add_argument(
        "-r", "--resolve",
        action="store_true",
        help="Try to resolve hostnames via reverse DNS"
    )
    args = parser.parse_args()

    hosts = parse_target(args.target)

    print(f"\n{'='*55}")
    print(f"  Ping Sweep")
    print(f"{'='*55}")
    print(f"  Target  : {args.target}")
    print(f"  Hosts   : {len(hosts)}")
    print(f"  Threads : {args.threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    alive = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(ping, ip): ip for ip in hosts}
        done = 0
        for future in as_completed(futures):
            ip, is_alive = future.result()
            done += 1
            print(f"\r  Scanning... {done}/{len(hosts)}", end="", flush=True)
            if is_alive:
                alive.append(ip)

    print()  # newline after progress

    alive.sort()

    print(f"\n  {'IP':<18} {'STATUS':<10} {'HOSTNAME'}")
    print(f"  {'-'*51}")

    for ip in alive:
        hostname = resolve_hostname(ip) if args.resolve else ""
        print(f"  {str(ip):<18} {'alive':<10} {hostname}")

    print(f"\n{'='*55}")
    print(f"  Done. {len(alive)}/{len(hosts)} host(s) alive.")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
