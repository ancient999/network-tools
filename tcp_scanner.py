#!/usr/bin/env python3
"""
TCP Port Scanner
Usage:
    python tcp_scanner.py 192.168.1.1
    python tcp_scanner.py 192.168.1.1 -p 22 80 443
    python tcp_scanner.py 192.168.1.1 -p 1-1024
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Well-known ports → service names
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 179: "BGP", 443: "HTTPS", 445: "SMB",
    514: "Syslog", 830: "NETCONF", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

TIMEOUT = 0.5  # seconds per connection attempt
MAX_THREADS = 100


def parse_ports(port_args: list[str]) -> list[int]:
    """Parse port arguments: single ports or ranges like 1-1024."""
    ports = []
    for arg in port_args:
        if "-" in arg:
            start, end = arg.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(arg))
    return sorted(set(ports))


def scan_port(host: str, port: int) -> tuple[int, bool, str]:
    """Try to connect to host:port. Returns (port, is_open, banner)."""
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try to grab banner (works for SSH, FTP, SMTP…)
                try:
                    sock.settimeout(0.3)
                    banner = sock.recv(256).decode(errors="ignore").strip()
                except Exception:
                    pass
                return port, True, banner
    except (socket.gaierror, OSError):
        pass
    return port, False, banner


def resolve_host(host: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {host}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        default=["1-1024"],
        metavar="PORT",
        help="Ports to scan: 22 80 443 or 1-1024 (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=MAX_THREADS,
        help=f"Number of threads (default: {MAX_THREADS})"
    )
    args = parser.parse_args()

    ip = resolve_host(args.host)
    ports = parse_ports(args.ports)

    print(f"\n{'='*55}")
    print(f"  TCP Port Scanner")
    print(f"{'='*55}")
    print(f"  Target  : {args.host} ({ip})")
    print(f"  Ports   : {len(ports)} ({ports[0]}–{ports[-1]})")
    print(f"  Threads : {args.threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service = KNOWN_PORTS.get(port, "unknown")
                open_ports.append((port, service, banner))

    open_ports.sort(key=lambda x: x[0])

    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'BANNER'}")
        print(f"  {'-'*51}")
        for port, service, banner in open_ports:
            banner_short = banner[:30].replace("\n", " ") if banner else ""
            print(f"  {port:<8} {'open':<8} {service:<12} {banner_short}")
    else:
        print("  No open ports found.")

    print(f"\n{'='*55}")
    print(f"  Done. {len(open_ports)} open port(s) found.")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
