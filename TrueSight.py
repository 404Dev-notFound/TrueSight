#!/usr/bin/env python3
"""
TrueSight — IP Finder (simple prototype)
Features:
 - Local IP discovery
 - Public IP lookup
 - Reverse DNS (hostname) lookup
 - Quick common port scan (TCP)
Usage:
    python3 ips.py                # shows local + public IP
    python3 ips.py target.com     # resolves & scans target
    python3 ips.py 8.8.8.8 --ports 20-1024
"""

import socket
import urllib.request
import argparse
import sys
import threading
from queue import Queue
import time

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5900,8080]

def get_outbound_ip():
    """Get primary outbound IP (works without external libs)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        try: s.close()
        except: pass
    return ip

def get_local_ips():
    """Attempt to list IPs for the host."""
    ips = set()
    hostname = socket.gethostname()
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for a in addrs:
            ip = a[4][0]
            # skip IPv6 link-local and empty
            if ip and ":" not in ip:
                ips.add(ip)
    except Exception:
        pass
    # include outbound ip heuristic
    ips.add(get_outbound_ip())
    return sorted(ips)

def get_public_ip():
    """Query a simple public IP service (ipify)."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return "unavailable"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# --- Simple threaded port scanner ---
def scan_port(target, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        s.close()
        return True
    except:
        return False

def worker(q, target, results):
    while not q.empty():
        port = q.get()
        if scan_port(target, port):
            results.append(port)
        q.task_done()

def quick_port_scan(target, ports, threads=50):
    q = Queue()
    for p in ports:
        q.put(p)
    results = []
    for _ in range(min(threads, q.qsize())):
        t = threading.Thread(target=worker, args=(q, target, results), daemon=True)
        t.start()
    q.join()
    return sorted(results)

# --- CLI ---
def parse_ports_arg(s):
    if "-" in s:
        a,b = s.split("-",1)
        return list(range(int(a), int(b)+1))
    else:
        return [int(x) for x in s.split(",") if x.strip()]

def main():
    parser = argparse.ArgumentParser(description="TrueSight — IP Finder (prototype)")
    parser.add_argument("target", nargs="?", help="target hostname or IP to inspect/scan")
    parser.add_argument("--ports", "-p", default=None, help="ports: '80,443,8080' or range '1-1024' or 'common'")
    parser.add_argument("--no-scan", action="store_true", help="don't run port scan even if target provided")
    args = parser.parse_args()

    print("=== TrueSight — IP Finder ===\n")

    # local info
    print("[Local Info]")
    print("Hostname:", socket.gethostname())
    local_ips = get_local_ips()
    print("Local IPs:", ", ".join(local_ips))
    print("Outbound (primary) IP:", get_outbound_ip())
    pub = get_public_ip()
    print("Public IP (detected):", pub)
    if pub != "unavailable":
        rd = reverse_dns(pub)
        if rd: print("Reverse DNS for public IP:", rd)
    print()

    if not args.target:
        print("No target provided. To inspect/scan a host, run: python3 ips.py target.com")
        return

    target = args.target
    print(f"[Target: {target}]")
    try:
        target_ip = socket.gethostbyname(target)
        print("Resolved IP:", target_ip)
    except Exception as e:
        print("DNS resolution failed:", e)
        return

    rd = reverse_dns(target_ip)
    if rd:
        print("Reverse DNS (hostname):", rd)
    else:
        print("Reverse DNS: (none)")

    if args.no_scan:
        print("Skipping port scan (--no-scan).")
        return

    # decide ports
    if args.ports is None or args.ports.lower() == "common":
        ports = COMMON_PORTS
    else:
        try:
            ports = parse_ports_arg(args.ports)
        except Exception:
            print("Invalid --ports format. Use '80,443' or '1-1024'.")
            return

    print(f"Starting quick port scan on {target_ip} ({len(ports)} ports)... (this may take a few seconds)")
    start = time.time()
    open_ports = quick_port_scan(target_ip, ports)
    elapsed = time.time() - start
    if open_ports:
        print("Open ports:", ", ".join(map(str, open_ports)))
    else:
        print("No open ports found in scanned list.")
    print(f"Scan completed in {elapsed:.2f}s")

if __name__ == "__main__":
    main()
