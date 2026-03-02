#!/usr/bin/env python3
"""
Port Scanner

Purpose: Educational and network-administration oriented TCP port scanner.
Uses only standard libraries: socket, argparse, sys, time, concurrent.futures.

Usage example:
  python3 port_scanner.py -t example.com -s 1 -e 1024 --timeout 0.5 -w 100

This tool is intended for authorized scanning only. Do not scan systems
you do not own or have permission to test.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_args():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner for administration and education"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target hostname or IP address to scan",
    )

    parser.add_argument(
        "-s", "--start",
        type=int,
        default=1,
        help="Starting port (default: 1)",
    )

    parser.add_argument(
        "-e", "--end",
        type=int,
        default=1024,
        help="Ending port (default: 1024)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds for each connection (default: 0.5)",
    )

    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)",
    )

    return parser.parse_args()


def resolve_target(target):
    """Resolve the target hostname to an IP address.

    Raises socket.gaierror if the hostname cannot be resolved.
    """
    return socket.gethostbyname(target)


def validate_port_range(start, end):
    """Validate port bounds; raise ValueError on invalid inputs."""
    if start < 1 or end < 1 or start > 65535 or end > 65535:
        raise ValueError("Ports must be in the range 1-65535")
    if start > end:
        raise ValueError("Start port must be less than or equal to end port")


def scan_port(target_ip, port, timeout):
    """Attempt to connect to a TCP port. Return True if open, else False."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            return result == 0
    except socket.error:
        # On socket errors, treat port as closed for scanning purposes.
        return False


def main():
    args = parse_args()

    # Validate ports and resolve target
    try:
        validate_port_range(args.start, args.end)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        target_ip = resolve_target(args.target)
    except socket.gaierror:
        print(f"Error: Unable to resolve target '{args.target}'. Check the hostname or IP.")
        sys.exit(1)

    # Banner with start time and target
    start_time = time.time()
    readable_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
    print(f"Starting scan at {readable_time}")
    print(f"Target: {args.target} ({target_ip})")
    print(f"Ports: {args.start} to {args.end} | Timeout: {args.timeout}s | Workers: {args.workers}")
    print("-" * 60)

    open_ports = []

    # Use a ThreadPoolExecutor to speed up scanning
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(scan_port, target_ip, port, args.timeout): port
                       for port in range(args.start, args.end + 1)}

            # Iterate over completed futures and print only open ports
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                except Exception:
                    # Unexpected exception inside thread; treat as closed
                    is_open = False

                if is_open:
                    # Only output open ports
                    print(f"[+] Port {port} is OPEN")
                    open_ports.append(port)

    except KeyboardInterrupt:
        # Gracefully handle user interruption
        print("\nScan interrupted by user. Exiting...")
        try:
            # allow interpreter to exit
            sys.exit(0)
        except SystemExit:
            raise

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"Scan completed in {elapsed:.2f} seconds")
    print(f"Open ports found: {len(open_ports)}")


if __name__ == "__main__":
    main()
