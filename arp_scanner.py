import argparse
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init
from utils import print_status

init(autoreset=True)


def check_host(ip: str, timeout: float = 0.5):
    """
    Check whether a host responds on common TCP ports.
    Local/authorized network discovery only.
    """
    common_ports = [22, 53, 80, 443, 8080]

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((str(ip), port)) == 0:
                    return {
                        "ip": str(ip),
                        "port": port
                    }
        except (socket.timeout, OSError):
            continue

    return None


def scan_network(target: str, timeout: float = 0.5, threads: int = 32):
    """
    Perform a lightweight TCP-based discovery scan.
    This avoids Scapy's unsupported Android packet I/O.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        print_status(f"Invalid network range: {exc}", "error")
        return []

    hosts = list(network.hosts())

    if not hosts:
        print_status("No usable host addresses found.", "error")
        return []

    print_status(
        f"Starting Android-compatible discovery on: {network}",
        "cyan"
    )
    print_status(
        f"Testing {len(hosts)} host(s) on common TCP ports...",
        "cyan"
    )

    devices = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_host, ip, timeout): ip
            for ip in hosts
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    return sorted(devices, key=lambda item: ipaddress.ip_address(item["ip"]))


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Local network discovery tool for Termux/Android. "
            "Use only on networks you own or are authorized to test."
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target local network (example: 192.168.1.0/24)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="TCP connection timeout in seconds (default: 0.5)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=32,
        help="Maximum concurrent checks (default: 32)"
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if not 1 <= args.threads <= 128:
        parser.error("--threads must be between 1 and 128")

    devices = scan_network(
        args.target,
        args.timeout,
        args.threads
    )

    print("-" * 55)
    print(f"{'IP Address':<20} {'Detected TCP Port':<20}")
    print("-" * 55)

    for device in devices:
        print(
            f"{Fore.GREEN}{device['ip']:<20}"
            f"{Style.RESET_ALL}"
            f"{device['port']:<20}"
        )

    print("-" * 55)

    print_status(
        f"Discovery complete. Found {len(devices)} responsive host(s).",
        "cyan"
    )


if __name__ == "__main__":
    main()
