import subprocess
import sys
import os

# Tools that need a target (IP, domain, URL, etc.) passed as an argument
NEEDS_TARGET = {"1", "2", "3", "4", "5", "6", "9"}

TOOLS = {
    "1": ("Network Scanner", "network_scanner.py"),
    "2": ("Port Banner Grabber", "port_banner_grabber.py"),
    "3": ("SSL Checker", "ssl_checker.py"),
    "4": ("Header Analyzer", "header_analyzer.py"),
    "5": ("WHOIS Lookup", "whois_lookup.py"),
    "6": ("Subdomain Finder", "subdomain_finder.py"),
    "7": ("Password Checker", "password_checker.py"),
    "8": ("Hash Tool", "hash_tool.py"),
    "9": ("Directory Bruter", "dir_bruter.py"),
    "10": ("ARP Scanner", "arp_scanner.py"),
}

def main():
    while True:
        print("\n=== MASTER-SECURITY Toolkit ===")
        for key, (name, _) in TOOLS.items():
            print(f"{key}. {name}")
        print("0. Exit")

        choice = input("\nSelect a tool: ").strip()

        if choice == "0":
            print("Bye.")
            sys.exit(0)

        if choice not in TOOLS:
            print("Invalid choice, try again.")
            continue

        name, script = TOOLS[choice]

        if not os.path.exists(script):
            print(f"[!] {script} not found in this directory.")
            continue

        cmd = [sys.executable, script]

        if choice in NEEDS_TARGET:
            target = input(f"Enter target for {name} (IP/domain/URL): ").strip()
            if not target:
                print("[!] Target required, skipping.")
                continue
            cmd.append(target)

        print(f"\n--- Launching {name} ---\n")
        subprocess.run(cmd)

if __name__ == "__main__":
    main()
