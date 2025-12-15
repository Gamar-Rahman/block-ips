#!/usr/bin/env python3

"""
Mini Fail2Ban-style IP blocking script.

- Accepts one or more log files as command-line arguments
- Parses log entries to extract IP addresses
- Enriches IPs with simulated geolocation / Tor data
- Blocks high-risk IPs based on predefined rules
"""

import sys
import re

# --------------------------------------------------
# Simulated IP enrichment (mock IPLocate API)
# In a real system, this would be an API call
# --------------------------------------------------
IP_INTEL_DB = {
    "203.0.113.42": {"country": "China", "tor": True},
    "198.51.100.17": {"country": "Russia", "tor": False},
    "192.168.1.10": {"country": "United States", "tor": False},
    "45.83.64.12": {"country": "North Korea", "tor": False},
}

# Countries that should always be blocked
BLOCKED_COUNTRIES = {"China", "Russia", "North Korea"}

# Regular expression to extract IPv4 addresses
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------
# Simulated IP lookup function
# --------------------------------------------------
def lookup_ip(ip):
    """
    Simulates an IP reputation / geolocation lookup.
    Returns a dictionary with country and tor status.
    """
    return IP_INTEL_DB.get(ip, {"country": "Unknown", "tor": False})


# --------------------------------------------------
# Main detection and blocking logic
# --------------------------------------------------
def main():
    # Ensure at least one log file is provided
    if len(sys.argv) < 2:
        print("Usage: python block_ips.py <logfile1> [logfile2 ...]")
        sys.exit(1)

    blocked_ips = set()  # Track already blocked IPs to avoid duplicates

    # Iterate over each log file provided
    for logfile in sys.argv[1:]:
        try:
            with open(logfile, "r") as f:
                for line in f:
                    # Extract IP addresses from each log line
                    ips = IP_REGEX.findall(line)

                    for ip in ips:
                        if ip in blocked_ips:
                            continue

                        intel = lookup_ip(ip)
                        country = intel["country"]
                        is_tor = intel["tor"]

                        # Blocking conditions
                        if is_tor or country in BLOCKED_COUNTRIES:
                            blocked_ips.add(ip)

                            reason = []
                            if country != "Unknown":
                                reason.append(country)
                            if is_tor:
                                reason.append("Tor Exit Node")

                            reason_text = ", ".join(reason) if reason else "suspicious activity"

                            print(
                                f"[BLOCKED] IP {ip} ({reason_text}) has been blocked."
                            )

        except FileNotFoundError:
            print(f"[ERROR] Log file not found: {logfile}")
        except PermissionError:
            print(f"[ERROR] Permission denied: {logfile}")


# --------------------------------------------------
# Entry point
# --------------------------------------------------
if __name__ == "__main__":
    main()
