# Mini Fail2Ban – Christmas Rush IP Blocking Script

A lightweight Python tool that mimics Fail2Ban-style behavior by scanning application logs, detecting suspicious IPs, enriching data via a mock IPLocate lookup, and blocking high-risk addresses.

This project was created for a holiday-themed security challenge where increased malicious activity required automatic blocking of Tor exit nodes and traffic from high-risk countries.



#### Python code

#!/usr/bin/env python3
"""
Christmas Rush: Mini Fail2Ban Module
------------------------------------
Scans log files, extracts IP addresses, enriches them with mock IPLocate data,
and blocks suspicious IPs (Tor exit nodes or high-risk countries).

Run:
    python block_ips.py app1.log app2.log
"""

import re
import sys
from typing import Set, Dict

# ---------------------------------------------
# Mock "IPLocate" enrichment
# In real usage, replace this with an actual API call.
# ---------------------------------------------
def mock_ip_lookup(ip: str) -> Dict[str, str]:
    """
    Pretend IP lookup. Replace this stub with IPLocate API requests if needed.

    Returns:
        dict containing:
        - country: Country name
        - is_tor: Bool flag for Tor exit nodes
    """
    tor_ips = {"203.0.113.42", "10.99.88.77"}  # Example Tor IPs
    china_ips = {"203.0.113.42"}               # Example Chinese IPs
    russia_ips = {"198.51.100.17"}
    nk_ips = {"203.0.113.99"}

    if ip in china_ips:
        return {"country": "China", "is_tor": ip in tor_ips}

    if ip in russia_ips:
        return {"country": "Russia", "is_tor": ip in tor_ips}

    if ip in nk_ips:
        return {"country": "North Korea", "is_tor": ip in tor_ips}

    # Default "safe" IP
    return {"country": "Unknown", "is_tor": ip in tor_ips}


# ---------------------------------------------
# IP extraction regex (IPv4 only)
# ---------------------------------------------
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ---------------------------------------------
# Main blocking logic
# ---------------------------------------------
def process_logs(files: list[str]) -> None:
    already_blocked: Set[str] = set()

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    # Extract IPs from each line
                    match = IP_REGEX.search(line)
                    if not match:
                        continue

                    ip = match.group(0)

                    # Skip if we already blocked it
                    if ip in already_blocked:
                        continue

                    # Enrich using "IPLocate"
                    info = mock_ip_lookup(ip)
                    country = info["country"]
                    is_tor = info["is_tor"]

                    # Blocking rules
                    high_risk_countries = {"China", "Russia", "North Korea"}

                    if is_tor or country in high_risk_countries:
                        reason = []

                        if country in high_risk_countries:
                            reason.append(country)

                        if is_tor:
                            reason.append("Tor Exit Node")

                        reason_str = ", ".join(reason)

                        print(f"[BLOCKED] IP {ip} ({reason_str}) has been blocked.")
                        already_blocked.add(ip)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}")
        except PermissionError:
            print(f"[ERROR] Permission denied: {filepath}")


# ---------------------------------------------
# CLI entry point
# ---------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python block_ips.py <logfile1> [logfile2 ...]")
        sys.exit(1)

    process_logs(sys.argv[1:])



---

##  Features
- Extracts IP addresses from one or more log files  
- Blocks IPs that:
  - Are Tor exit nodes  
  - Originate from China, Russia, or North Korea  
- Prevents duplicate block events  
- Mock IPLocate data built in (safe & offline)
- Clear, readable console output  
- Simple, dependency-free Python script  

## 📁 File Structure
mini-fail2ban/
│
├── block_ips.py       # Main script
├── README.md          # This documentation
└── .gitignore         # Git ignore rules


---

##  Usage

### Run with one log file:
```bash
python block_ips.py logs/app.log

-----

🔧 How It Works

The script scans each log file line-by-line.

It extracts IPv4 addresses using a regex.

For each IP, a mock IPLocate lookup provides:

Country

Tor exit node flag

If an IP meets blocking criteria, a message is printed.

The same IP will not be blocked twice.
