# Mini Fail2Ban – Christmas Rush IP Blocking Script

A lightweight Python tool that mimics Fail2Ban-style behavior by scanning application logs, detecting suspicious IPs, enriching data via a mock IPLocate lookup, and blocking high-risk addresses.

This project was created for a holiday-themed security challenge where increased malicious activity required automatic blocking of Tor exit nodes and traffic from high-risk countries.

---

## 🎅 Features
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

## 🏁 Usage

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
