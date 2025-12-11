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

---

## 🏁 Usage

### Run with one log file:
```bash
python block_ips.py logs/app.log
