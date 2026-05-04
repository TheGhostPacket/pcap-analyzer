# 🔍 PCAP Network Threat Analyzer

A professional network packet capture analysis tool that detects real threats from `.pcap` files. Built with Python Flask and Scapy.

## What It Detects

| Detection | Technique |
|-----------|-----------|
| **Port Scanning** | Vertical (many ports, one host) and horizontal (one port, many hosts) via SYN packet analysis |
| **ARP Spoofing** | Conflicting IP-to-MAC mappings in ARP reply packets — indicator of MITM attacks |
| **DNS Tunneling** | Long subdomains, high Shannon entropy queries, excessive unique DNS queries |
| **Brute Force** | SSH (port 22), FTP (port 21), HTTP/S — SYN flood pattern detection |
| **ICMP Flood** | High-volume echo request detection (DoS/DDoS indicator) |
| **Suspicious Ports** | Metasploit (4444), Tor (9001/9050), IRC botnet C2 (6666/6667), and others |
| **Large Transfers** | Single-host data volume anomalies (potential exfiltration) |

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Navigate to `http://localhost:5000` and upload a `.pcap` file.

## Supported Formats

- `.pcap` (Wireshark, tcpdump)
- `.pcapng` (next-generation format)
- `.cap` (various tools)
- Max file size: 50MB

## Getting Sample PCAPs to Test

```bash
# Capture live traffic (requires root/sudo)
sudo tcpdump -i eth0 -w capture.pcap -c 1000

# Or download sample PCAPs from:
# https://wiki.wireshark.org/SampleCaptures
# https://www.malware-traffic-analysis.net/
```

## Tech Stack

- **Backend**: Python 3.10+, Flask, Scapy
- **Analysis**: Shannon entropy, statistical thresholds, protocol-specific heuristics
- **Frontend**: Vanilla JS, DM Sans + Syne fonts (matches TheGhostPacket portfolio)
- **Export**: CSV report generation

## Project Structure

```
pcap-analyzer/
├── app.py              # Flask routes
├── analyzer.py         # Core detection engine
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/app.js
└── uploads/            # Temp storage (auto-cleaned)
```

## Author

[TheGhostPacket](https://theghostpacket.com) — Nhyira Yanney
