# PCAP Bloodhound

A desktop threat-hunting tool that analyzes Wireshark packet captures with visual dashboards. No command-line expertise required.

## Features

### Threat Hunting
- **C2 Beaconing Detection** — Identifies implant heartbeats via coefficient of variation analysis
- **DNS Tunneling** — Scores query entropy, flags long subdomains, detects suspicious record types
- **NTLM Hash Extraction** — Parses NTLMSSP exchanges, outputs Hashcat mode 5600 format
- **Cleartext Credentials** — Detects HTTP Basic Auth, FTP, SMTP AUTH LOGIN, form POST passwords
- **Exfiltration Profiling** — Flags high-asymmetry outbound flows exceeding 1 MB

### Network Troubleshooting
- **Connection Failures** — TCP resets, ICMP unreachable, silently dropped SYNs
- **DNS Health** — NXDOMAIN, SERVFAIL, timeouts, slow queries (>500ms)
- **TLS/SSL Inspection** — SNI extraction, cert parsing, SSL-inspection product detection
- **Traffic Timeline** — Packets/bytes per second, spike detection, top conversations

## Download

Download the latest release from [Releases](https://github.com/BardSec/pcap-bloodhound/releases).

- **macOS**: `PCAP Bloodhound.app`
- **Windows**: Coming soon

## Building from Source

### Prerequisites

- Python 3.12+
- pip

### Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run from source

```bash
python -m app.main
```

### Build standalone app

```bash
pyinstaller build/bloodhound.spec
```

The `.app` bundle will be in `dist/`.

## Usage

1. Open the application
2. Click **Open PCAP File** in the sidebar
3. Select a `.pcap`, `.pcapng`, or `.cap` file
4. Wait for analysis to complete (progress shown in sidebar)
5. Browse results across 9 analyzer tabs
6. Click **Export JSON** to save full results (includes raw credentials for IR)

## Tech Stack

- **Python 3.12** — Core language
- **PySide6 (Qt 6)** — Desktop GUI framework
- **Scapy** — Packet parsing and protocol analysis
- **QtCharts** — Interactive data visualizations
- **PyInstaller** — Standalone binary packaging

## License

MIT
