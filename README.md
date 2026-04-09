# PCAP Detective

A desktop threat-hunting tool that analyzes Wireshark packet captures with interactive visual dashboards. No command-line expertise required.

## Install

**macOS (Homebrew):**
```bash
brew tap BardSec/tap
brew install --cask pcap-detective
```

**macOS / Windows:** Download from [Releases](https://github.com/BardSec/pcap-detective/releases).

## What's New in v2.1.0

### Investigation Threads
Entity-centric investigation view that groups findings around hosts, domains, and endpoints. Each thread shows a narrative summary, risk score, related detections, and a timeline of events — so you can investigate an entity, not just browse analyzer tabs.

### Evidence-Based Findings
Every detection now includes a confidence score (0–100) built from weighted indicators, supporting evidence ("Why was this flagged?"), and alternative explanations ("Could also be"). Findings are framed as hypotheses, not conclusions.

### AI Analysis Integration
One-click "Copy for AI Analysis" button on any investigation thread packages the full context — findings, indicators, timeline, metadata — into a structured prompt you can paste into ChatGPT, Claude, or any AI assistant for guided next steps.

### Capture Metadata Layer
Per-host profiling, DNS baselines, and peer comparison enable metadata-first detection. The tool identifies outliers relative to the capture — hosts with unusual DNS volume, asymmetric traffic, or unique external destinations — even when TLS hides payload content.

### Entity Pivot Navigation
Click any IP or domain to jump to its investigation thread. Right-click any IP or domain in any table across all panels to pivot to the Investigation view.

### Sample Capture
New users can click "Try a sample investigation" in the sidebar to load a bundled PCAP that triggers all major analyzers — no capture file needed to explore the tool.

## Features

### Threat Hunting
- **C2 Beaconing Detection** — Identifies implant heartbeats via coefficient of variation analysis
- **DNS Tunneling** — Scores query entropy, flags long subdomains, detects suspicious record types
- **NTLM Hash Extraction** — Parses NTLMSSP exchanges, outputs Hashcat mode 5600 format
- **Cleartext Credentials** — Detects HTTP Basic Auth, FTP, SMTP AUTH LOGIN, form POST passwords (masked by default, reveal on click)
- **Exfiltration Profiling** — Flags high-asymmetry outbound flows exceeding 1 MB
- **Lateral Movement Detection** — Identifies internal-to-internal connections on SMB, RPC, RDP, WinRM, SSH, and Telnet; detects scan patterns across 5+ internal targets
- **DGA Detection** — Identifies Domain Generation Algorithm activity through entropy analysis and pattern matching
- **Data Staging** — Detects data collection and preparation patterns before exfiltration
- **Suspicious User-Agents** — Flags abnormal HTTP User-Agent strings associated with malware and exploitation tools
- **PowerShell/WMI Activity** — Detects network activity from PowerShell and WMI operations

### K-12 / Education
- **Content Filter Bypass** — Detects VPN/proxy bypass attempts, unauthorized DNS resolvers, DoH/DoT
- **CIPA Compliance** — Verifies web traffic passes through recognized content filters
- **Student Data Exposure** — Scans cleartext traffic for student PII (SSNs, DOBs, student IDs, email patterns) and unencrypted SIS/EdTech API traffic — FERPA/COPPA relevant
- **Vendor Traffic** — Identifies EdTech vendor connections, flags unencrypted vendor traffic, bulk data exports, and third-party analytics/tracking domains

### Network Visibility
- **Connection Failures** — TCP resets, ICMP unreachable, silently dropped SYNs
- **DNS Health** — NXDOMAIN, SERVFAIL, timeouts, slow queries (>500ms)
- **TLS/SSL Inspection** — SNI extraction, cert parsing, detection of 24+ SSL-inspection products
- **Traffic Timeline** — IO graphs, top conversations, endpoint summaries with spike/gap detection
- **VLAN Traffic** — Detects and maps 802.1Q VLAN-tagged traffic
- **DHCP Analysis** — Analyzes DHCP request/reply patterns
- **Broadcast Storms** — Detects excessive broadcast/multicast traffic
- **Service Discovery** — Identifies network services through protocol analysis

### Industry Packs (toggleable)
- **Financial Services** — PCI DSS compliance, FIX/Bloomberg/SWIFT protocol detection
- **Healthcare** — HIPAA compliance, medical device and protocol detection
- **Energy / Utilities** — ICS/SCADA protocol detection, IT/OT segmentation analysis

### Live Capture
Capture packets directly from the application without needing Wireshark or tcpdump. Select a network interface, set optional packet count and duration limits, and feed the capture straight into the analysis pipeline.

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

## Live Capture Requirements

Live capture requires raw socket access, which varies by platform:

- **macOS** — BPF access at `/dev/bpf0`. Install Wireshark, Xcode Command Line Tools, or add your user to the `access_bpf` group.
- **Windows** — [Npcap](https://npcap.com) installed with API-compatible mode enabled.
- **Linux** — Root or `CAP_NET_RAW` capability: `sudo setcap cap_net_raw+ep $(which python3)`

## Usage

1. Open the application
2. Click **Try a sample investigation** for a guided tour, or **Open PCAP File** to analyze your own capture
3. Browse results across analyzer panels in the sidebar
4. Click **Investigation** to see entity-centric findings with confidence scores and evidence
5. Click any IP or domain to pivot between related findings
6. Use **Copy for AI Analysis** on any investigation thread for AI-assisted guidance
7. Click **Export JSON** to save full results

## Tech Stack

- **Python 3.12** — Core language
- **PySide6 (Qt 6)** — Desktop GUI framework
- **Scapy** — Packet parsing and protocol analysis
- **NumPy** — Statistical calculations (CV analysis, entropy scoring)
- **cryptography** — Certificate parsing and TLS handling
- **QtCharts** — Interactive data visualizations
- **PyInstaller** — Standalone binary packaging

## License

MIT
