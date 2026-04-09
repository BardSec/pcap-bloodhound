# PCAP Bloodhound (PCAP Detective)

Desktop threat-hunting tool for analyzing Wireshark packet captures. Detects C2
beaconing, DNS tunneling, NTLM hashes, cleartext credentials, data exfiltration,
and more with interactive visual dashboards.

## Stack

- Python 3.12 / PySide6 (Qt 6) + QtCharts
- Scapy 2.6 for packet parsing
- NumPy 2.0 for statistical analysis (CV, entropy)
- cryptography 44.0 for certificate parsing
- PyInstaller 6.0+ for standalone packaging

## Project Layout

```
app/
  main.py             # Entry point — QApplication
  ui/
    main_window.py    # Main window with category nav
    capture_dialog.py # Live capture UI
    theme.py          # Dark theme
    panels/           # 20+ result tabs (c2_beacon, dns_tunnel, ntlm, exfil, etc.)
  analyzers/          # Threat detection modules (one dir per category)
  analysis/           # Core analysis engine + background runner
  settings.py         # Configuration
build/
  bloodhound.spec     # macOS PyInstaller spec
  bloodhound-win.spec # Windows PyInstaller spec
```

## Dev Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m app.main                # run from source
python -m app.main -p capture.pcap  # open a PCAP directly
```

## Key Patterns

- Follows the PySide6 Desktop App archetype from global CLAUDE.md
- `ANALYZER_CATEGORIES` registry drives nav, overview, and panel creation
- Each analyzer is a self-contained module in `app/analyzers/`
- QThread workers for background analysis with progress signals
- Vertical category nav (QListWidget) + QStackedWidget for panels
- Generic panel auto-renders dict/list data; custom panels for charts

## Live Capture Requirements

- macOS: BPF access (`/dev/bpf0`) — install Wireshark or add user to `access_bpf`
- Windows: Npcap with API-compatible mode
- Linux: root or `CAP_NET_RAW` capability

## Build

```bash
pyinstaller build/bloodhound.spec       # macOS → dist/PCAP Detective.app
pyinstaller build/bloodhound-win.spec   # Windows → dist/PCAP Detective.exe
```

Distributed via GitHub Releases + Homebrew Cask (`brew install --cask pcap-detective`).
