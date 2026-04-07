# PCAP Detective

A desktop threat-hunting tool that analyzes Wireshark packet captures with interactive visual dashboards. No command-line expertise required.

## Features

### Threat Hunting
- **C2 Beaconing Detection** — Identifies implant heartbeats via coefficient of variation analysis
- **DNS Tunneling** — Scores query entropy, flags long subdomains, detects suspicious record types
- **NTLM Hash Extraction** — Parses NTLMSSP exchanges, outputs Hashcat mode 5600 format
- **Cleartext Credentials** — Detects HTTP Basic Auth, FTP, SMTP AUTH LOGIN, form POST passwords
- **Exfiltration Profiling** — Flags high-asymmetry outbound flows exceeding 1 MB
- **Lateral Movement Detection** — Identifies internal-to-internal connections on SMB, RPC, RDP, WinRM, SSH, and Telnet ports; detects scan patterns across 5+ internal targets
- **DGA Detection** — Identifies Domain Generation Algorithm activity through entropy analysis and pattern matching on DNS queries
- **Data Staging** — Detects patterns indicative of data collection and preparation before exfiltration
- **Suspicious User-Agents** — Flags abnormal HTTP User-Agent strings associated with malware and exploitation tools
- **PowerShell/WMI Activity** — Detects network activity from PowerShell and WMI operations

### Network Troubleshooting
- **Connection Failures** — TCP resets, ICMP unreachable, silently dropped SYNs
- **DNS Health** — NXDOMAIN, SERVFAIL, timeouts, slow queries (>500ms)
- **TLS/SSL Inspection** — SNI extraction, cert parsing, detection of 24+ SSL-inspection products (Zscaler, Palo Alto, Fortinet, etc.)
- **Traffic Timeline** — IO graphs, top conversations, endpoint summaries with automatic bin sizing and spike/gap detection

### K-12 / Education
- **Content Filter Bypass** — Detects attempts to circumvent school content filters
- **CIPA Compliance** — Analyzes web traffic for Children's Internet Protection Act compliance violations

### Network Visibility
- **VLAN Traffic** — Detects and maps 802.1Q VLAN-tagged traffic
- **DHCP Analysis** — Analyzes DHCP request/reply patterns
- **Broadcast Storms** — Detects excessive broadcast/multicast traffic indicating network problems
- **Service Discovery** — Identifies network services through mDNS, LLMNR, and protocol analysis

### Live Capture
Capture packets directly from the application without needing Wireshark or tcpdump. Select a network interface, set optional packet count and duration limits, and feed the capture straight into the analysis pipeline.

## Download

Download the latest release from [Releases](https://github.com/BardSec/pcap-detective/releases).

- **macOS**: `PCAP Detective.app`
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

## Live Capture Requirements

Live capture requires raw socket access, which varies by platform:

- **macOS** — BPF access at `/dev/bpf0`. Install Wireshark, Xcode Command Line Tools, or add your user to the `access_bpf` group.
- **Windows** — [Npcap](https://npcap.com) installed with API-compatible mode enabled.
- **Linux** — Root or `CAP_NET_RAW` capability: `sudo setcap cap_net_raw+ep $(which python3)`

## Usage

1. Open the application
2. Click **Open PCAP File** in the sidebar (or use **Live Capture** to sniff directly)
3. Select a `.pcap`, `.pcapng`, or `.cap` file
4. Wait for analysis to complete (progress shown in sidebar)
5. Browse results across 20 analyzer tabs
6. Click **Export JSON** to save full results (includes raw credentials for IR)

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
