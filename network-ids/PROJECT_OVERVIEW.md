# Network Intrusion Detection System (NIDS)

## METADATA
```
project: Network Intrusion Detection System (NIDS)
course: System Security — Midterm Project
developer: 1 person
duration: 3 weeks
stack: Python 3, Scapy, Flask, SQLite, Chart.js, Flask-SocketIO
os_requirement: Linux (Ubuntu 20.04+ recommended)
privilege_requirement: root/sudo (required for packet sniffing and iptables)
```

---

## SECTION: PROJECT_OBJECTIVES

The system must achieve the following goals:
1. Capture and analyze live network traffic in real time.
2. Detect intrusion behaviors: port scanning, brute-force login, ARP spoofing, flood/DDoS, ping sweep.
3. Automatically respond to threats by blocking offending IPs.
4. Expose all data through a web dashboard with real-time visualization.
5. Maintain structured logs and alert history in a local SQLite database.

---

## SECTION: SYSTEM_ARCHITECTURE

```
[Network Interface]
        |
        v (Scapy packet sniffing)
[Packet Analysis Engine]
   |-- Rule-Based Detection
   |-- Threshold-Based Detection
        |
        +--> [SQLite Database]         # logs, alerts, IP lists
        |       - PacketLog
        |       - AlertHistory
        |       - IPList (whitelist/blacklist)
        |
        +--> [Auto-Response Engine]    # iptables blocking, rate limiting
        |
        v
[Flask Web Dashboard]                 # served at http://localhost:5000
   |-- Real-time traffic chart (WebSocket)
   |-- Alert feed with severity levels
   |-- IP whitelist/blacklist management
   |-- Threat heatmap (hour x day-of-week)
   |-- Protocol distribution chart
   |-- Log viewer with CSV export
```

---

## SECTION: FEATURES

### FEATURE_GROUP: detection

| feature_id | name | description | implementation_hint |
|---|---|---|---|
| DET-01 | Port Scan Detection | Count unique destination ports from one source IP within a sliding time window. Trigger alert if count exceeds threshold. | Scapy TCP/SYN filter; use `collections.defaultdict` with timestamps |
| DET-02 | Brute-Force Detection | Count failed connection attempts to SSH (22), FTP (21), HTTP (80/443) from one source IP. | Track SYN packets per port per IP; threshold = 20 attempts / 10s |
| DET-03 | ARP Spoofing Detection | Maintain an IP-to-MAC mapping table. Alert if an ARP reply maps a known IP to a new MAC address. | Scapy ARP layer filter; store mapping in dict; compare on each reply |
| DET-04 | Flood / Mini-DDoS Detection | Count total packets per source IP per second. Alert if rate exceeds threshold. | Rolling counter per IP; reset every 1s interval |
| DET-05 | Ping Sweep Detection | Count unique destination IPs targeted with ICMP echo requests from one source. | Scapy ICMP filter; track unique dst IPs per src IP per 5s window |

### FEATURE_GROUP: response

| feature_id | name | description | implementation_hint |
|---|---|---|---|
| RES-01 | Real-time Alerts | Generate alert records with fields: timestamp, src_ip, threat_type, severity, details. Severity levels: LOW / MEDIUM / HIGH / CRITICAL | Write to AlertHistory table; emit via SocketIO to dashboard |
| RES-02 | IP Auto-Blocking | Execute `iptables -A INPUT -s <ip> -j DROP` when an IP triggers a HIGH or CRITICAL alert. | Use `subprocess.run()`; check for duplicates before inserting rule |
| RES-03 | Whitelist / Blacklist Management | Allow admin to add/remove IPs from whitelist (never block) or blacklist (always block). | Store in IPList table; check before processing any packet |
| RES-04 | Rate Limiting | For MEDIUM-severity IPs, throttle instead of hard block using iptables rate-limit rules. | `iptables -A INPUT -s <ip> -m limit --limit 10/min -j ACCEPT` |

### FEATURE_GROUP: dashboard

| feature_id | name | description | implementation_hint |
|---|---|---|---|
| DSH-01 | Real-time Traffic Chart | Line chart showing packets/second over a 60-second rolling window. | Flask-SocketIO pushes data every 1s; Chart.js renders on frontend |
| DSH-02 | Alert Feed | Live scrollable list of alerts with: timestamp, src IP, threat type, severity badge. | SocketIO event `new_alert`; frontend appends rows dynamically |
| DSH-03 | Threat Heatmap | 2D grid: X = hour of day (0–23), Y = day of week (Mon–Sun), cell = alert count. | Aggregate AlertHistory by hour+weekday; render with CSS grid or Chart.js matrix |
| DSH-04 | Protocol Distribution | Pie chart: percentage breakdown of TCP / UDP / ICMP / Other traffic. | Count by protocol in PacketLog; update every 5s via REST endpoint |
| DSH-05 | Log Viewer + CSV Export | Paginated table of PacketLog entries with filters (IP, protocol, time range). Export filtered view as CSV. | Flask endpoint `/api/logs?page=&ip=&proto=`; CSV via Python `csv` module |

### FEATURE_GROUP: logging

| feature_id | name | description | implementation_hint |
|---|---|---|---|
| LOG-01 | Structured Packet Logging | Store per-packet: id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, payload_size | SQLAlchemy model `PacketLog`; bulk insert every 100 packets for performance |
| LOG-02 | Alert History | Store per-alert: id, timestamp, src_ip, threat_type, severity, status (new/acknowledged/resolved) | SQLAlchemy model `AlertHistory`; status updatable via dashboard |

---

## SECTION: DATABASE_SCHEMA

```sql
-- PacketLog
CREATE TABLE packet_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    DATETIME NOT NULL,
    src_ip       TEXT NOT NULL,
    dst_ip       TEXT NOT NULL,
    protocol     TEXT NOT NULL,   -- 'TCP' | 'UDP' | 'ICMP' | 'OTHER'
    src_port     INTEGER,
    dst_port     INTEGER,
    payload_size INTEGER
);

-- AlertHistory
CREATE TABLE alert_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL,
    src_ip      TEXT NOT NULL,
    threat_type TEXT NOT NULL,   -- 'PORT_SCAN' | 'BRUTE_FORCE' | 'ARP_SPOOF' | 'FLOOD' | 'PING_SWEEP'
    severity    TEXT NOT NULL,   -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    details     TEXT,
    status      TEXT DEFAULT 'new'  -- 'new' | 'acknowledged' | 'resolved'
);

-- IPList
CREATE TABLE ip_list (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT UNIQUE NOT NULL,
    list_type   TEXT NOT NULL,   -- 'whitelist' | 'blacklist'
    added_at    DATETIME NOT NULL,
    reason      TEXT
);
```

---

## SECTION: PROJECT_STRUCTURE

```
network-ids/
│
├── core/
│   ├── sniffer.py          # Scapy packet capture; calls analyzer per packet
│   ├── analyzer.py         # Detection logic for all 5 threat types
│   └── responder.py        # iptables blocking, rate limiting, IP list checks
│
├── db/
│   ├── models.py           # SQLAlchemy ORM models
│   └── database.py         # Engine setup, session factory
│
├── api/
│   ├── routes.py           # REST endpoints: /api/logs, /api/alerts, /api/iplist
│   └── websocket.py        # SocketIO events: traffic_update, new_alert
│
├── dashboard/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/
│           ├── charts.js   # Chart.js setup for traffic, heatmap, protocol pie
│           └── alerts.js   # Alert feed rendering
│
├── config.py               # All thresholds and tunable parameters (see below)
├── main.py                 # Entry point: starts sniffer thread + Flask server
├── requirements.txt
└── README.md
```

---

## SECTION: CONFIGURATION

All detection thresholds are centralized in `config.py`:

```python
# config.py

NETWORK_INTERFACE = "eth0"          # Change to match your interface (use `ip a`)
FLASK_PORT = 5000

# Detection thresholds
PORT_SCAN_THRESHOLD = 15            # unique ports within time window
PORT_SCAN_WINDOW_SEC = 5

BRUTE_FORCE_THRESHOLD = 20          # attempts within time window
BRUTE_FORCE_WINDOW_SEC = 10
BRUTE_FORCE_PORTS = [22, 21, 80, 443]

FLOOD_PACKET_RATE_THRESHOLD = 500   # packets per second from one IP

PING_SWEEP_HOST_THRESHOLD = 10      # unique dst IPs within time window
PING_SWEEP_WINDOW_SEC = 5

# Response
AUTO_BLOCK_SEVERITIES = ["HIGH", "CRITICAL"]
RATE_LIMIT_SEVERITIES = ["MEDIUM"]

# Logging
DB_PATH = "db/nids.sqlite"
BULK_INSERT_BATCH_SIZE = 100
```

---

## SECTION: TECHNOLOGY_STACK

| layer | technology | version | purpose |
|---|---|---|---|
| packet_capture | Scapy | 2.5+ | Sniff and parse raw packets |
| detection_engine | Python | 3.10+ | Rule-based and threshold-based analysis |
| database | SQLite + SQLAlchemy | 2.0+ | Persist logs, alerts, IP lists |
| web_backend | Flask + Flask-SocketIO | Flask 3.x | REST API + WebSocket push |
| web_frontend | HTML/CSS/JS + Chart.js | Chart.js 4.x | Dashboard rendering |
| ip_blocking | iptables | system | Firewall rule injection |

---

## SECTION: DEVELOPMENT_PLAN

### WEEK_1: Core Engine (Days 1–7)
- Day 1–2: Initialize project structure, virtual environment, install all dependencies
- Day 3–4: Implement `sniffer.py` — capture TCP/UDP/ICMP, extract metadata, bulk-log to DB
- Day 5–6: Implement detection rules in `analyzer.py`: DET-01 (Port Scan), DET-04 (Flood), DET-05 (Ping Sweep)
- Day 7: Manual test with Nmap and hping3; validate DB entries; fix false-positive rates

### WEEK_2: Advanced Detection + Response (Days 8–14)
- Day 8–9: Implement DET-02 (Brute-Force) and DET-03 (ARP Spoofing)
- Day 10–11: Implement `responder.py`: RES-02 (Auto-Block), RES-03 (IP List), RES-04 (Rate Limiting)
- Day 12–13: Implement RES-01 (Alert generation + SocketIO emit)
- Day 14: Full pipeline integration test; verify alerts trigger correct responses

### WEEK_3: Dashboard + Polish (Days 15–21)
- Day 15–16: Build Flask REST API (`routes.py`) and SocketIO events (`websocket.py`)
- Day 17–18: Build dashboard: DSH-01 (traffic chart), DSH-02 (alert feed)
- Day 19: Add DSH-03 (heatmap), DSH-04 (protocol pie), DSH-05 (log viewer + CSV export)
- Day 20: End-to-end testing with all attack scenarios; tune thresholds
- Day 21: Code cleanup, documentation, demo preparation

---

## SECTION: ATTACK_TESTING_GUIDE

> Prerequisites: Use a local lab environment.
> Recommended setup: two Linux VMs on the same network (Attacker VM + Target VM running NIDS).

### LAB_ENVIRONMENT
```
Attacker VM : 192.168.1.100  (Kali Linux or Ubuntu with tools installed)
Target VM   : 192.168.1.50   (Ubuntu — runs NIDS, has SSH/FTP/HTTP services active)
Network     : Host-only or NAT network in VirtualBox/VMware
```

Start NIDS on Target VM before running any test:
```bash
sudo python3 main.py --interface eth0
# Dashboard accessible at http://localhost:5000
```

---

### TEST_CASE: TC-01 — Port Scan Detection (covers DET-01)

**Objective:** Verify that an Nmap SYN scan triggers a PORT_SCAN alert.

**Tools required:** `nmap`

```bash
# On Attacker VM — SYN scan
sudo nmap -sS 192.168.1.50

# Full connect scan
nmap -sT 192.168.1.50

# UDP scan
sudo nmap -sU 192.168.1.50
```

**Expected result:**
- `alert_history.threat_type = 'PORT_SCAN'`
- `alert_history.severity = 'HIGH'` or `'CRITICAL'`
- Source IP `192.168.1.100` appears in alert feed within 5 seconds
- iptables DROP rule added for `192.168.1.100`

**Verify block was applied:**
```bash
# On Target VM
sudo iptables -L INPUT -n | grep 192.168.1.100
```

---

### TEST_CASE: TC-02 — Brute-Force Detection (covers DET-02)

**Objective:** Verify repeated SSH login attempts trigger a BRUTE_FORCE alert.

**Tools required:** `hydra`

```bash
# Ensure SSH is running on Target VM
sudo systemctl start ssh

# On Attacker VM — SSH brute force with wordlist
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50

# Faster test with smaller wordlist
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 ssh://192.168.1.50
```

**Manual test (no hydra required):**
```bash
# On Attacker VM
for i in $(seq 1 30); do ssh -o ConnectTimeout=1 wronguser@192.168.1.50; done
```

**Expected result:**
- `alert_history.threat_type = 'BRUTE_FORCE'`
- `alert_history.severity = 'HIGH'`
- Alert triggered after 20 failed SYN attempts on port 22

---

### TEST_CASE: TC-03 — ARP Spoofing Detection (covers DET-03)

**Objective:** Verify ARP reply spoofing triggers an ARP_SPOOF alert.

**Tools required:** `arpspoof` (from dsniff package) or `ettercap`

```bash
# On Attacker VM — enable IP forwarding first
sudo echo 1 > /proc/sys/net/ipv4/ip_forward

# Spoof ARP: tell Target that Gateway's IP is at attacker's MAC
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# In second terminal — reverse direction
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.50
```

**Alternative using ettercap:**
```bash
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.50// /192.168.1.1//
```

**Expected result:**
- `alert_history.threat_type = 'ARP_SPOOF'`
- `alert_history.severity = 'CRITICAL'`
- Dashboard shows IP-MAC conflict: IP `192.168.1.1` remapped to attacker MAC

---

### TEST_CASE: TC-04 — Flood / Mini-DDoS Detection (covers DET-04)

**Objective:** Verify high-rate packet flooding triggers a FLOOD alert.

**Tools required:** `hping3`

```bash
# On Attacker VM

# TCP SYN flood
sudo hping3 -S -p 80 --flood 192.168.1.50

# UDP flood
sudo hping3 --udp -p 53 --flood 192.168.1.50

# ICMP flood
sudo hping3 --icmp --flood 192.168.1.50
```

**Expected result:**
- `alert_history.threat_type = 'FLOOD'`
- `alert_history.severity = 'CRITICAL'`
- Packet rate exceeds `FLOOD_PACKET_RATE_THRESHOLD` (default: 500 pps)
- Source IP auto-blocked via iptables
- Dashboard DSH-01 (traffic chart) shows a sudden spike

---

### TEST_CASE: TC-05 — Ping Sweep Detection (covers DET-05)

**Objective:** Verify ICMP host discovery triggers a PING_SWEEP alert.

**Tools required:** `nmap` or `fping`

```bash
# On Attacker VM
sudo nmap -sn 192.168.1.0/24

# Alternative with fping
fping -a -g 192.168.1.0/24 2>/dev/null
```

**Expected result:**
- `alert_history.threat_type = 'PING_SWEEP'`
- `alert_history.severity = 'MEDIUM'`
- Alert fires after hitting `PING_SWEEP_HOST_THRESHOLD` unique destination IPs (default: 10)

---

### TEST_CASE: TC-06 — Whitelist Bypass (covers RES-03)

**Objective:** Verify whitelisted IPs are never blocked, even under attack conditions.

**Steps:**
1. Add attacker IP to whitelist via dashboard API:
```bash
curl -X POST http://localhost:5000/api/iplist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "type": "whitelist"}'
```
2. Run any attack from TC-01 through TC-05 from `192.168.1.100`
3. Confirm no iptables DROP rule is added; alerts are still generated (monitoring continues)

**Expected result:**
- No iptables block applied for whitelisted IP
- Alert still logged to `alert_history` with all details

---

### TEST_CASE: TC-07 — Rate Limiting (covers RES-04)

**Objective:** Verify MEDIUM severity IPs are rate-limited instead of hard-blocked.

**Steps:**
1. Confirm config: `AUTO_BLOCK_SEVERITIES = ["HIGH", "CRITICAL"]` (MEDIUM excluded)
2. Run TC-05 (Ping Sweep) — expected severity is MEDIUM
3. Check iptables on Target VM:

```bash
sudo iptables -L INPUT -n -v
```

**Expected result:**
- Rate-limit rule present: `-A INPUT -s 192.168.1.100 -m limit --limit 10/min -j ACCEPT`
- No DROP rule for this IP

---

### TESTING_CHECKLIST

| test_id | attack_type | tool | alert_triggered | auto_blocked | dashboard_updated |
|---|---|---|---|---|---|
| TC-01 | Port Scan | nmap -sS | [ ] | [ ] | [ ] |
| TC-02 | Brute Force SSH | hydra | [ ] | [ ] | [ ] |
| TC-03 | ARP Spoofing | arpspoof | [ ] | [ ] | [ ] |
| TC-04 | Flood / DDoS | hping3 --flood | [ ] | [ ] | [ ] |
| TC-05 | Ping Sweep | nmap -sn | [ ] | [ ] | [ ] |
| TC-06 | Whitelist Bypass | any | [ ] | [ ] | [ ] |
| TC-07 | Rate Limiting | nmap -sn | [ ] | [ ] | [ ] |

---

## SECTION: EXPECTED_OUTCOMES

- NIDS running on Linux, sniffing live traffic with root privileges
- 5 detection modules active and individually testable
- Web dashboard at `http://localhost:5000` with real-time data
- Confirmed auto-blocking via iptables for HIGH/CRITICAL threats
- Structured logs queryable via dashboard and exportable to CSV
- All 7 test cases in TESTING_CHECKLIST passing

---

## SECTION: LIMITATIONS

- Single-host monitoring only; no distributed/multi-agent support
- Rule-based detection; may produce false positives on high-traffic networks
- Requires root — not suitable for restricted environments
- Encrypted payloads (TLS/HTTPS) are not inspected; only packet metadata is analyzed
- ARP spoofing detection works only on the same broadcast domain (Layer 2)

---

## SECTION: FUTURE_IMPROVEMENTS

- Add ML-based anomaly detection (Isolation Forest, Random Forest) as a second detection layer
- PCAP file ingestion for offline forensic analysis
- Multi-host agent architecture with central aggregation server
- Dashboard authentication (login page, session tokens)
- IPv6 support (current implementation targets IPv4 only)

---

## SECTION: REFERENCES

- Scapy documentation: https://scapy.readthedocs.io
- Flask documentation: https://flask.palletsprojects.com
- Flask-SocketIO: https://flask-socketio.readthedocs.io
- Nmap reference guide: https://nmap.org/book/man.html
- hping3 manual: http://www.hping.org/manpage.html
- OWASP detection techniques: https://owasp.org
- Bejtlich, R. (2004). The Tao of Network Security Monitoring. Addison-Wesley.