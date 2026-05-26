# NIDS — Implementation Guide

> Companion to `PROJECT_OVERVIEW.md`. This document is **prescriptive**: every file, every command, every parameter is concrete and production-ready. Feature IDs (`DET-*`, `RES-*`, `DSH-*`, `LOG-*`) are referenced in the docstring of every module so a reviewer can trace any line back to the spec.

## Table of contents

1. [Roadmap & thinking model](#1-roadmap--thinking-model)
2. [Part 1 — Environment, scaffolding, configuration, DB init](#part-1--environment-scaffolding-configuration-db-init)
3. [Part 2 — Database layer + Sniffer + Analyzer (DET-01…DET-05, LOG-01)](#part-2--database-layer--sniffer--analyzer)
4. [Part 3 — Response engine (RES-01…RES-04, LOG-02)](#part-3--response-engine)
5. [Part 4 — REST API, WebSocket, main entrypoint](#part-4--rest-api-websocket-main-entrypoint)
6. [Part 5 — Dashboard frontend (DSH-01…DSH-05)](#part-5--dashboard-frontend)
7. [Part 6 — Running the full system](#part-6--running-the-full-system)
8. [Part 7 — Common errors and fixes](#part-7--common-errors-and-fixes)

---

## 1. Roadmap & thinking model

A NIDS is a **producer/consumer pipeline with a side-channel UI**:

```
Scapy thread  ─►  Analyzer (in-memory counters)  ─►  Alerts table
       │                          │
       ▼                          ▼
  PacketLog table            Responder (iptables)
                                   │
                                   ▼
                              Flask + SocketIO  ◄── Browser
```

Two facts drive every design choice that follows:

1. **The sniffer needs raw sockets** → root + `libpcap`.
2. **The sniffer thread and the Flask thread share one SQLite file** → SQLite is opened with `check_same_thread=False` *and* writes are batched via `BULK_INSERT_BATCH_SIZE` to dodge lock contention.

Build order is bottom-up:

| Layer | Files | Reason it's built here |
|---|---|---|
| Foundation | `config.py`, `requirements.txt`, `init_db.py` | Nothing else compiles without these. |
| Persistence | `db/database.py`, `db/models.py` | Sniffer and responder both write through this. |
| Detection | `core/sniffer.py`, `core/analyzer.py` | Pure backend; can be tested without Flask. |
| Response | `core/responder.py` | Consumes alerts the analyzer emits. |
| Surface | `api/routes.py`, `api/websocket.py`, `main.py` | Glues backend to browser. |
| Dashboard | `dashboard/templates/index.html`, `static/js/*`, `static/css/style.css` | Frontend only depends on the API surface. |

---

## Part 1 — Environment, scaffolding, configuration, DB init

### 1.1 Operating-system preparation (Ubuntu 20.04 / 22.04 / 24.04)

```bash
# 1. System packages required by Scapy and the firewall layer
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    libpcap-dev tcpdump \
    iptables \
    net-tools iproute2 \
    build-essential

# 2. Verify Python version (must be >= 3.10 per spec)
python3 --version

# 3. Identify the interface you will sniff on
ip -brief addr
# Typical names: eth0, ens33, enp0s3, wlan0 — write yours down
```

> **Why `libpcap-dev`?** Scapy falls back to a slower pure-Python L2 socket if libpcap headers are missing; under `hping3 --flood` (TC-04) that fallback drops packets and produces false negatives.

### 1.2 Folder scaffolding

Reproduce the exact tree from `SECTION: PROJECT_STRUCTURE`:

```bash
mkdir -p network-ids/{core,db,api,dashboard/templates,dashboard/static/css,dashboard/static/js}
cd network-ids

# Python package markers
touch core/__init__.py db/__init__.py api/__init__.py

# Source files (filled in later sections)
touch core/sniffer.py core/analyzer.py core/responder.py
touch db/models.py db/database.py
touch api/routes.py api/websocket.py
touch dashboard/templates/index.html
touch dashboard/static/css/style.css
touch dashboard/static/js/charts.js dashboard/static/js/alerts.js
touch config.py main.py requirements.txt README.md init_db.py
```

### 1.3 Python virtualenv and dependencies

#### File: `network-ids/requirements.txt`

```text
scapy==2.5.0
Flask==3.0.3
Flask-SocketIO==5.3.6
python-socketio==5.11.4
python-engineio==4.9.1
simple-websocket==1.0.0
SQLAlchemy==2.0.30
```

**Why these exact versions:**

- `simple-websocket` lets Flask-SocketIO run in `async_mode="threading"` without pulling in `eventlet`. We deliberately avoid `eventlet` because its `monkey_patch()` interferes with Scapy's blocking raw socket calls.
- `SQLAlchemy==2.0.x` matches `SECTION: TECHNOLOGY_STACK` ("SQLite + SQLAlchemy 2.0+"). We use the 2.0-style API (`select()`, `Mapped[...]`).

#### Create & activate the venv

```bash
cd network-ids
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Smoke test
python -c "import scapy, flask, flask_socketio, sqlalchemy; print('deps OK')"
```

> **Run reminder:** Scapy needs root. Always launch the app via `sudo .venv/bin/python main.py` — do **not** `sudo` *after* activating the venv, because `sudo` drops your venv's `PATH`.

### 1.4 `config.py` — every parameter explained

#### File: `network-ids/config.py`

```python
"""
Central configuration for the NIDS.

Every threshold and tunable in the project is referenced from this module by
name. To change behavior, edit this file -- never hard-code values in engine
modules. Used by: core/sniffer.py, core/analyzer.py, core/responder.py,
db/database.py, api/*, main.py.
"""

# ---------------------------------------------------------------------------
# Network / server
# ---------------------------------------------------------------------------
NETWORK_INTERFACE = "eth0"
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# ---------------------------------------------------------------------------
# DET-01 Port Scan
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW_SEC = 5

# ---------------------------------------------------------------------------
# DET-02 Brute Force
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 20
BRUTE_FORCE_WINDOW_SEC = 10
BRUTE_FORCE_PORTS = [22, 21, 80, 443]

# ---------------------------------------------------------------------------
# DET-04 Flood / mini-DDoS
# ---------------------------------------------------------------------------
FLOOD_PACKET_RATE_THRESHOLD = 500   # packets per second from one source IP

# ---------------------------------------------------------------------------
# DET-05 Ping Sweep
# ---------------------------------------------------------------------------
PING_SWEEP_HOST_THRESHOLD = 10
PING_SWEEP_WINDOW_SEC = 5

# ---------------------------------------------------------------------------
# Response (RES-02, RES-04)
# ---------------------------------------------------------------------------
AUTO_BLOCK_SEVERITIES = ["HIGH", "CRITICAL"]
RATE_LIMIT_SEVERITIES = ["MEDIUM"]
RATE_LIMIT_RULE = "10/min"          # passed to iptables -m limit --limit

# ---------------------------------------------------------------------------
# Logging / persistence (LOG-01, LOG-02)
# ---------------------------------------------------------------------------
DB_PATH = "db/nids.sqlite"
BULK_INSERT_BATCH_SIZE = 100
FLUSH_INTERVAL_SEC = 2              # max seconds before a partial batch flushes
ALERT_COOLDOWN_SEC = 10             # suppress duplicate alerts for same (ip, type)
```

#### Parameter reference

| Parameter | Used by | Meaning & tuning advice |
|---|---|---|
| `NETWORK_INTERFACE` | `core/sniffer.py` | NIC Scapy binds to. Get it from `ip -brief addr`. **#1 setup error** if wrong. |
| `FLASK_HOST` / `FLASK_PORT` | `main.py` | Dashboard endpoint. Use `127.0.0.1` to restrict to local access. |
| `PORT_SCAN_THRESHOLD` | DET-01 | Unique destination ports per source IP. Lower → more sensitive, more false positives. 15 catches Nmap default scans. |
| `PORT_SCAN_WINDOW_SEC` | DET-01 | Sliding-window length in seconds. |
| `BRUTE_FORCE_THRESHOLD` | DET-02 | SYN packets to `BRUTE_FORCE_PORTS` per source IP. 20/10s matches Hydra `-t 4` default. |
| `BRUTE_FORCE_WINDOW_SEC` | DET-02 | Sliding window. |
| `BRUTE_FORCE_PORTS` | DET-02 | Monitored service ports. Extend with 3306/3389/5432 as needed. |
| `FLOOD_PACKET_RATE_THRESHOLD` | DET-04 | Packets per second per source. 500 is well above legit traffic, well below `hping3 --flood` (10k–100k pps). |
| `PING_SWEEP_HOST_THRESHOLD` | DET-05 | Unique destination IPs hit by ICMP echo. |
| `PING_SWEEP_WINDOW_SEC` | DET-05 | Sliding window. |
| `AUTO_BLOCK_SEVERITIES` | RES-02 | Severities that trigger `iptables -j DROP`. |
| `RATE_LIMIT_SEVERITIES` | RES-04 | Severities that trigger a `-m limit` rule. Must not overlap with `AUTO_BLOCK_SEVERITIES`. |
| `RATE_LIMIT_RULE` | RES-04 | Token-bucket spec passed to `iptables -m limit --limit`. |
| `DB_PATH` | `db/database.py` | SQLite file path, relative to project root. |
| `BULK_INSERT_BATCH_SIZE` | LOG-01 | Rows buffered before a single bulk insert. Higher = better throughput, higher loss-on-crash. |
| `FLUSH_INTERVAL_SEC` | LOG-01 | Max seconds before a partial batch is flushed (keeps the dashboard responsive on quiet networks). |
| `ALERT_COOLDOWN_SEC` | `core/analyzer.py` | Suppresses repeated alerts for the same `(src_ip, threat_type)` within this window. Prevents the dashboard from drowning in a flood. |

> **Tuning rule of thumb:** raise the threshold first; only shrink the window if an attacker beats the throughput limit. Window shrinkage inflates false positives faster than threshold raises.

### 1.5 Database initialization script

The schema declared in `db/models.py` (Part 2) is created here via `Base.metadata.create_all`. Reusing the model module keeps the schema in one place.

#### File: `network-ids/init_db.py`

```python
"""
One-shot database initializer.

Creates db/nids.sqlite with all three tables defined in db/models.py.
Run once after first checkout (re-running is safe -- create_all is idempotent):

    python init_db.py

To wipe the DB, delete the .sqlite file first, then re-run this script.
"""

import sys
from pathlib import Path

from sqlalchemy import inspect

import config
from db.database import engine, Base
import db.models  # noqa: F401  (import side-effect: registers models on Base)


def main() -> int:
    db_file = Path(config.DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(engine)

    tables = set(inspect(engine).get_table_names())
    expected = {"packet_log", "alert_history", "ip_list"}
    missing = expected - tables
    if missing:
        print(f"[FAIL] Missing tables after create_all: {missing}", file=sys.stderr)
        return 1

    print(f"[OK] Database ready at {db_file.resolve()}")
    print(f"     Tables: {sorted(tables)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run it **after Part 2 is in place**:

```bash
source .venv/bin/activate
python init_db.py
# Expected: [OK] Database ready at .../network-ids/db/nids.sqlite
#           Tables: ['alert_history', 'ip_list', 'packet_log']
```

---

## Part 2 — Database layer + Sniffer + Analyzer

### 2.1 Thinking before the code

The persistence layer is intentionally **thin**: one engine, one `Base`, one `session_scope()` context manager. Every module that writes to the DB uses `session_scope()` so that:

- Sessions auto-commit on success and roll back on exception.
- Sessions are short-lived → minimal SQLite lock contention.
- No module ever holds a session across threads.

The sniffer is a **two-thread component**:

1. The **capture thread** runs `scapy.sniff()` and calls the analyzer per packet.
2. The **flush thread** wakes every `FLUSH_INTERVAL_SEC` and forces a bulk insert of buffered rows, so the dashboard does not lag during quiet periods.

The analyzer is **pure in-memory**, no I/O. It returns alert dicts; the responder decides what to do with them. This separation makes detectors unit-testable without a database.

### 2.2 `db/database.py` — engine, Base, session factory

#### File: `network-ids/db/database.py`

```python
"""
SQLAlchemy engine, declarative Base, and session factory.

All other modules import these symbols and never construct their own engine.
SQLite is opened with check_same_thread=False because the sniffer thread and
the Flask request threads write concurrently; SQLAlchemy serializes the writes
via its connection pool.
"""

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

import config


_db_path = Path(config.DB_PATH)
_db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{_db_path}",
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


@contextmanager
def session_scope() -> Iterator[Session]:
    """Yield a session, commit on success, roll back on error, always close."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

**Connections to other modules**

- `init_db.py` imports `engine` and `Base` to run `create_all()`.
- `db/models.py` imports `Base` to declare ORM classes.
- `core/sniffer.py`, `core/responder.py`, `api/routes.py`, `api/websocket.py` all import `session_scope()` for short-lived writes/reads.

### 2.3 `db/models.py` — ORM models

#### File: `network-ids/db/models.py`

```python
"""
SQLAlchemy 2.0 ORM models for the three tables defined in
SECTION: DATABASE_SCHEMA of PROJECT_OVERVIEW.md.

  packet_log     -- LOG-01 (per-packet metadata)
  alert_history  -- LOG-02, RES-01 (detection results)
  ip_list        -- RES-03 (whitelist / blacklist)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


class PacketLog(Base):
    __tablename__ = "packet_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    payload_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")


class IPList(Base):
    __tablename__ = "ip_list"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    list_type: Mapped[str] = mapped_column(String(16), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
```

Run the database initializer now:

```bash
python init_db.py
```

### 2.4 `core/analyzer.py` — detection engine (DET-01…DET-05)

#### Thinking
- Five detectors, five data structures. Each detector follows the same pattern: *push timestamp into a deque → prune entries older than the window → check threshold*.
- All state is per-source-IP, kept in dictionaries. Memory is bounded because expired entries are pruned on every push.
- A short cooldown (`ALERT_COOLDOWN_SEC`) prevents a 10 000-pps flood from generating 10 000 identical alerts in the same second.
- All shared state lives behind a single `threading.Lock` — this is fine because detection is O(1) per packet.

#### File: `network-ids/core/analyzer.py`

```python
"""
Detection engine. Implements DET-01..DET-05 from PROJECT_OVERVIEW.md.

Each call to Analyzer.process(pkt, meta) returns a list of alert dicts.
The caller (sniffer) hands them to the Responder for persistence and action.

Alert dict shape (consumed by RES-01):
    {
        "timestamp":   datetime,
        "src_ip":      str,
        "threat_type": "PORT_SCAN" | "BRUTE_FORCE" | "ARP_SPOOF" | "FLOOD" | "PING_SWEEP",
        "severity":    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "details":     str,
    }
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque

import config


TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10


class Analyzer:
    def __init__(self) -> None:
        self._lock = threading.Lock()

        # DET-01: src_ip -> deque[(timestamp, dst_port)]
        self.port_scan: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)

        # DET-02: (src_ip, dst_port) -> deque[timestamp]
        self.brute_force: dict[tuple[str, int], Deque[float]] = defaultdict(deque)

        # DET-03: ip -> mac
        self.arp_table: dict[str, str] = {}

        # DET-04: src_ip -> [bucket_epoch_second, count_in_bucket]
        self.flood_counter: dict[str, list[int]] = defaultdict(lambda: [0, 0])

        # DET-05: src_ip -> deque[(timestamp, dst_ip)]
        self.ping_sweep: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)

        # Anti-storm: suppress repeat of (src_ip, threat_type) within cooldown
        self._cooldown: dict[tuple[str, str], float] = {}

    def process(self, pkt, meta: dict) -> list[dict]:
        alerts: list[dict] = []
        with self._lock:
            self._detect_flood(meta, alerts)
            proto = meta["protocol"]
            if proto == "TCP":
                self._detect_port_scan(meta, alerts)
                self._detect_brute_force(meta, alerts)
            elif proto == "ICMP":
                self._detect_ping_sweep(meta, alerts)
            elif proto == "ARP":
                self._detect_arp_spoof(meta, alerts)
        return [a for a in alerts if self._allow(a)]

    def _allow(self, alert: dict) -> bool:
        key = (alert["src_ip"], alert["threat_type"])
        now = time.time()
        if now - self._cooldown.get(key, 0.0) < config.ALERT_COOLDOWN_SEC:
            return False
        self._cooldown[key] = now
        return True

    # ---------------------------- DET-01 ----------------------------
    def _detect_port_scan(self, meta: dict, out: list[dict]) -> None:
        flags = meta.get("tcp_flags")
        if flags is None:
            return
        # Count SYN-only packets (Nmap -sS). SYN+ACK is a server response, ignore.
        if not (flags & TCP_FLAG_SYN) or (flags & TCP_FLAG_ACK):
            return

        src = meta["src_ip"]
        dq = self.port_scan[src]
        now = time.time()
        dq.append((now, meta["dst_port"]))

        cutoff = now - config.PORT_SCAN_WINDOW_SEC
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
            out.append({
                "timestamp": datetime.utcnow(),
                "src_ip": src,
                "threat_type": "PORT_SCAN",
                "severity": "HIGH",
                "details": (
                    f"{len(unique_ports)} unique ports in "
                    f"{config.PORT_SCAN_WINDOW_SEC}s"
                ),
            })

    # ---------------------------- DET-02 ----------------------------
    def _detect_brute_force(self, meta: dict, out: list[dict]) -> None:
        flags = meta.get("tcp_flags")
        if flags is None or not (flags & TCP_FLAG_SYN) or (flags & TCP_FLAG_ACK):
            return
        dport = meta.get("dst_port")
        if dport not in config.BRUTE_FORCE_PORTS:
            return

        src = meta["src_ip"]
        key = (src, dport)
        dq = self.brute_force[key]
        now = time.time()
        dq.append(now)

        cutoff = now - config.BRUTE_FORCE_WINDOW_SEC
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= config.BRUTE_FORCE_THRESHOLD:
            out.append({
                "timestamp": datetime.utcnow(),
                "src_ip": src,
                "threat_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "details": (
                    f"{len(dq)} attempts on port {dport} in "
                    f"{config.BRUTE_FORCE_WINDOW_SEC}s"
                ),
            })

    # ---------------------------- DET-03 ----------------------------
    def _detect_arp_spoof(self, meta: dict, out: list[dict]) -> None:
        if not meta.get("is_arp_reply"):
            return
        ip = meta["src_ip"]
        mac = meta.get("arp_src_mac")
        if not ip or not mac:
            return

        known = self.arp_table.get(ip)
        if known is None:
            self.arp_table[ip] = mac
            return
        if known != mac:
            out.append({
                "timestamp": datetime.utcnow(),
                "src_ip": ip,
                "threat_type": "ARP_SPOOF",
                "severity": "CRITICAL",
                "details": f"IP {ip} was {known}, now claims {mac}",
            })
            self.arp_table[ip] = mac

    # ---------------------------- DET-04 ----------------------------
    def _detect_flood(self, meta: dict, out: list[dict]) -> None:
        src = meta.get("src_ip")
        if not src:
            return
        bucket = int(time.time())
        state = self.flood_counter[src]
        # Reset counter when we roll into a new 1-second bucket.
        if state[0] != bucket:
            state[0] = bucket
            state[1] = 0
        state[1] += 1
        if state[1] >= config.FLOOD_PACKET_RATE_THRESHOLD:
            out.append({
                "timestamp": datetime.utcnow(),
                "src_ip": src,
                "threat_type": "FLOOD",
                "severity": "CRITICAL",
                "details": f"{state[1]} pps from {src}",
            })

    # ---------------------------- DET-05 ----------------------------
    def _detect_ping_sweep(self, meta: dict, out: list[dict]) -> None:
        src = meta["src_ip"]
        dq = self.ping_sweep[src]
        now = time.time()
        dq.append((now, meta["dst_ip"]))

        cutoff = now - config.PING_SWEEP_WINDOW_SEC
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_targets = {d for _, d in dq}
        if len(unique_targets) >= config.PING_SWEEP_HOST_THRESHOLD:
            out.append({
                "timestamp": datetime.utcnow(),
                "src_ip": src,
                "threat_type": "PING_SWEEP",
                "severity": "MEDIUM",
                "details": (
                    f"{len(unique_targets)} hosts probed in "
                    f"{config.PING_SWEEP_WINDOW_SEC}s"
                ),
            })
```

### 2.5 `core/sniffer.py` — packet capture and bulk logging (LOG-01)

#### Thinking
- Scapy's `sniff()` is a blocking call → must run in a dedicated thread.
- Buffer rows in memory; flush either when the buffer reaches `BULK_INSERT_BATCH_SIZE` or when `FLUSH_INTERVAL_SEC` has elapsed.
- The sniffer hands packets to the analyzer **synchronously**. The analyzer is O(1), so this does not throttle capture in practice.
- When the analyzer returns alerts, the sniffer hands each one to the responder via the `alert_sink` callback (injected from `main.py`).

#### File: `network-ids/core/sniffer.py`

```python
"""
Scapy packet capture + bulk packet logging (LOG-01).

Two threads:
  - capture thread: runs scapy.sniff(); per packet, builds meta dict, asks
    the analyzer to run, and appends a PacketLog row to the buffer.
  - flush  thread: every FLUSH_INTERVAL_SEC, drains the buffer to SQLite
    via a single INSERT...VALUES batch.

The capture path NEVER does direct DB I/O. All inserts happen on the flush
thread under the sniffer's buffer lock to avoid SQLite contention with the
Flask request threads.
"""

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from sqlalchemy import insert

import config
from core.analyzer import Analyzer
from db.database import session_scope
from db.models import PacketLog


AlertSink = Callable[[dict], None]


class PacketSniffer:
    def __init__(self, analyzer: Analyzer, alert_sink: Optional[AlertSink] = None) -> None:
        self.analyzer = analyzer
        self.alert_sink = alert_sink

        self._buffer: list[dict] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self._capture_loop, name="sniffer", daemon=True).start()
        threading.Thread(target=self._flush_loop, name="flusher", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    # capture loop
    # ------------------------------------------------------------------
    def _capture_loop(self) -> None:
        sniff(
            iface=config.NETWORK_INTERFACE,
            prn=self._handle,
            store=False,
            stop_filter=lambda _p: self._stop.is_set(),
        )

    def _handle(self, pkt: Packet) -> None:
        meta = self._extract_meta(pkt)
        if meta is None:
            return

        # Detection (synchronous, in-memory; O(1) per packet)
        alerts = self.analyzer.process(pkt, meta)
        if alerts and self.alert_sink:
            for a in alerts:
                try:
                    self.alert_sink(a)
                except Exception as e:
                    print(f"[sniffer] alert sink error: {e}")

        # Logging buffer (LOG-01)
        with self._buffer_lock:
            self._buffer.append({
                "timestamp": meta["timestamp"],
                "src_ip": meta["src_ip"],
                "dst_ip": meta["dst_ip"],
                "protocol": meta["protocol"],
                "src_port": meta.get("src_port"),
                "dst_port": meta.get("dst_port"),
                "payload_size": meta["payload_size"],
            })
            if len(self._buffer) >= config.BULK_INSERT_BATCH_SIZE:
                self._flush_locked()

    # ------------------------------------------------------------------
    # parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_meta(pkt: Packet) -> Optional[dict]:
        # ARP is L2, no IP layer -- handle it first.
        if ARP in pkt:
            return {
                "timestamp": datetime.utcnow(),
                "src_ip": pkt[ARP].psrc or "",
                "dst_ip": pkt[ARP].pdst or "",
                "protocol": "ARP",
                "src_port": None,
                "dst_port": None,
                "payload_size": int(len(pkt)),
                "is_arp_reply": pkt[ARP].op == 2,
                "arp_src_mac": pkt[ARP].hwsrc,
            }

        if IP not in pkt:
            return None

        ip_layer = pkt[IP]
        protocol = "OTHER"
        sport: Optional[int] = None
        dport: Optional[int] = None
        tcp_flags: Optional[int] = None

        if TCP in pkt:
            protocol = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            protocol = "ICMP"

        return {
            "timestamp": datetime.utcnow(),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": protocol,
            "src_port": sport,
            "dst_port": dport,
            "payload_size": int(len(pkt)),
            "tcp_flags": tcp_flags,
        }

    # ------------------------------------------------------------------
    # flush loop
    # ------------------------------------------------------------------
    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(config.FLUSH_INTERVAL_SEC)
            with self._buffer_lock:
                if self._buffer and (time.time() - self._last_flush) >= config.FLUSH_INTERVAL_SEC:
                    self._flush_locked()

    def _flush_locked(self) -> None:
        rows = self._buffer
        self._buffer = []
        self._last_flush = time.time()
        if not rows:
            return
        try:
            with session_scope() as s:
                s.execute(insert(PacketLog), rows)
        except Exception as e:
            # Don't crash the sniffer if the DB hiccups; just drop this batch.
            print(f"[sniffer] bulk insert failed: {e}")
```

**Connections**

- `core/sniffer.py` ← `core/analyzer.py` (synchronous call per packet).
- `core/sniffer.py` → `db/database.py` (only via `session_scope`).
- `core/sniffer.py` → `alert_sink` callback (injected by `main.py`, points to `Responder.handle_alert`).

---

## Part 3 — Response engine

### 3.1 Thinking

The responder is the single place where:

- Alerts become **persistent** (`AlertHistory` rows → LOG-02 / RES-01).
- IPs become **affected by the firewall** (RES-02 / RES-04).
- The **whitelist exemption** is enforced (RES-03): whitelisted IPs still get an alert row and still appear in the dashboard, but no `iptables` action is taken.

The responder is also the only module allowed to call `subprocess.run(["iptables", ...])`. Centralizing this keeps the side effects auditable.

Idempotency matters: `iptables -A` appends a duplicate rule every time it is called. We use `iptables -C` (check) first and only `-A` (append) if `-C` returns non-zero.

### 3.2 `core/responder.py`

#### File: `network-ids/core/responder.py`

```python
"""
Response engine. Implements RES-01..RES-04 from PROJECT_OVERVIEW.md.

Flow on each alert:
  1. Persist row in alert_history (RES-01, LOG-02).
  2. Look up source IP in ip_list (RES-03):
       whitelist -> skip firewall action
       blacklist -> always block (regardless of severity)
  3. Firewall action based on severity:
       HIGH/CRITICAL -> iptables DROP                 (RES-02)
       MEDIUM        -> iptables -m limit rate cap    (RES-04)
  4. Push alert dict over SocketIO so the dashboard updates live (RES-01).
"""

import subprocess
import threading
from typing import Callable, Optional

from sqlalchemy import select

import config
from db.database import session_scope
from db.models import AlertHistory, IPList


SocketEmit = Callable[[dict], None]


class Responder:
    def __init__(self, socket_emit: Optional[SocketEmit] = None) -> None:
        self.socket_emit = socket_emit
        self._blocked: set[str] = set()
        self._rate_limited: set[str] = set()
        self._lock = threading.Lock()
        self._reapply_blacklist_on_boot()

    # ------------------------------------------------------------------
    # Public entrypoint (called by sniffer thread)
    # ------------------------------------------------------------------
    def handle_alert(self, alert: dict) -> None:
        list_type = self._lookup_list(alert["src_ip"])
        alert_id = self._persist_alert(alert)
        payload = {**alert, "id": alert_id, "status": "new"}

        if list_type == "whitelist":
            # RES-03: never block a whitelisted IP, but still surface the alert.
            self._emit(payload)
            return

        severity = alert["severity"]
        if list_type == "blacklist" or severity in config.AUTO_BLOCK_SEVERITIES:
            self._apply_block(alert["src_ip"])
        elif severity in config.RATE_LIMIT_SEVERITIES:
            self._apply_rate_limit(alert["src_ip"])

        self._emit(payload)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist_alert(self, alert: dict) -> int:
        with session_scope() as s:
            row = AlertHistory(
                timestamp=alert["timestamp"],
                src_ip=alert["src_ip"],
                threat_type=alert["threat_type"],
                severity=alert["severity"],
                details=alert.get("details"),
                status="new",
            )
            s.add(row)
            s.flush()  # populate row.id
            return row.id

    def _lookup_list(self, ip: str) -> Optional[str]:
        with session_scope() as s:
            row = s.scalar(select(IPList).where(IPList.ip_address == ip))
            return row.list_type if row else None

    def _reapply_blacklist_on_boot(self) -> None:
        """On startup, re-apply iptables DROP for every blacklisted IP."""
        try:
            with session_scope() as s:
                rows = s.scalars(
                    select(IPList).where(IPList.list_type == "blacklist")
                ).all()
                ips = [r.ip_address for r in rows]
        except Exception as e:
            print(f"[responder] could not load blacklist on boot: {e}")
            return
        for ip in ips:
            self._apply_block(ip)

    # ------------------------------------------------------------------
    # Firewall actions
    # ------------------------------------------------------------------
    def _apply_block(self, ip: str) -> None:
        with self._lock:
            if ip in self._blocked:
                return
            self._blocked.add(ip)
        try:
            # iptables -C returns 0 if the rule exists, !=0 otherwise.
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, check=False,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, check=True,
                )
            print(f"[responder] BLOCK {ip}")
        except FileNotFoundError:
            print(f"[responder] iptables binary not found; would BLOCK {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[responder] iptables BLOCK {ip} failed: {e.stderr}")

    def _apply_rate_limit(self, ip: str) -> None:
        with self._lock:
            if ip in self._rate_limited:
                return
            self._rate_limited.add(ip)
        rule = [
            "INPUT", "-s", ip,
            "-m", "limit", "--limit", config.RATE_LIMIT_RULE,
            "-j", "ACCEPT",
        ]
        try:
            check = subprocess.run(
                ["iptables", "-C", *rule],
                capture_output=True, text=True, check=False,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-A", *rule],
                    capture_output=True, text=True, check=True,
                )
            print(f"[responder] RATE-LIMIT {ip} ({config.RATE_LIMIT_RULE})")
        except FileNotFoundError:
            print(f"[responder] iptables binary not found; would RATE-LIMIT {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[responder] iptables RATE-LIMIT {ip} failed: {e.stderr}")

    # ------------------------------------------------------------------
    # Socket emission
    # ------------------------------------------------------------------
    def _emit(self, payload: dict) -> None:
        if not self.socket_emit:
            return
        try:
            self.socket_emit(payload)
        except Exception as e:
            print(f"[responder] socket emit failed: {e}")
```

**Connections**

- Called by `core/sniffer.py` via the injected `alert_sink` callback.
- Reads `IPList` and writes `AlertHistory` through `db.database.session_scope`.
- `_emit` calls the function returned by `api.websocket.attach`, which calls `Flask-SocketIO.emit("new_alert", ...)`.

---

## Part 4 — REST API, WebSocket, main entrypoint

### 4.1 Thinking

- The REST surface is a single `Blueprint` in `api/routes.py`. All endpoints are `/api/...` so the dashboard's static files at `/` don't collide.
- The WebSocket layer has **two server-to-client events**: `traffic_update` (every 1 s; DSH-01) and `new_alert` (per alert; DSH-02). No client-to-server messages are needed for this spec.
- `main.py` is the one place where the dependency graph is wired:
  `Analyzer → Sniffer → Responder → SocketIO`. Every other module is unaware of the others' constructors.

### 4.2 `api/routes.py` — REST endpoints

#### File: `network-ids/api/routes.py`

```python
"""
REST endpoints consumed by the dashboard.

  GET    /api/logs                     paginated packet log (DSH-05)
  GET    /api/logs/export.csv          CSV export of filtered packet log (DSH-05)
  GET    /api/alerts                   recent alerts (DSH-02 initial load)
  POST   /api/alerts/<id>/status       update status -- new/acknowledged/resolved
  GET    /api/iplist                   list whitelist + blacklist (RES-03)
  POST   /api/iplist                   add/update IP in whitelist|blacklist (RES-03)
  DELETE /api/iplist/<ip>              remove IP from any list (RES-03)
  GET    /api/stats/protocol           protocol distribution over last 5min (DSH-04)
  GET    /api/stats/heatmap            7x24 alert count grid (DSH-03)
"""

import csv
import io
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, Response, jsonify, request
from sqlalchemy import func, select

from db.database import session_scope
from db.models import AlertHistory, IPList, PacketLog


api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _apply_packet_filters(stmt, ip, proto, start, end):
    if ip:
        stmt = stmt.where(PacketLog.src_ip == ip)
    if proto:
        stmt = stmt.where(PacketLog.protocol == proto.upper())
    if start:
        stmt = stmt.where(PacketLog.timestamp >= start)
    if end:
        stmt = stmt.where(PacketLog.timestamp <= end)
    return stmt


# ---------------------------------------------------------------------------
# DSH-05  packet log + CSV export
# ---------------------------------------------------------------------------
@api_bp.get("/logs")
def list_logs():
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(int(request.args.get("per_page", 50)), 500)
    ip = request.args.get("ip") or None
    proto = request.args.get("proto") or None
    start = _parse_dt(request.args.get("start"))
    end = _parse_dt(request.args.get("end"))

    with session_scope() as s:
        base = _apply_packet_filters(select(PacketLog), ip, proto, start, end)
        total = s.scalar(
            _apply_packet_filters(
                select(func.count(PacketLog.id)), ip, proto, start, end
            )
        ) or 0
        rows = s.scalars(
            base.order_by(PacketLog.id.desc())
            .limit(per_page)
            .offset((page - 1) * per_page)
        ).all()
        items = [{
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "protocol": r.protocol,
            "src_port": r.src_port,
            "dst_port": r.dst_port,
            "payload_size": r.payload_size,
        } for r in rows]

    return jsonify({"page": page, "per_page": per_page, "total": total, "items": items})


@api_bp.get("/logs/export.csv")
def export_logs_csv():
    ip = request.args.get("ip") or None
    proto = request.args.get("proto") or None
    start = _parse_dt(request.args.get("start"))
    end = _parse_dt(request.args.get("end"))

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "timestamp", "src_ip", "dst_ip",
        "protocol", "src_port", "dst_port", "payload_size",
    ])
    with session_scope() as s:
        stmt = _apply_packet_filters(
            select(PacketLog), ip, proto, start, end
        ).order_by(PacketLog.id.desc())
        for r in s.scalars(stmt):
            writer.writerow([
                r.id, r.timestamp.isoformat(), r.src_ip, r.dst_ip,
                r.protocol, r.src_port, r.dst_port, r.payload_size,
            ])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packet_log.csv"},
    )


# ---------------------------------------------------------------------------
# DSH-02  alerts feed (initial load) + status update
# ---------------------------------------------------------------------------
@api_bp.get("/alerts")
def list_alerts():
    limit = min(int(request.args.get("limit", 100)), 1000)
    with session_scope() as s:
        rows = s.scalars(
            select(AlertHistory).order_by(AlertHistory.id.desc()).limit(limit)
        ).all()
        return jsonify([{
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "threat_type": r.threat_type,
            "severity": r.severity,
            "details": r.details,
            "status": r.status,
        } for r in rows])


@api_bp.post("/alerts/<int:alert_id>/status")
def update_alert_status(alert_id: int):
    body = request.get_json(force=True, silent=True) or {}
    new_status = body.get("status")
    if new_status not in {"new", "acknowledged", "resolved"}:
        return jsonify({"error": "status must be new|acknowledged|resolved"}), 400
    with session_scope() as s:
        row = s.get(AlertHistory, alert_id)
        if not row:
            return jsonify({"error": "not found"}), 404
        row.status = new_status
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# RES-03  IP list management
# ---------------------------------------------------------------------------
@api_bp.get("/iplist")
def get_iplist():
    with session_scope() as s:
        rows = s.scalars(select(IPList).order_by(IPList.id.desc())).all()
        return jsonify([{
            "id": r.id,
            "ip_address": r.ip_address,
            "list_type": r.list_type,
            "added_at": r.added_at.isoformat(),
            "reason": r.reason,
        } for r in rows])


@api_bp.post("/iplist")
def add_iplist():
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip")
    list_type = body.get("type") or body.get("list_type")
    if not ip or list_type not in {"whitelist", "blacklist"}:
        return jsonify({"error": "ip and type (whitelist|blacklist) are required"}), 400
    with session_scope() as s:
        existing = s.scalar(select(IPList).where(IPList.ip_address == ip))
        if existing:
            existing.list_type = list_type
            existing.reason = body.get("reason")
        else:
            s.add(IPList(
                ip_address=ip,
                list_type=list_type,
                added_at=datetime.utcnow(),
                reason=body.get("reason"),
            ))
    return jsonify({"ok": True}), 201


@api_bp.delete("/iplist/<ip>")
def delete_iplist(ip: str):
    with session_scope() as s:
        row = s.scalar(select(IPList).where(IPList.ip_address == ip))
        if not row:
            return jsonify({"error": "not found"}), 404
        s.delete(row)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# DSH-04  protocol distribution
# ---------------------------------------------------------------------------
@api_bp.get("/stats/protocol")
def stats_protocol():
    since = datetime.utcnow() - timedelta(minutes=5)
    with session_scope() as s:
        rows = s.execute(
            select(PacketLog.protocol, func.count(PacketLog.id))
            .where(PacketLog.timestamp >= since)
            .group_by(PacketLog.protocol)
        ).all()
    return jsonify({proto: int(cnt) for proto, cnt in rows})


# ---------------------------------------------------------------------------
# DSH-03  heatmap (weekday x hour)
# ---------------------------------------------------------------------------
@api_bp.get("/stats/heatmap")
def stats_heatmap():
    # SQLite: strftime("%w", ts) -> 0=Sun..6=Sat ; strftime("%H", ts) -> "00".."23"
    with session_scope() as s:
        rows = s.execute(
            select(
                func.strftime("%w", AlertHistory.timestamp).label("dow"),
                func.strftime("%H", AlertHistory.timestamp).label("hour"),
                func.count(AlertHistory.id),
            ).group_by("dow", "hour")
        ).all()
    grid = [[0] * 24 for _ in range(7)]
    for dow, hour, count in rows:
        try:
            grid[int(dow)][int(hour)] = int(count)
        except (TypeError, ValueError):
            continue
    return jsonify({"grid": grid})
```

### 4.3 `api/websocket.py` — SocketIO events (DSH-01 traffic, RES-01 push)

#### File: `network-ids/api/websocket.py`

```python
"""
SocketIO server-to-client events.

  traffic_update   list[{"t": "HH:MM:SS", "pps": int}]   every 1s (DSH-01)
  new_alert        alert dict                            on each detection (RES-01 / DSH-02)

The traffic emitter runs in a daemon thread spawned at app startup. It counts
new packet_log rows since the last poll -- this is cheap because packet_log.id
is indexed and we filter on id > last_seen_id.
"""

import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable

from flask_socketio import SocketIO
from sqlalchemy import func, select

from db.database import session_scope
from db.models import PacketLog


_TRAFFIC_WINDOW_SEC = 60
_traffic_window = deque(maxlen=_TRAFFIC_WINDOW_SEC)


def attach(socketio: SocketIO) -> Callable[[dict], None]:
    """Spawn the traffic emitter and return a function that emits 'new_alert'."""

    def emit_alert(alert: dict) -> None:
        # SocketIO emits must contain JSON-serializable values.
        payload = dict(alert)
        ts = payload.get("timestamp")
        if isinstance(ts, datetime):
            payload["timestamp"] = ts.isoformat()
        socketio.emit("new_alert", payload)

    def _traffic_loop() -> None:
        last_seen_id = 0
        while True:
            try:
                with session_scope() as s:
                    cnt, max_id = s.execute(
                        select(
                            func.count(PacketLog.id),
                            func.coalesce(func.max(PacketLog.id), 0),
                        ).where(PacketLog.id > last_seen_id)
                    ).one()
                last_seen_id = int(max_id) or last_seen_id
                _traffic_window.append({
                    "t": datetime.utcnow().strftime("%H:%M:%S"),
                    "pps": int(cnt),
                })
                socketio.emit("traffic_update", list(_traffic_window))
            except Exception as e:
                print(f"[ws] traffic loop error: {e}")
            time.sleep(1)

    threading.Thread(target=_traffic_loop, name="traffic_ws", daemon=True).start()
    return emit_alert
```

### 4.4 `main.py` — entrypoint

#### File: `network-ids/main.py`

```python
"""
NIDS entrypoint. Wires Analyzer -> Sniffer -> Responder -> Flask + SocketIO.

Usage (must be root for packet capture):
    sudo .venv/bin/python main.py --interface eth0 --port 5000

Dashboard: http://localhost:5000
"""

import argparse
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

import config
import db.models  # noqa: F401  -- registers ORM models on Base
from api.routes import api_bp
from api.websocket import attach as attach_websocket
from core.analyzer import Analyzer
from core.responder import Responder
from core.sniffer import PacketSniffer
from db.database import Base, engine


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Network Intrusion Detection System")
    p.add_argument("--interface", "-i", default=config.NETWORK_INTERFACE,
                   help="NIC name (default from config.py)")
    p.add_argument("--port", "-p", type=int, default=config.FLASK_PORT,
                   help="Flask port")
    p.add_argument("--host", default=config.FLASK_HOST, help="Flask bind host")
    return p.parse_args()


def create_app() -> tuple[Flask, SocketIO]:
    project_root = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "dashboard" / "templates"),
        static_folder=str(project_root / "dashboard" / "static"),
    )
    app.config["SECRET_KEY"] = "nids-midterm-secret"
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
    return app, socketio


def main() -> None:
    args = parse_args()
    config.NETWORK_INTERFACE = args.interface
    config.FLASK_PORT = args.port
    config.FLASK_HOST = args.host

    Base.metadata.create_all(engine)

    app, socketio = create_app()
    emit_alert = attach_websocket(socketio)

    responder = Responder(socket_emit=emit_alert)
    analyzer = Analyzer()
    sniffer = PacketSniffer(analyzer=analyzer, alert_sink=responder.handle_alert)
    sniffer.start()

    print(f"[NIDS] sniffing on {config.NETWORK_INTERFACE}")
    print(f"[NIDS] dashboard at http://{config.FLASK_HOST}:{config.FLASK_PORT}")

    socketio.run(
        app,
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        allow_unsafe_werkzeug=True,  # required for SocketIO + threading mode
    )


if __name__ == "__main__":
    main()
```

**Connections recap (entire backend)**

```
                       ┌───────────────────────┐
                       │  scapy.sniff (thread) │
                       └─────────┬─────────────┘
                                 │ Packet
                                 ▼
                       ┌───────────────────────┐
                       │   Analyzer.process    │   DET-01..DET-05
                       └─────────┬─────────────┘
                                 │ alert dicts
                                 ▼
                       ┌───────────────────────┐
                       │ Responder.handle_alert│   RES-01..RES-04
                       │   (iptables + DB)     │
                       └─────────┬─────────────┘
                                 │ emit_alert(...)
                                 ▼
        ┌─────────────────────────────────────────────────┐
        │ Flask app  +  SocketIO  (async_mode=threading)  │
        │   - /                routes index.html          │
        │   - /api/...         api/routes.py              │
        │   - traffic_update   api/websocket.py           │
        │   - new_alert        api/websocket.py           │
        └─────────────────────────────────────────────────┘
```

---

## Part 5 — Dashboard frontend

### 5.1 Thinking

- Single-page HTML, **no build step**. Chart.js and socket.io-client are loaded from a CDN.
- `charts.js` owns the SocketIO `socket` instance (single global). `alerts.js` reuses that same global — script order in `index.html` matters: charts.js first, alerts.js second.
- The dashboard polls `/api/stats/protocol` and `/api/stats/heatmap` on a slow interval (5 s / 30 s). Real-time data uses WebSocket only.

### 5.2 `dashboard/templates/index.html`

#### File: `network-ids/dashboard/templates/index.html`

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NIDS Dashboard</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
</head>
<body>
  <header>
    <h1>Network Intrusion Detection System</h1>
    <span id="status" class="status-dot" title="WebSocket status"></span>
  </header>

  <main>
    <section class="grid">
      <!-- DSH-01 -->
      <div class="card">
        <h2>Traffic (pkts/sec, last 60s)</h2>
        <canvas id="trafficChart" height="120"></canvas>
      </div>

      <!-- DSH-04 -->
      <div class="card">
        <h2>Protocol distribution (last 5 min)</h2>
        <canvas id="protocolChart" height="120"></canvas>
      </div>

      <!-- DSH-02 -->
      <div class="card span-2">
        <h2>Live alerts</h2>
        <ul id="alertFeed" class="alert-feed"></ul>
      </div>

      <!-- DSH-03 -->
      <div class="card span-2">
        <h2>Threat heatmap (weekday x hour)</h2>
        <div id="heatmap" class="heatmap"></div>
      </div>

      <!-- RES-03 -->
      <div class="card span-2">
        <h2>IP list (whitelist / blacklist)</h2>
        <form id="iplistForm">
          <input name="ip" placeholder="192.168.1.100" required />
          <select name="type">
            <option value="whitelist">whitelist</option>
            <option value="blacklist">blacklist</option>
          </select>
          <input name="reason" placeholder="reason (optional)" />
          <button type="submit">Add / Update</button>
        </form>
        <table id="iplistTable">
          <thead>
            <tr><th>IP</th><th>Type</th><th>Added</th><th>Reason</th><th></th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <!-- DSH-05 -->
      <div class="card span-2">
        <h2>Packet log</h2>
        <form id="logFilters">
          <input name="ip" placeholder="src IP" />
          <select name="proto">
            <option value="">All protocols</option>
            <option>TCP</option>
            <option>UDP</option>
            <option>ICMP</option>
            <option>ARP</option>
            <option>OTHER</option>
          </select>
          <button type="submit">Apply</button>
          <a id="csvExport" class="btn-link" href="/api/logs/export.csv" download>Export CSV</a>
        </form>
        <table id="logTable">
          <thead>
            <tr>
              <th>Time</th><th>Src</th><th>Dst</th><th>Proto</th>
              <th>Sport</th><th>Dport</th><th>Bytes</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
        <div class="pager">
          <button id="prevPage">Prev</button>
          <span id="pageInfo"></span>
          <button id="nextPage">Next</button>
        </div>
      </div>
    </section>
  </main>

  <script src="{{ url_for('static', filename='js/charts.js') }}"></script>
  <script src="{{ url_for('static', filename='js/alerts.js') }}"></script>
</body>
</html>
```

### 5.3 `dashboard/static/css/style.css`

#### File: `network-ids/dashboard/static/css/style.css`

```css
:root {
  --bg: #0f1117;
  --panel: #1a1d27;
  --text: #e4e7ef;
  --muted: #8b94a7;
  --accent: #4f8ef7;
  --low: #4caf50;
  --medium: #ff9800;
  --high: #ff5722;
  --critical: #d50000;
  --border: #2a2f3d;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
}
header {
  display: flex; align-items: center; gap: .75rem;
  padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);
}
header h1 { margin: 0; font-size: 1.1rem; font-weight: 600; }
.status-dot {
  width: .6rem; height: .6rem; border-radius: 50%;
  background: #666; transition: background .2s, box-shadow .2s;
}
.status-dot.live { background: #4caf50; box-shadow: 0 0 8px #4caf50; }
main { padding: 1rem 1.5rem; }
.grid {
  display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;
}
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 1rem;
}
.card.span-2 { grid-column: span 2; }
.card h2 {
  margin: 0 0 .75rem; font-size: .95rem;
  color: var(--muted); font-weight: 500;
}
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td {
  padding: .4rem .6rem; border-bottom: 1px solid var(--border);
  text-align: left;
}
th { color: var(--muted); font-weight: 500; }
.alert-feed {
  list-style: none; padding: 0; margin: 0;
  max-height: 280px; overflow-y: auto;
}
.alert-feed li {
  padding: .5rem .75rem; border-bottom: 1px solid var(--border);
  display: flex; gap: .5rem; align-items: center; font-size: .85rem;
}
.alert-feed .ts { color: var(--muted); font-size: .75rem; }
.badge {
  padding: .15rem .5rem; border-radius: 4px;
  font-size: .7rem; font-weight: 600; color: white;
}
.badge-low { background: var(--low); }
.badge-medium { background: var(--medium); }
.badge-high { background: var(--high); }
.badge-critical { background: var(--critical); }
form { display: flex; gap: .5rem; margin-bottom: .75rem; flex-wrap: wrap; }
input, select, button, .btn-link {
  background: #0f1117; color: var(--text);
  border: 1px solid var(--border); padding: .4rem .6rem;
  border-radius: 4px; font-size: .85rem;
}
button, .btn-link {
  background: var(--accent); border: none; color: white;
  cursor: pointer; text-decoration: none;
}
button:hover, .btn-link:hover { filter: brightness(1.1); }
.heatmap {
  display: grid; grid-template-columns: 40px repeat(24, 1fr);
  gap: 2px; font-size: .65rem;
}
.heatmap .cell {
  height: 18px; border-radius: 2px; background: #1f2330;
}
.heatmap .lbl { color: var(--muted); padding: .1rem .3rem; }
.pager {
  display: flex; gap: .5rem; align-items: center; margin-top: .5rem;
}
```

### 5.4 `dashboard/static/js/charts.js` — DSH-01, DSH-03, DSH-04

#### File: `network-ids/dashboard/static/js/charts.js`

```javascript
// Single SocketIO client, reused by alerts.js (loaded after this file).
const socket = io();
const statusDot = document.getElementById('status');
socket.on('connect',    () => statusDot.classList.add('live'));
socket.on('disconnect', () => statusDot.classList.remove('live'));

// ---------------------------------------------------------------------------
// DSH-01  Traffic chart (line, 60s rolling window, fed by 'traffic_update')
// ---------------------------------------------------------------------------
const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'pkts/sec',
      data: [],
      borderColor: '#4f8ef7',
      backgroundColor: 'rgba(79, 142, 247, 0.15)',
      tension: 0.25,
      fill: true,
      pointRadius: 0,
    }],
  },
  options: {
    animation: false,
    scales: { y: { beginAtZero: true } },
    plugins: { legend: { display: false } },
  },
});
socket.on('traffic_update', (windowPoints) => {
  trafficChart.data.labels = windowPoints.map(p => p.t);
  trafficChart.data.datasets[0].data = windowPoints.map(p => p.pps);
  trafficChart.update('none');
});

// ---------------------------------------------------------------------------
// DSH-04  Protocol distribution (doughnut, polled every 5s)
// ---------------------------------------------------------------------------
const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#4f8ef7', '#4caf50', '#ff9800', '#d50000', '#8b94a7'],
    }],
  },
  options: { plugins: { legend: { position: 'right' } } },
});
async function refreshProtocol() {
  try {
    const r = await fetch('/api/stats/protocol');
    const data = await r.json();
    protocolChart.data.labels = Object.keys(data);
    protocolChart.data.datasets[0].data = Object.values(data);
    protocolChart.update();
  } catch (e) { console.error('refreshProtocol', e); }
}
refreshProtocol();
setInterval(refreshProtocol, 5000);

// ---------------------------------------------------------------------------
// DSH-03  Threat heatmap (CSS grid, 7 rows x 24 cols, polled every 30s)
// ---------------------------------------------------------------------------
async function refreshHeatmap() {
  try {
    const r = await fetch('/api/stats/heatmap');
    const { grid } = await r.json();
    const root = document.getElementById('heatmap');
    root.innerHTML = '';
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    let max = 0;
    for (const row of grid) for (const v of row) if (v > max) max = v;

    // header row: empty corner + 0..23
    root.appendChild(document.createElement('div'));
    for (let h = 0; h < 24; h++) {
      const el = document.createElement('div');
      el.className = 'lbl';
      el.textContent = h;
      root.appendChild(el);
    }

    for (let d = 0; d < 7; d++) {
      const lbl = document.createElement('div');
      lbl.className = 'lbl';
      lbl.textContent = days[d];
      root.appendChild(lbl);
      for (let h = 0; h < 24; h++) {
        const v = grid[d][h];
        const intensity = max ? v / max : 0;
        const cell = document.createElement('div');
        cell.className = 'cell';
        cell.title = `${days[d]} ${h}:00 — ${v} alerts`;
        cell.style.background = `rgba(255, 87, 34, ${0.12 + intensity * 0.85})`;
        root.appendChild(cell);
      }
    }
  } catch (e) { console.error('refreshHeatmap', e); }
}
refreshHeatmap();
setInterval(refreshHeatmap, 30000);
```

### 5.5 `dashboard/static/js/alerts.js` — DSH-02, RES-03, DSH-05

#### File: `network-ids/dashboard/static/js/alerts.js`

```javascript
// ---------------------------------------------------------------------------
// DSH-02  Alert feed (initial REST load + live SocketIO append)
// ---------------------------------------------------------------------------
const alertList = document.getElementById('alertFeed');

function renderAlert(a) {
  const li = document.createElement('li');
  const sev = (a.severity || 'LOW').toLowerCase();
  li.innerHTML = `
    <span class="badge badge-${sev}">${a.severity}</span>
    <strong>${a.threat_type}</strong>
    <span>${a.src_ip}</span>
    <span class="ts">${new Date(a.timestamp).toLocaleTimeString()}</span>
    <span style="color: var(--muted); margin-left: auto;">${a.details ?? ''}</span>
  `;
  alertList.prepend(li);
  while (alertList.children.length > 100) alertList.removeChild(alertList.lastChild);
}

async function loadInitialAlerts() {
  try {
    const r = await fetch('/api/alerts?limit=50');
    const items = await r.json();
    for (const a of items.reverse()) renderAlert(a);
  } catch (e) { console.error('loadInitialAlerts', e); }
}
loadInitialAlerts();
socket.on('new_alert', renderAlert);

// ---------------------------------------------------------------------------
// RES-03  IP list management
// ---------------------------------------------------------------------------
const ipForm = document.getElementById('iplistForm');
const ipTableBody = document.querySelector('#iplistTable tbody');

async function refreshIPList() {
  const r = await fetch('/api/iplist');
  const items = await r.json();
  ipTableBody.innerHTML = '';
  for (const x of items) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${x.ip_address}</td>
      <td>${x.list_type}</td>
      <td>${new Date(x.added_at).toLocaleString()}</td>
      <td>${x.reason ?? ''}</td>
      <td><button data-ip="${x.ip_address}" class="del">Remove</button></td>
    `;
    ipTableBody.appendChild(tr);
  }
}
ipForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(ipForm);
  await fetch('/api/iplist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip: fd.get('ip'),
      type: fd.get('type'),
      reason: fd.get('reason') || null,
    }),
  });
  ipForm.reset();
  refreshIPList();
});
ipTableBody.addEventListener('click', async (e) => {
  if (!e.target.matches('.del')) return;
  await fetch(`/api/iplist/${e.target.dataset.ip}`, { method: 'DELETE' });
  refreshIPList();
});
refreshIPList();

// ---------------------------------------------------------------------------
// DSH-05  Packet log viewer with pagination + CSV export link
// ---------------------------------------------------------------------------
const logForm = document.getElementById('logFilters');
const logBody = document.querySelector('#logTable tbody');
const pageInfo = document.getElementById('pageInfo');
const csvLink = document.getElementById('csvExport');
const logState = { page: 1, ip: '', proto: '' };

function logQueryString() {
  const p = new URLSearchParams();
  p.set('page', logState.page);
  if (logState.ip) p.set('ip', logState.ip);
  if (logState.proto) p.set('proto', logState.proto);
  return p.toString();
}

async function refreshLogs() {
  try {
    const r = await fetch('/api/logs?' + logQueryString());
    const data = await r.json();
    logBody.innerHTML = '';
    for (const row of data.items) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${new Date(row.timestamp).toLocaleTimeString()}</td>
        <td>${row.src_ip}</td>
        <td>${row.dst_ip}</td>
        <td>${row.protocol}</td>
        <td>${row.src_port ?? ''}</td>
        <td>${row.dst_port ?? ''}</td>
        <td>${row.payload_size ?? ''}</td>
      `;
      logBody.appendChild(tr);
    }
    const totalPages = Math.max(1, Math.ceil(data.total / data.per_page));
    pageInfo.textContent = `Page ${data.page} / ${totalPages} (${data.total} rows)`;
    csvLink.href = '/api/logs/export.csv?' + logQueryString();
  } catch (e) { console.error('refreshLogs', e); }
}

logForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const fd = new FormData(logForm);
  logState.page = 1;
  logState.ip = fd.get('ip') || '';
  logState.proto = fd.get('proto') || '';
  refreshLogs();
});
document.getElementById('prevPage').addEventListener('click', () => {
  logState.page = Math.max(1, logState.page - 1);
  refreshLogs();
});
document.getElementById('nextPage').addEventListener('click', () => {
  logState.page += 1;
  refreshLogs();
});

refreshLogs();
setInterval(refreshLogs, 5000);
```

---

## Part 6 — Running the full system

### 6.1 First-run checklist

```bash
cd network-ids

# 1. Activate venv
source .venv/bin/activate

# 2. Initialize DB schema (idempotent)
python init_db.py
# Expect: [OK] Database ready at .../network-ids/db/nids.sqlite

# 3. Confirm interface name
ip -brief addr
# Edit config.py if NETWORK_INTERFACE differs (or pass --interface)

# 4. Run the NIDS (root required)
sudo .venv/bin/python main.py --interface eth0
```

You should see:

```
[NIDS] sniffing on eth0
[NIDS] dashboard at http://0.0.0.0:5000
 * Running on http://0.0.0.0:5000
```

Open `http://localhost:5000` in a browser. The status dot in the header turns green when the WebSocket is connected.

### 6.2 Smoke test (same host)

```bash
# In another terminal -- generate some packets
ping -c 5 8.8.8.8
curl http://example.com >/dev/null

# Verify rows exist
sqlite3 db/nids.sqlite "SELECT protocol, COUNT(*) FROM packet_log GROUP BY protocol;"
```

The dashboard's traffic chart should tick upward; the protocol pie should fill in.

### 6.3 Triggering each detection (mapped to spec test cases)

Run these from an **Attacker VM** against the **Target VM** running the NIDS, as described in `SECTION: ATTACK_TESTING_GUIDE`.

| Test | Command (attacker) | Expected alert |
|---|---|---|
| TC-01 | `sudo nmap -sS <target>` | `PORT_SCAN` / HIGH |
| TC-02 | `for i in $(seq 1 30); do ssh -o ConnectTimeout=1 wronguser@<target>; done` | `BRUTE_FORCE` / HIGH |
| TC-03 | `sudo arpspoof -i eth0 -t <target> <gateway>` | `ARP_SPOOF` / CRITICAL |
| TC-04 | `sudo hping3 -S -p 80 --flood <target>` | `FLOOD` / CRITICAL |
| TC-05 | `sudo nmap -sn <subnet>` | `PING_SWEEP` / MEDIUM |
| TC-06 | `curl -X POST http://localhost:5000/api/iplist -H 'Content-Type: application/json' -d '{"ip":"<attacker>","type":"whitelist"}'`, then run TC-01 | alert logged, **no** iptables rule |
| TC-07 | TC-05 → `sudo iptables -L INPUT -n -v` | rate-limit rule visible, no DROP |

### 6.4 Tearing down test firewall state

The responder appends rules but never removes them. Between test cycles:

```bash
sudo iptables -F INPUT          # flush INPUT chain
sudo iptables -L INPUT -n -v    # confirm empty
```

To reset the application state instead, delete the SQLite file and re-init:

```bash
rm db/nids.sqlite
python init_db.py
```

### 6.5 Stopping the NIDS

`Ctrl+C` in the terminal running `main.py`. Daemon threads (sniffer, flusher, traffic emitter) terminate with the main process.

---

## Part 7 — Common errors and fixes

### 7.1 Setup errors

| Symptom | Cause | Fix |
|---|---|---|
| `PermissionError: [Errno 1] Operation not permitted` on startup | Not running as root | `sudo .venv/bin/python main.py` (note: use the venv's interpreter path explicitly). |
| `OSError: [Errno 19] No such device` | Wrong `NETWORK_INTERFACE` | Run `ip -brief addr`, set the right name in `config.py` or pass `--interface`. |
| `ImportError: cannot import name 'engine' from 'db.database'` | Ran `init_db.py` before Part 2 was in place | Implement `db/database.py` and `db/models.py` first. |
| `ModuleNotFoundError: No module named 'scapy'` | venv not activated, or wrong interpreter under `sudo` | Use `sudo .venv/bin/python ...` not `sudo python ...`. |
| `RuntimeError: The Werkzeug web server is not designed to run in production` | Flask-SocketIO refuses to start under bare Werkzeug | Already handled by `allow_unsafe_werkzeug=True` in `socketio.run`. If you removed it, add it back. |

### 7.2 Runtime errors

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard loads but charts stay empty; status dot grey | SocketIO can't connect (port blocked, wrong async mode) | Confirm `async_mode="threading"` in `main.py`; check browser console for WS errors; check that `simple-websocket` is installed. |
| `sqlite3.OperationalError: database is locked` | Long-running write while another writer waits | Reduce `BULK_INSERT_BATCH_SIZE` or raise `FLUSH_INTERVAL_SEC`; ensure no external process has `db/nids.sqlite` open. |
| Alerts stop firing after 1-2 hits | `ALERT_COOLDOWN_SEC` is doing its job | Wait 10 s, or set `ALERT_COOLDOWN_SEC = 0` for tuning sessions. |
| Many `OTHER` rows in protocol pie | IPv6 / non-IP traffic | Expected — spec scopes to IPv4. Either ignore, or filter `if IP not in pkt: return None` (already done). |
| `iptables: command not found` | `iptables` package missing or `nftables`-only system | `sudo apt install iptables`; on nftables systems use `iptables-legacy` or symlink as fallback. |
| `iptables: Chain 'INPUT' does not exist` | Default policy chain renamed by another tool (Docker, ufw) | `sudo iptables -N INPUT` then re-run. Verify with `sudo iptables -L`. |
| Browser shows `405 Method Not Allowed` on `/api/iplist` | Wrong HTTP verb from frontend | Confirm `Content-Type: application/json` and `POST`; check `alerts.js` `ipForm` handler. |

### 7.3 Detection-quality issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Port scan undetected | Nmap is slower than the window allows | Raise `PORT_SCAN_WINDOW_SEC` to 10–15, or lower `PORT_SCAN_THRESHOLD`. |
| Brute-force undetected | Source closes the connection, no SYN retransmits | The detector counts SYNs only (matches the hint in DET-02). Use Hydra `-t 4` or higher concurrency in tests. |
| Flood detected but `pps` is below your test rate | `hping3 --flood` outpaces SQLite, packets are dropped at the libpcap layer | Confirm `libpcap-dev` is installed (`dpkg -l | grep libpcap-dev`); reduce `BULK_INSERT_BATCH_SIZE` so the flusher keeps up. |
| ARP spoof undetected | First-seen MAC is the spoofed one (no baseline) | Run NIDS *before* starting attacks, or pre-seed `arp_table` with `arp -a` output via a startup hook. |
| Ping sweep undetected on a single IP scan | Threshold needs ≥ 10 distinct destinations | Use `nmap -sn 192.168.1.0/24`, not a single-host ping. |

### 7.4 Cleanup of `iptables` state

The NIDS only appends rules. To revert all changes from a test session:

```bash
sudo iptables -F INPUT                # flush all INPUT rules added during run
sudo iptables -L INPUT -n -v          # confirm empty (or only default policy)
```

For production, ship a `cleanup.sh` that loops over `_blocked` IPs and runs `iptables -D INPUT -s <ip> -j DROP`. Out of scope for the spec.

---

**End of guide.** Every file path, every parameter, every endpoint, and every test case referenced here maps 1-to-1 to the IDs in `PROJECT_OVERVIEW.md`. Build bottom-up (Parts 1 → 5), verify with Part 6's checklist, and consult Part 7 if anything misbehaves.
