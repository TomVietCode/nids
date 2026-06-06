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
VPS_IP = "152.42.209.91"  # used to filter self-traffic in sniffer + analyzer
IGNORE_IPS = {VPS_IP}     # secondary Python-level filter for known benign IPs
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
BRUTE_FORCE_PORTS = [22, 21]  # auth-only ports; HTTP floods handled by DET-04

# ---------------------------------------------------------------------------
# DET-04 Flood / mini-DDoS
# ---------------------------------------------------------------------------
FLOOD_PACKET_RATE_THRESHOLD = 500  # packets per second from one source IP

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
RATE_LIMIT_RULE = "10/min"  # passed to iptables -m limit --limit

# ---------------------------------------------------------------------------
# Logging / persistence (LOG-01, LOG-02)
# ---------------------------------------------------------------------------
DB_PATH = "db/nids.sqlite"
BULK_INSERT_BATCH_SIZE = 100
FLUSH_INTERVAL_SEC = 2  # max seconds before a partial batch flushes
ALERT_COOLDOWN_SEC = 10  # suppress duplicate alerts for same (ip, type)
