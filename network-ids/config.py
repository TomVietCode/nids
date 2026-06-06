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
NETWORK_INTERFACE = "ens33"
VPS_IP = "192.168.68.128"       # IP thực của VM, dùng để filter self-traffic

# VMware NAT gateway thường là .1 hoặc .2 trong subnet của VM
VMWARE_GATEWAY_IP = "192.168.68.2"   # gateway NAT của VMware
VMWARE_HOST_IP    = "192.168.68.1"   # host-only adapter của VMware trên Windows

# Toàn bộ IP trong set này sẽ bị bỏ qua (không log, không detect)
IGNORE_IPS = {
    VPS_IP,             # traffic của chính VM
    VMWARE_GATEWAY_IP,  # VMware NAT gateway (ARP, DHCP, routing...)
    VMWARE_HOST_IP,     # VMware host-only interface
}

# Bỏ qua multicast/broadcast protocol dùng cho service discovery nội bộ.
# Các địa chỉ này không phải tấn công, chỉ là noise từ VMware và Windows host.
IGNORE_DST_IPS = {
    "224.0.0.251",      # mDNS multicast
    "239.255.255.250",  # SSDP/UPnP multicast
    "255.255.255.255",  # broadcast thông thường
    f"{'.'.join(VPS_IP.split('.')[:3])}.255",  # broadcast của subnet VM
}

# Bỏ qua các port dịch vụ hệ thống không liên quan đến bảo mật
IGNORE_UDP_PORTS = {
    123,    # NTP (time sync)
    5353,   # mDNS
    1900,   # SSDP/UPnP
    57621,  # Spotify LAN discovery
}

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
