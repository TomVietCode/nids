"""
Detection engine. Implements DET-01..DET-05.

Each call to Analyzer.process(pkt, meta) returns a list of alert dicts.
The caller (sniffer) hands them to the Responder for persistence and action.

Alert dict shape:
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

        # Track IPs with active floods to suppress brute-force during floods
        self._flood_active: set[str] = set()

    # Main entry point for processing packets
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
        return [a for a in alerts if self._allow(a)]

    # Public: remove all cooldown entries for a given IP so it can be re-detected
    # immediately after being removed from the blacklist.
    def clear_cooldown(self, ip: str) -> None:
        with self._lock:
            keys_to_del = [k for k in self._cooldown if k[0] == ip]
            for k in keys_to_del:
                del self._cooldown[k]

    # Anti-storm: suppress repeat of (src_ip, threat_type) within cooldown
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

        # Prune entries older than the window
        cutoff = now - config.PORT_SCAN_WINDOW_SEC
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # Check if the number of unique ports exceeds the threshold
        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
            out.append(
                {
                    "timestamp": datetime.utcnow(),
                    "src_ip": src,
                    "threat_type": "PORT_SCAN",
                    "severity": "HIGH",
                    "details": (
                        f"{len(unique_ports)} unique ports in "
                        f"{config.PORT_SCAN_WINDOW_SEC}s"
                    ),
                }
            )

    # ---------------------------- DET-02 ----------------------------
    def _detect_brute_force(self, meta: dict, out: list[dict]) -> None:
        flags = meta.get("tcp_flags")
        if flags is None or not (flags & TCP_FLAG_SYN) or (flags & TCP_FLAG_ACK):
            return
        dport = meta.get("dst_port")
        if dport not in config.BRUTE_FORCE_PORTS:
            return

        src = meta["src_ip"]

        # If this IP already has an active flood, skip brute-force detection.
        # A SYN flood to port 22 shouldn't fire both FLOOD and BRUTE_FORCE.
        if src in self._flood_active:
            return
        key = (src, dport)
        dq = self.brute_force[key]
        now = time.time()
        dq.append(now)

        cutoff = now - config.BRUTE_FORCE_WINDOW_SEC
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= config.BRUTE_FORCE_THRESHOLD:
            out.append(
                {
                    "timestamp": datetime.utcnow(),
                    "src_ip": src,
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "details": (
                        f"{len(dq)} attempts on port {dport} in "
                        f"{config.BRUTE_FORCE_WINDOW_SEC}s"
                    ),
                }
            )

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
            out.append(
                {
                    "timestamp": datetime.utcnow(),
                    "src_ip": ip,
                    "threat_type": "ARP_SPOOF",
                    "severity": "CRITICAL",
                    "details": f"IP {ip} was {known}, now claims {mac}",
                }
            )
            self.arp_table[ip] = mac

    # ---------------------------- DET-04 ----------------------------
    def _detect_flood(self, meta: dict, out: list[dict]) -> None:
        src = meta.get("src_ip")
        if not src:
            return

        # Only count inbound packets (targeting our VPS)
        if meta.get("dst_ip") != config.VPS_IP:
            return

        bucket = int(time.time())
        state = self.flood_counter[src]
        # Reset counter when we roll into a new 1-second bucket.
        if state[0] != bucket:
            state[0] = bucket
            state[1] = 0
            # Clear flood-active flag when a new bucket starts below threshold
            self._flood_active.discard(src)
        state[1] += 1
        if state[1] >= config.FLOOD_PACKET_RATE_THRESHOLD:
            self._flood_active.add(src)  # suppress brute-force for this IP
            out.append(
                {
                    "timestamp": datetime.utcnow(),
                    "src_ip": src,
                    "threat_type": "FLOOD",
                    "severity": "CRITICAL",
                    "details": f"{state[1]} pps from {src}",
                }
            )

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
            out.append(
                {
                    "timestamp": datetime.utcnow(),
                    "src_ip": src,
                    "threat_type": "PING_SWEEP",
                    "severity": "MEDIUM",
                    "details": (
                        f"{len(unique_targets)} hosts probed in "
                        f"{config.PING_SWEEP_WINDOW_SEC}s"
                    ),
                }
            )
