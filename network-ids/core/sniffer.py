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

import ipaddress
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
    def __init__(
        self,
        analyzer: Analyzer,
        alert_sink: Optional[AlertSink] = None,
        blocked_ips: Optional[set] = None,  # Reference to Responder.blocked_ips
    ) -> None:
        self.analyzer = analyzer
        self.alert_sink = alert_sink
        # Use Responder's set to know which IPs are being iptables DROP
        self._blocked_ips: set = blocked_ips if blocked_ips is not None else set()

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
        noise_udp = " or ".join(
            f"udp port {p}" for p in config.IGNORE_UDP_PORTS
        )
        noise_dst = " or ".join(
            f"dst host {ip}" for ip in config.IGNORE_DST_IPS
        )
        bpf = (
            f"arp or (not port {config.FLASK_PORT}"
            f" and not src host {config.VPS_IP}"
            f" and not ({noise_udp})"
            f" and not ({noise_dst}))"
        )
        sniff(
            iface=config.NETWORK_INTERFACE,
            filter=bpf,
            prn=self._handle,
            store=False,
            stop_filter=lambda _p: self._stop.is_set(),
        )

    def _handle(self, pkt: Packet) -> None:
        meta = self._extract_meta(pkt)
        if meta is None:
            return

        # Filter by src IP (VMware gateway, VM itself) and dst IP (multicast/broadcast).
        if meta["src_ip"] in config.IGNORE_IPS:
            return
        if meta["dst_ip"] in config.IGNORE_DST_IPS:
            return
        # Ignore UDP noise port if BPF cannot catch it (e.g., ARP encapsulated)
        if (
            meta["protocol"] == "UDP"
            and meta.get("dst_port") in config.IGNORE_UDP_PORTS
        ):
            return

        # Check if src_ip is being iptables DROP.
        # If yes: only log with is_blocked=True, ignore detection —
        # because this IP has been processed, further alerts are just noise.
        is_blocked = meta["src_ip"] in self._blocked_ips

        has_alerts = False
        if not is_blocked:
            # Detection (synchronous, in-memory; O(1) per packet)
            alerts = self.analyzer.process(pkt, meta)
            has_alerts = bool(alerts)
            if alerts and self.alert_sink:
                for a in alerts:
                    try:
                        self.alert_sink(a)
                    except Exception as e:
                        print(f"[sniffer] alert sink error: {e}")

        # Routine traffic classification (Task 4).
        # Never mark a packet as routine if it triggered an alert.
        is_routine = False
        routine_reason = None
        if not has_alerts and not is_blocked:
            is_routine, routine_reason = self._classify_routine(meta)

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
                "is_blocked": is_blocked,
                "is_routine": is_routine,
                "routine_reason": routine_reason,
            })

    # ------------------------------------------------------------------
    # routine traffic classification (noise filter)
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_routine(meta: dict) -> tuple[bool, Optional[str]]:
        """Check if a packet is routine/benign background traffic.

        Returns (is_routine, reason_string).
        This is only called when the packet did NOT trigger any alert.
        """
        proto = meta["protocol"]
        src = meta["src_ip"]
        dst = meta["dst_ip"]

        # Check 1: Protocol in the suppression list
        if proto in config.FILTER_PROTOCOLS:
            # ARP broadcast check
            if proto == "ARP" and config.FILTER_ARP_BROADCASTS:
                # ARP to broadcast/gateway is normal LAN behavior
                if dst in config.GATEWAY_IPS or dst.endswith(".255"):
                    return True, f"ARP broadcast to {dst} — normal LAN behavior"
                # ARP between hosts in trusted subnet
                for subnet_str in config.TRUSTED_LOCAL_SUBNETS:
                    try:
                        net = ipaddress.ip_network(subnet_str, strict=False)
                        if (ipaddress.ip_address(src) in net and
                                ipaddress.ip_address(dst) in net):
                            return True, f"ARP within trusted subnet {subnet_str}"
                    except ValueError:
                        continue
            # Non-ARP filtered protocol
            elif proto in config.FILTER_PROTOCOLS:
                return True, f"{proto} — filtered protocol"

        # Check 2: Traffic to/from gateway IPs (routine for any protocol)
        if dst in config.GATEWAY_IPS or src in config.GATEWAY_IPS:
            for subnet_str in config.TRUSTED_LOCAL_SUBNETS:
                try:
                    net = ipaddress.ip_network(subnet_str, strict=False)
                    src_in = ipaddress.ip_address(src) in net
                    dst_in = ipaddress.ip_address(dst) in net
                    if src_in and dst_in:
                        gw = dst if dst in config.GATEWAY_IPS else src
                        return True, f"Routine traffic to gateway {gw}"
                except ValueError:
                    continue

        return False, None

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
            time.sleep(0.1)  # Poll frequently to check buffer size and elapsed time
            should_flush = False
            with self._buffer_lock:
                if self._buffer:
                    elapsed = time.time() - self._last_flush
                    if len(self._buffer) >= config.BULK_INSERT_BATCH_SIZE or elapsed >= config.FLUSH_INTERVAL_SEC:
                        should_flush = True
            if should_flush:
                self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        with self._buffer_lock:
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