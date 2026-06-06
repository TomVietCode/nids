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
        # Exclude Flask port and VPS's own outbound traffic at the kernel
        # level (most efficient). ARP packets are unaffected because the
        # "src host" filter only applies to the IP header.
        bpf = f"not port 5000 and not src host {config.VPS_IP}"
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

        # Secondary Python-level filter for known benign IPs (belt-and-suspenders)
        if meta["src_ip"] in config.IGNORE_IPS:
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