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
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy import select

import config
from db.database import session_scope
from db.models import AlertHistory, IPList


SocketEmit = Callable[[dict], None]


class Responder:
    def __init__(self, socket_emit: Optional[SocketEmit] = None) -> None:
        self.socket_emit = socket_emit
        # Public set — Sniffer đọc để đánh dấu is_blocked trên packet log.
        # set.add() và `in` là thread-safe trong CPython (GIL bảo vệ).
        self.blocked_ips: set[str] = set()
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
            reason = f"auto-blocked: {severity} {alert.get('threat_type', '')}"
            self._apply_block(alert["src_ip"], reason=reason)
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
    def unblock(self, ip: str) -> None:
        """Remove IP from in-memory sets so it can be re-blocked on the next alert.
        Called by the API DELETE /iplist/<ip> route after DB + iptables are cleared.
        """
        with self._lock:
            self.blocked_ips.discard(ip)
            self._rate_limited.discard(ip)

    def _apply_block(self, ip: str, reason: str = "auto-blocked") -> None:
        with self._lock:
            if ip in self.blocked_ips:
                return
            self.blocked_ips.add(ip)
        try:
            # iptables -C returns 0 if the rule exists, !=0 otherwise.
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, check=False,
            )
            if check.returncode != 0:
                # -I INPUT 1 inserts at the TOP of the chain so this DROP
                # beats any existing ACCEPT rules (ufw, fail2ban, etc.).
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, check=True,
                )
            print(f"[responder] BLOCK {ip}")
        except FileNotFoundError:
            print(f"[responder] iptables binary not found; would BLOCK {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[responder] iptables BLOCK {ip} failed: {e.stderr}")

        # Persist to IPList DB so the block is visible on the dashboard
        # and survives restarts via _reapply_blacklist_on_boot().
        try:
            with session_scope() as s:
                existing = s.scalar(select(IPList).where(IPList.ip_address == ip))
                if not existing:
                    s.add(IPList(
                        ip_address=ip,
                        list_type="blacklist",
                        added_at=datetime.utcnow(),
                        reason=reason,
                    ))
        except Exception as e:
            print(f"[responder] DB write for auto-block {ip} failed: {e}")

    def _apply_rate_limit(self, ip: str) -> None:
        with self._lock:
            if ip in self._rate_limited:
                return
            self._rate_limited.add(ip)
        # Two-rule pattern: first rule ACCEPTs packets up to the limit,
        # second rule DROPs everything else from that IP.
        accept_rule = [
            "INPUT", "-s", ip,
            "-m", "limit", "--limit", config.RATE_LIMIT_RULE,
            "--limit-burst", "20",
            "-j", "ACCEPT",
        ]
        drop_rule = ["INPUT", "-s", ip, "-j", "DROP"]
        try:
            # Insert DROP first (position 1), then ACCEPT at position 1.
            # Result: ACCEPT at top, DROP right below — correct order.
            check_drop = subprocess.run(
                ["iptables", "-C", *drop_rule],
                capture_output=True, text=True, check=False,
            )
            if check_drop.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", *drop_rule[1:]],
                    capture_output=True, text=True, check=True,
                )
            check_accept = subprocess.run(
                ["iptables", "-C", *accept_rule],
                capture_output=True, text=True, check=False,
            )
            if check_accept.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", *accept_rule[1:]],
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