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
from datetime import datetime, timedelta, timezone
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
            "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat(),
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
                r.id, r.timestamp.replace(tzinfo=timezone.utc).isoformat(), r.src_ip, r.dst_ip,
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
            "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat(),
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
            "added_at": r.added_at.replace(tzinfo=timezone.utc).isoformat(),
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
        was_blacklisted = row.list_type == "blacklist"
        s.delete(row)

    # Sync iptables: remove the DROP rule if this was a blacklisted IP
    if was_blacklisted:
        import subprocess
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            pass  # iptables not available (e.g., dev environment)

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