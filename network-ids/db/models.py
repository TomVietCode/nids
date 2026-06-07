"""
SQLAlchemy 2.0 ORM models for the three tables defined in
SECTION: DATABASE_SCHEMA of PROJECT_OVERVIEW.md.

  packet_log     -- LOG-01 (per-packet metadata)
  alert_history  -- LOG-02, RES-01 (detection results)
  ip_list        -- RES-03 (whitelist / blacklist)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String
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
    # True nếu src_ip đang bị iptables DROP — packet đến NIC nhưng kernel hủy, app không bị ảnh hưởng
    is_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="0")
    # Routine traffic classification (noise filter)
    is_routine: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="0")
    routine_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)


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