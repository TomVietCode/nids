"""
One-time migration: add is_blocked column to packet_log.

Run once on the host VM (where nids.sqlite lives):
    sudo .venv/bin/python migrate_add_is_blocked.py

Safe to re-run — uses IF NOT EXISTS check before ALTER.
"""

import sqlite3
from pathlib import Path
import config

db_path = Path(config.DB_PATH)
if not db_path.exists():
    print(f"[SKIP] DB not found at {db_path.resolve()} — chạy main.py trước.")
    raise SystemExit(0)

with sqlite3.connect(db_path) as conn:
    # Kiểm tra column đã tồn tại chưa
    cols = [row[1] for row in conn.execute("PRAGMA table_info(packet_log)")]
    if "is_blocked" in cols:
        print("[SKIP] Column is_blocked đã tồn tại.")
    else:
        conn.execute(
            "ALTER TABLE packet_log ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0"
        )
        print("[OK] Đã thêm column is_blocked vào packet_log.")
