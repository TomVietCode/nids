"""
Migration: add is_routine and routine_reason columns to packet_log.

Run once:
    python migrate_add_routine.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "db" / "nids.sqlite"


def migrate():
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    # Check which columns already exist to make this idempotent
    cur.execute("PRAGMA table_info(packet_log)")
    existing = {row[1] for row in cur.fetchall()}

    if "is_routine" not in existing:
        cur.execute(
            "ALTER TABLE packet_log ADD COLUMN is_routine BOOLEAN NOT NULL DEFAULT 0"
        )
        print("[migrate] added column: is_routine")
    else:
        print("[migrate] column is_routine already exists, skipping")

    if "routine_reason" not in existing:
        cur.execute(
            "ALTER TABLE packet_log ADD COLUMN routine_reason TEXT"
        )
        print("[migrate] added column: routine_reason")
    else:
        print("[migrate] column routine_reason already exists, skipping")

    conn.commit()
    conn.close()
    print("[migrate] done")


if __name__ == "__main__":
    migrate()
