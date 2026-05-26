"""
SocketIO server-to-client events.

  traffic_update   list[{"t": "HH:MM:SS", "pps": int}]   every 1s (DSH-01)
  new_alert        alert dict                            on each detection (RES-01 / DSH-02)

The traffic emitter runs in a daemon thread spawned at app startup. It counts
new packet_log rows since the last poll -- this is cheap because packet_log.id
is indexed and we filter on id > last_seen_id.
"""

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

from flask_socketio import SocketIO
from sqlalchemy import func, select

from db.database import session_scope
from db.models import PacketLog


_TRAFFIC_WINDOW_SEC = 60
_traffic_window = deque(maxlen=_TRAFFIC_WINDOW_SEC)


def attach(socketio: SocketIO) -> Callable[[dict], None]:
    """Spawn the traffic emitter and return a function that emits 'new_alert'."""

    def emit_alert(alert: dict) -> None:
        # SocketIO emits must contain JSON-serializable values.
        payload = dict(alert)
        ts = payload.get("timestamp")
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                payload["timestamp"] = ts.replace(tzinfo=timezone.utc).isoformat()
            else:
                payload["timestamp"] = ts.isoformat()
        socketio.emit("new_alert", payload)

    def _traffic_loop() -> None:
        last_seen_id = 0
        while True:
            try:
                with session_scope() as s:
                    cnt, max_id = s.execute(
                        select(
                            func.count(PacketLog.id),
                            func.coalesce(func.max(PacketLog.id), 0),
                        ).where(PacketLog.id > last_seen_id)
                    ).one()
                last_seen_id = int(max_id) or last_seen_id
                _traffic_window.append(
                    {
                        "t": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
                        "pps": int(cnt),
                    }
                )
                socketio.emit("traffic_update", list(_traffic_window))
            except Exception as e:
                print(f"[ws] traffic loop error: {e}")
            time.sleep(1)

    threading.Thread(target=_traffic_loop, name="traffic_ws", daemon=True).start()
    return emit_alert
