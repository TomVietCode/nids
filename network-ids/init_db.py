
import sys
from pathlib import Path

from sqlalchemy import inspect

import config
from db.database import engine, Base
import db.models  # noqa: F401  (import side-effect: registers models on Base)


def main() -> int:
    db_file = Path(config.DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(engine)

    tables = set(inspect(engine).get_table_names())
    expected = {"packet_log", "alert_history", "ip_list"}
    missing = expected - tables
    if missing:
        print(f"[FAIL] Missing tables after create_all: {missing}", file=sys.stderr)
        return 1

    print(f"[OK] Database ready at {db_file.resolve()}")
    print(f"     Tables: {sorted(tables)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
