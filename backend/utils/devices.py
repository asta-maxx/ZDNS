import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "backend" / "events.db"


def _now():
    return datetime.utcnow().isoformat()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                query_count INTEGER,
                blocked_count INTEGER,
                warn_count INTEGER,
                allow_count INTEGER
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Devices DB Init Error: {e}")


init_db()


def update_device(ip: str, action: str, hostname: Optional[str] = None):
    if not ip:
        return
    now = _now()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
    row = cursor.fetchone()

    blocked = 1 if action == "BLOCK" else 0
    warn = 1 if action == "WARN" else 0
    allow = 1 if action == "ALLOW" else 0

    if row is None:
        cursor.execute(
            """
            INSERT INTO devices (ip, hostname, first_seen, last_seen, query_count, blocked_count, warn_count, allow_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ip, hostname, now, now, 1, blocked, warn, allow),
        )
    else:
        cursor.execute(
            """
            UPDATE devices
            SET hostname = COALESCE(?, hostname),
                last_seen = ?,
                query_count = query_count + 1,
                blocked_count = blocked_count + ?,
                warn_count = warn_count + ?,
                allow_count = allow_count + ?
            WHERE ip = ?
            """,
            (hostname, now, blocked, warn, allow, ip),
        )
    conn.commit()
    conn.close()


def list_devices(limit: int = 50) -> List[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    devices = []
    for row in rows:
        devices.append(
            {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "query_count": row["query_count"],
                "blocked_count": row["blocked_count"],
                "warn_count": row["warn_count"],
                "allow_count": row["allow_count"],
            }
        )
    return devices


def count_active_devices(window_minutes: int = 60) -> int:
    conn = get_db()
    cursor = conn.cursor()
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    cursor.execute(
        "SELECT COUNT(*) as total FROM devices WHERE last_seen >= ?",
        (cutoff.isoformat(),),
    )
    row = cursor.fetchone()
    conn.close()
    return int(row["total"]) if row else 0
