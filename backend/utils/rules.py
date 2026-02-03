import re
import sqlite3
from datetime import datetime
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
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                pattern TEXT,
                match_type TEXT,
                action TEXT,
                enabled INTEGER,
                priority INTEGER,
                notes TEXT,
                source TEXT,
                expires_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        _ensure_columns(cursor)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Rules DB Init Error: {e}")


init_db()

def _ensure_columns(cursor):
    try:
        cursor.execute("PRAGMA table_info(rules)")
        existing = {row[1] for row in cursor.fetchall()}
        columns = {
            "source": "TEXT",
            "expires_at": "TEXT",
        }
        for name, col_type in columns.items():
            if name not in existing:
                cursor.execute(f"ALTER TABLE rules ADD COLUMN {name} {col_type}")
    except Exception as e:
        print(f"Rules Column Ensure Error: {e}")


def list_rules() -> List[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM rules ORDER BY priority ASC, id ASC"
    )
    rows = cursor.fetchall()
    conn.close()
    rules = []
    for row in rows:
        rules.append(
            {
                "id": row["id"],
                "name": row["name"],
                "pattern": row["pattern"],
                "match_type": row["match_type"],
                "action": row["action"],
                "enabled": bool(row["enabled"]),
                "priority": row["priority"],
                "notes": row["notes"],
                "source": row["source"],
                "expires_at": row["expires_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return rules


def create_rule(data: Dict) -> Dict:
    conn = get_db()
    cursor = conn.cursor()
    now = _now()
    cursor.execute(
        """
        INSERT INTO rules (name, pattern, match_type, action, enabled, priority, notes, source, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("name"),
            data.get("pattern"),
            data.get("match_type"),
            data.get("action"),
            1 if data.get("enabled", True) else 0,
            int(data.get("priority", 100)),
            data.get("notes"),
            data.get("source"),
            data.get("expires_at"),
            now,
            now,
        ),
    )
    conn.commit()
    rule_id = cursor.lastrowid
    conn.close()
    data["id"] = rule_id
    data["created_at"] = now
    data["updated_at"] = now
    return data


def upsert_rule_by_pattern(data: Dict) -> Dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM rules WHERE pattern = ? AND match_type = ?",
        (data.get("pattern"), data.get("match_type")),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return update_rule(row["id"], data)
    return create_rule(data)


def update_rule(rule_id: int, data: Dict) -> Optional[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    now = _now()
    cursor.execute(
        """
        UPDATE rules
        SET name = ?, pattern = ?, match_type = ?, action = ?, enabled = ?, priority = ?, notes = ?, source = ?, expires_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            data.get("name"),
            data.get("pattern"),
            data.get("match_type"),
            data.get("action"),
            1 if data.get("enabled", True) else 0,
            int(data.get("priority", 100)),
            data.get("notes"),
            data.get("source"),
            data.get("expires_at"),
            now,
            rule_id,
        ),
    )
    conn.commit()
    conn.close()
    data["id"] = rule_id
    data["updated_at"] = now
    return data


def delete_rule(rule_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0


def _normalize_domain(domain: str) -> str:
    return domain.lower().rstrip(".")


def _match_rule(domain: str, rule: Dict) -> bool:
    pattern = (rule.get("pattern") or "").strip().lower()
    match_type = (rule.get("match_type") or "EXACT").upper()
    if not pattern:
        return False

    if match_type == "EXACT":
        return domain == pattern
    if match_type == "SUFFIX":
        if domain == pattern:
            return True
        return domain.endswith("." + pattern)
    if match_type == "REGEX":
        try:
            return re.search(pattern, domain) is not None
        except re.error:
            return False
    return False


def evaluate_domain(domain: str) -> Optional[Dict]:
    domain = _normalize_domain(domain)
    for rule in list_rules():
        if not rule.get("enabled", True):
            continue
        expires_at = rule.get("expires_at")
        if expires_at:
            try:
                if datetime.utcnow().isoformat() >= expires_at.replace("Z", ""):
                    continue
            except Exception:
                pass
        if _match_rule(domain, rule):
            return rule
    return None
