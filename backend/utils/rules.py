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
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Rules DB Init Error: {e}")


init_db()


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
        INSERT INTO rules (name, pattern, match_type, action, enabled, priority, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("name"),
            data.get("pattern"),
            data.get("match_type"),
            data.get("action"),
            1 if data.get("enabled", True) else 0,
            int(data.get("priority", 100)),
            data.get("notes"),
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


def update_rule(rule_id: int, data: Dict) -> Optional[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    now = _now()
    cursor.execute(
        """
        UPDATE rules
        SET name = ?, pattern = ?, match_type = ?, action = ?, enabled = ?, priority = ?, notes = ?, updated_at = ?
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
        if _match_rule(domain, rule):
            return rule
    return None
