import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from backend.utils.rules import upsert_rule_by_pattern

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "backend" / "events.db"


def _now():
    return datetime.utcnow().isoformat() + "Z"


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS list_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            list_type TEXT,
            url TEXT,
            enabled INTEGER,
            last_fetched TEXT,
            last_imported INTEGER,
            last_error TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def list_sources() -> List[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM list_sources ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "list_type": row["list_type"],
            "url": row["url"],
            "enabled": bool(row["enabled"]),
            "last_fetched": row["last_fetched"],
            "last_imported": row["last_imported"] or 0,
            "last_error": row["last_error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def create_source(data: Dict) -> Dict:
    conn = get_db()
    cursor = conn.cursor()
    now = _now()
    cursor.execute(
        """
        INSERT INTO list_sources
        (name, list_type, url, enabled, last_fetched, last_imported, last_error, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("name"),
            data.get("list_type"),
            data.get("url"),
            1 if data.get("enabled", True) else 0,
            None,
            0,
            None,
            now,
            now,
        ),
    )
    conn.commit()
    source_id = cursor.lastrowid
    conn.close()
    data["id"] = source_id
    data["created_at"] = now
    data["updated_at"] = now
    data["last_imported"] = 0
    return data


def delete_source(source_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM list_sources WHERE id = ?", (source_id,))
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0


def update_source(source_id: int, data: Dict) -> Optional[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    now = _now()
    cursor.execute(
        """
        UPDATE list_sources
        SET name = ?, list_type = ?, url = ?, enabled = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            data.get("name"),
            data.get("list_type"),
            data.get("url"),
            1 if data.get("enabled", True) else 0,
            now,
            source_id,
        ),
    )
    conn.commit()
    conn.close()
    data["id"] = source_id
    data["updated_at"] = now
    return data


def _is_valid_hostname(name: str) -> bool:
    if not name or len(name) > 255:
        return False
    if "://" in name or "/" in name or "@" in name:
        return False
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def _extract_domain(line: str) -> Optional[str]:
    raw = line.strip()
    if not raw:
        return None
    if raw.startswith("#") or raw.startswith("//") or raw.startswith(";"):
        return None
    if raw.startswith("0.0.0.0") or raw.startswith("127.0.0.1"):
        parts = raw.split()
        if len(parts) >= 2:
            raw = parts[1]
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            return urlparse(raw).hostname
        except Exception:
            return None
    raw = raw.split()[0].split(",")[0].strip()
    raw = raw.lower().rstrip(".")
    if _is_valid_hostname(raw):
        return raw
    return None


def _apply_domain(domain: str, list_type: str, source: str) -> bool:
    list_type = (list_type or "").lower()
    if list_type == "whitelist":
        rule = {
            "name": f"allow {domain}",
            "pattern": domain,
            "match_type": "SUFFIX",
            "action": "ALLOW",
            "enabled": True,
            "priority": 1,
            "notes": f"source:{source}",
            "source": "list",
        }
    else:
        rule = {
            "name": f"block {domain}",
            "pattern": domain,
            "match_type": "SUFFIX",
            "action": "BLOCK",
            "enabled": True,
            "priority": 100,
            "notes": f"source:{source}",
            "source": "list",
        }
    upsert_rule_by_pattern(rule)
    return True


def pull_source(source: Dict) -> Dict:
    url = source.get("url")
    list_type = source.get("list_type")
    name = source.get("name") or url
    now = _now()
    imported = 0
    error = None
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            domain = _extract_domain(line)
            if not domain:
                continue
            if _apply_domain(domain, list_type, source=name):
                imported += 1
    except Exception as e:
        error = str(e)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE list_sources
        SET last_fetched = ?, last_imported = ?, last_error = ?, updated_at = ?
        WHERE id = ?
        """,
        (now, imported, error, now, source.get("id")),
    )
    conn.commit()
    conn.close()
    return {"imported": imported, "error": error}


def pull_all_sources() -> Dict:
    sources = [s for s in list_sources() if s.get("enabled", True)]
    total = 0
    errors: List[Dict] = []
    for src in sources:
        result = pull_source(src)
        total += result.get("imported", 0)
        if result.get("error"):
            errors.append({"id": src.get("id"), "error": result.get("error")})
    return {"sources": len(sources), "imported": total, "errors": errors}


def list_status() -> Dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM list_sources")
    total_sources = cursor.fetchone()[0]
    cursor.execute("SELECT MAX(last_fetched) FROM list_sources")
    last_fetched = cursor.fetchone()[0]
    cursor.execute("SELECT SUM(last_imported) FROM list_sources")
    total_imported = cursor.fetchone()[0] or 0
    conn.close()
    return {
        "total_sources": total_sources,
        "last_fetched": last_fetched,
        "last_imported": total_imported,
    }
