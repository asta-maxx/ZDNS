import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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
        CREATE TABLE IF NOT EXISTS stix_collections (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            can_read INTEGER,
            can_write INTEGER,
            created_at TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS stix_objects (
            id TEXT PRIMARY KEY,
            collection_id TEXT,
            type TEXT,
            spec_version TEXT,
            created TEXT,
            modified TEXT,
            object_json TEXT,
            added_at TEXT,
            FOREIGN KEY(collection_id) REFERENCES stix_collections(id)
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def _ensure_default_collection():
    default_id = "zdns-threat-intel"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM stix_collections WHERE id = ?", (default_id,))
    row = cursor.fetchone()
    if not row:
        cursor.execute(
            """
            INSERT INTO stix_collections (id, title, description, can_read, can_write, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                default_id,
                "ZDNS Threat Intel",
                "Primary collection for ZDNS threat intelligence",
                1,
                1,
                _now(),
            ),
        )
        conn.commit()
    conn.close()
    return default_id


def list_collections() -> List[Dict]:
    _ensure_default_collection()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stix_collections ORDER BY created_at ASC")
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "can_read": bool(row["can_read"]),
            "can_write": bool(row["can_write"]),
            "created": row["created_at"],
        }
        for row in rows
    ]


def get_collection(collection_id: str) -> Optional[Dict]:
    _ensure_default_collection()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stix_collections WHERE id = ?", (collection_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "can_read": bool(row["can_read"]),
        "can_write": bool(row["can_write"]),
        "created": row["created_at"],
    }


def add_objects(collection_id: str, objects: List[Dict]) -> Dict:
    added = 0
    conn = get_db()
    cursor = conn.cursor()
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_id = obj.get("id")
        obj_type = obj.get("type")
        if not obj_id or not obj_type:
            continue
        cursor.execute(
            """
            INSERT OR REPLACE INTO stix_objects
            (id, collection_id, type, spec_version, created, modified, object_json, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                obj_id,
                collection_id,
                obj_type,
                obj.get("spec_version"),
                obj.get("created"),
                obj.get("modified"),
                json.dumps(obj),
                _now(),
            ),
        )
        added += 1
    conn.commit()
    conn.close()
    return {"added": added}


def get_objects(collection_id: str, limit: int = 500, after: Optional[str] = None) -> List[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    if after:
        cursor.execute(
            """
            SELECT * FROM stix_objects
            WHERE collection_id = ? AND added_at > ?
            ORDER BY added_at ASC
            LIMIT ?
            """,
            (collection_id, after, limit),
        )
    else:
        cursor.execute(
            """
            SELECT * FROM stix_objects
            WHERE collection_id = ?
            ORDER BY added_at ASC
            LIMIT ?
            """,
            (collection_id, limit),
        )
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row["object_json"]) for row in rows]


def get_manifest(collection_id: str) -> List[Dict]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, modified, added_at FROM stix_objects
        WHERE collection_id = ?
        ORDER BY added_at ASC
        """,
        (collection_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "date_added": row["added_at"],
            "version": row["modified"] or row["added_at"],
        }
        for row in rows
    ]
