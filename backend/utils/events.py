import sqlite3
import json
from pathlib import Path
from datetime import datetime

# DB Setup
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "backend" / "events.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ray_id TEXT,
                domain TEXT,
                score REAL,
                action TEXT,
                timestamp TEXT,
                source TEXT,
                client_ip TEXT,
                rule_id INTEGER,
                rule_action TEXT,
                label TEXT,
                qtype TEXT,
                raw_data TEXT
            )
        ''')
        _ensure_columns(cursor)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Init Error: {e}")

# Ensure older DBs get new columns without losing data
def _ensure_columns(cursor):
    try:
        cursor.execute("PRAGMA table_info(events)")
        existing = {row[1] for row in cursor.fetchall()}
        columns = {
            "client_ip": "TEXT",
            "rule_id": "INTEGER",
            "rule_action": "TEXT",
            "label": "TEXT",
            "qtype": "TEXT",
        }
        for name, col_type in columns.items():
            if name not in existing:
                cursor.execute(f"ALTER TABLE events ADD COLUMN {name} {col_type}")
    except Exception as e:
        print(f"DB Column Ensure Error: {e}")

# Initialize on module import
init_db()

def log_event(event: dict):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Serialize full event for raw_data column just in case
        raw_data = json.dumps(event)
        
        cursor.execute('''
            INSERT INTO events (ray_id, domain, score, action, timestamp, source, client_ip, rule_id, rule_action, label, qtype, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get("ray_id"),
            event.get("domain"),
            event.get("score"),
            event.get("action"),
            event.get("timestamp"),
            event.get("source", "unknown"),
            event.get("client_ip"),
            event.get("rule_id"),
            event.get("rule_action"),
            event.get("label"),
            event.get("qtype"),
            raw_data
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log Event Error: {e}")

def get_events(limit=100):
    events = []
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        
        for row in rows:
            events.append({
                "ray_id": row["ray_id"],
                "domain": row["domain"],
                "score": row["score"],
                "action": row["action"],
                "timestamp": row["timestamp"],
                "source": row["source"],
                "client_ip": row["client_ip"],
                "rule_id": row["rule_id"],
                "rule_action": row["rule_action"],
                "label": row["label"],
                "qtype": row["qtype"]
            })
        conn.close()
    except Exception as e:
        print(f"Get Events Error: {e}")
    
    return events
