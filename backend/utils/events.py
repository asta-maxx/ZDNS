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
                raw_data TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Init Error: {e}")

# Initialize on module import
init_db()

def log_event(event: dict):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Serialize full event for raw_data column just in case
        raw_data = json.dumps(event)
        
        cursor.execute('''
            INSERT INTO events (ray_id, domain, score, action, timestamp, source, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get("ray_id"),
            event.get("domain"),
            event.get("score"),
            event.get("action"),
            event.get("timestamp"),
            event.get("source", "unknown"),
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
                "source": row["source"]
            })
        conn.close()
    except Exception as e:
        print(f"Get Events Error: {e}")
    
    return events
