import sqlite3
import os
from datetime import datetime

# Database location (in user home directory)
DB_PATH = os.path.expanduser("~/.secure_vault/vault.db")


def init_db():
    """
    Initialize the database with necessary tables.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table for file metadata
    c.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT UNIQUE,
        stored_path TEXT,
        created_at TEXT
    )
    """)

    # Table for access logs
    c.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        action TEXT,
        filename TEXT,
        result TEXT
    )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized at", DB_PATH)


def log_action(action: str, filename: str, result: str = "OK"):
    """
    Log every operation performed on a file.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO access_logs (timestamp, action, filename, result) VALUES (?,?,?,?)",
        (datetime.utcnow().isoformat(), action, filename, result)
    )
    conn.commit()
    conn.close()


def get_logs(limit: int = 10):
    """
    Retrieve the last N logs.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, action, filename, result FROM access_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = c.fetchall()
    conn.close()
    return logs
