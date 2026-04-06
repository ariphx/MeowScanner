# utils/db_manager.py
import sqlite3
import logging
import sys
from config import DB_NAME

logger = logging.getLogger("MeowDB")

def init_db() -> None:
    try:
        conn = sqlite3.connect(DB_NAME)
        curr = conn.cursor()
        curr.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                hash TEXT PRIMARY KEY,
                target TEXT,
                vuln_name TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Gagal menginisialisasi database: {e}")
        sys.exit(1)

def is_new_finding(finding_hash: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    curr = conn.cursor()
    curr.execute("SELECT 1 FROM vulnerabilities WHERE hash = ?", (finding_hash,))
    result = curr.fetchone()
    conn.close()
    return result is None

def save_finding(finding_hash: str, target_url: str, vuln_name: str, severity: str) -> None:
    conn = sqlite3.connect(DB_NAME)
    curr = conn.cursor()
    curr.execute(
        "INSERT INTO vulnerabilities (hash, target, vuln_name, severity) VALUES (?, ?, ?, ?)",
        (finding_hash, target_url, vuln_name, severity)
    )
    conn.commit()
    conn.close()
