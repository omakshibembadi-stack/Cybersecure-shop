"""
SecureShop (Vulnerable Version) - Database Module
Initializes and connects to vulnerable/database.db
"""
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    """
    Initializes the vulnerable SQLite database from schema.sql.
    """
    if force_reseed and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    if os.path.exists(DB_PATH) and not force_reseed:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            cursor.fetchone()
            conn.close()
            return
        except Exception:
            pass

    conn = get_db_connection()
    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db(force_reseed=True)
    print("Vulnerable database initialized successfully at:", DB_PATH)
