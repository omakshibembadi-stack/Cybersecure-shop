"""
Database management, schema execution, and seeding for SecureShop e-commerce lab.
Primary database file: database.db
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    """
    Initializes the SQLite database.
    If database.db does not exist or force_reseed is True, executes schema.sql.
    """
    if force_reseed and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    # If database file already exists and not reseeding, check if tables exist
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

    # Execute schema.sql to build schema and populate seed records
    conn = get_db_connection()
    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_script = f.read()
        conn.executescript(schema_script)
    else:
        # Fallback DDL if schema.sql is not found
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_algo TEXT NOT NULL DEFAULT 'plaintext',
            role TEXT NOT NULL DEFAULT 'customer',
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 50,
            image_url TEXT DEFAULT '/static/placeholder.png'
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            shipping_address TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Processing',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        """)
        cursor.execute("""
        INSERT INTO users (username, email, password, password_algo, role, bio) VALUES
        ('admin', 'admin@secureshop.local', 'AdminPass123!', 'plaintext', 'admin', 'System Administrator with elevated portal privileges.'),
        ('alice', 'alice@secureshop.local', 'AlicePass456!', 'plaintext', 'customer', 'Cybersecurity student and technology enthusiast.'),
        ('bob', 'bob@secureshop.local', 'BobPass789!', 'plaintext', 'customer', 'DevOps engineer looking for secure authentication hardware.');
        """)
        conn.commit()

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db(force_reseed=True)
    print("Database initialized successfully at:", DB_PATH)
