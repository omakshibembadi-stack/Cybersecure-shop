"""
SecureShop (Remediated Fixed Version) - Database Module
Initializes fixed/database.db with salted password hashes.
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    """
    Initializes the secure SQLite database and seeds with hashed passwords.
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

    cursor = conn.cursor()

    # Seed users with salted password hashes
    admin_pw = generate_password_hash("AdminPass123!")
    alice_pw = generate_password_hash("AlicePass456!")
    bob_pw = generate_password_hash("BobPass789!")

    cursor.execute("""
    INSERT INTO users (id, username, email, password, password_algo, role, bio) VALUES
    (1, 'admin', 'admin@secureshop.local', ?, 'scrypt', 'admin', 'System Administrator with elevated portal privileges.'),
    (2, 'alice', 'alice@secureshop.local', ?, 'scrypt', 'customer', 'Cybersecurity student and technology enthusiast.'),
    (3, 'bob', 'bob@secureshop.local', ?, 'scrypt', 'customer', 'DevOps engineer looking for secure authentication hardware.');
    """, (admin_pw, alice_pw, bob_pw))

    # Seed products
    cursor.execute("""
    INSERT INTO products (id, name, description, category, price, stock, image_url) VALUES
    (1, 'Hardware Security Key (FIDO2/U2F)', 'Cryptographic USB-C/NFC hardware security token supporting FIDO2, WebAuthn, and TOTP.', 'Hardware', 45.00, 100, '/static/placeholder.png'),
    (2, 'Mechanical Cyberdeck Keyboard', 'Hot-swappable RGB mechanical keyboard with integrated programmable macro keys and QMK firmware.', 'Peripherals', 129.99, 45, '/static/placeholder.png'),
    (3, 'Privacy Shield Webcam 1080p', 'Full HD streaming webcam with physical privacy shutter slide and stereo noise-canceling mic.', 'Peripherals', 39.50, 80, '/static/placeholder.png'),
    (4, 'Encrypted Portable SSD 1TB', 'Hardware-encrypted USB-C NVMe external solid state drive with built-in PIN pad authentication.', 'Storage', 149.00, 30, '/static/placeholder.png'),
    (5, 'RFID Blocking Security Backpack', 'Water-resistant tactical everyday carry bag with Faraday signal-blocking pocket and lockable zippers.', 'Accessories', 89.95, 25, '/static/placeholder.png'),
    (6, 'Anti-Glare 27-inch 4K Monitor', 'Ultra-sharp IPS display featuring privacy viewing filter angles, low blue light, and 99% sRGB.', 'Displays', 389.00, 15, '/static/placeholder.png');
    """)

    # Seed orders
    cursor.execute("""
    INSERT INTO orders (id, user_id, total_amount, shipping_address, status) VALUES
    (101, 2, 45.00, '42 Silicon Avenue, Tech City, CA 94016', 'Shipped'),
    (102, 3, 179.45, '108 Binary Blvd, Cyberspace, NY 10001', 'Delivered'),
    (103, 2, 149.00, '42 Silicon Avenue, Tech City, CA 94016', 'Processing');
    """)

    # Seed order items
    cursor.execute("""
    INSERT INTO order_items (id, order_id, product_id, quantity, unit_price) VALUES
    (1, 101, 1, 1, 45.00),
    (2, 102, 1, 2, 45.00),
    (3, 102, 5, 1, 89.45),
    (4, 103, 4, 1, 149.00);
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db(force_reseed=True)
    print("Fixed database initialized successfully at:", DB_PATH)
