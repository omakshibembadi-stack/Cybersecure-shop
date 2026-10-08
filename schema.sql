-- ==============================================================================
-- SecureShop - Database Schema and Seed Data
-- Database Engine: SQLite3
-- File: database.db
-- Purpose: Relational schema for users, products, orders, and order_items
-- ==============================================================================

DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

-- 1. Users Table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    password_algo TEXT NOT NULL DEFAULT 'plaintext',
    role TEXT NOT NULL DEFAULT 'customer',
    bio TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Products Table
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 50,
    image_url TEXT DEFAULT '/static/placeholder.png'
);

-- 3. Orders Table
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total_amount REAL NOT NULL,
    shipping_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Processing',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 4. Order Items Table
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- ==============================================================================
-- Seed Data
-- ==============================================================================

-- Test Accounts:
-- 1. admin: AdminPass123! (Role: admin)
-- 2. alice: AlicePass456! (Role: customer)
-- 3. bob:   BobPass789!   (Role: customer)
INSERT INTO users (id, username, email, password, password_algo, role, bio) VALUES
(1, 'admin', 'admin@secureshop.local', 'AdminPass123!', 'plaintext', 'admin', 'System Administrator with elevated portal privileges.'),
(2, 'alice', 'alice@secureshop.local', 'AlicePass456!', 'plaintext', 'customer', 'Cybersecurity student and technology enthusiast.'),
(3, 'bob', 'bob@secureshop.local', 'BobPass789!', 'plaintext', 'customer', 'DevOps engineer looking for secure authentication hardware.');

-- Sample Products
INSERT INTO products (id, name, description, category, price, stock, image_url) VALUES
(1, 'Hardware Security Key (FIDO2/U2F)', 'Cryptographic USB-C/NFC hardware security token supporting FIDO2, WebAuthn, and TOTP.', 'Hardware', 45.00, 100, '/static/placeholder.png'),
(2, 'Mechanical Cyberdeck Keyboard', 'Hot-swappable RGB mechanical keyboard with integrated programmable macro keys and QMK firmware.', 'Peripherals', 129.99, 45, '/static/placeholder.png'),
(3, 'Privacy Shield Webcam 1080p', 'Full HD streaming webcam with physical privacy shutter slide and stereo noise-canceling mic.', 'Peripherals', 39.50, 80, '/static/placeholder.png'),
(4, 'Encrypted Portable SSD 1TB', 'Hardware-encrypted USB-C NVMe external solid state drive with built-in PIN pad authentication.', 'Storage', 149.00, 30, '/static/placeholder.png'),
(5, 'RFID Blocking Security Backpack', 'Water-resistant tactical everyday carry bag with Faraday signal-blocking pocket and lockable zippers.', 'Accessories', 89.95, 25, '/static/placeholder.png'),
(6, 'Anti-Glare 27-inch 4K Monitor', 'Ultra-sharp IPS display featuring privacy viewing filter angles, low blue light, and 99% sRGB.', 'Displays', 389.00, 15, '/static/placeholder.png');

-- Sample Orders
INSERT INTO orders (id, user_id, total_amount, shipping_address, status) VALUES
(101, 2, 45.00, '42 Silicon Avenue, Tech City, CA 94016', 'Shipped'),
(102, 3, 179.45, '108 Binary Blvd, Cyberspace, NY 10001', 'Delivered'),
(103, 2, 149.00, '42 Silicon Avenue, Tech City, CA 94016', 'Processing');

-- Sample Order Items
INSERT INTO order_items (id, order_id, product_id, quantity, unit_price) VALUES
(1, 101, 1, 1, 45.00),
(2, 102, 1, 2, 45.00),
(3, 102, 5, 1, 89.45),
(4, 103, 4, 1, 149.00);
