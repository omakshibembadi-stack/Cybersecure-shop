"""
==============================================================================
SecureShop - Intentionally Vulnerable Version (Assignment Baseline)
==============================================================================
Designed strictly for local college-level Application Security & Red Team labs.
Purpose: BUILD -> EXPOSE -> SCAN -> INVESTIGATE -> SAFELY VALIDATE

OWASP Top 10 Vulnerabilities Implemented:
  1. A01:2021 - Broken Access Control (IDOR on /profile/<id> & /order/<id>, Broken Admin RBAC)
  2. A03:2021 - Injection (SQL Injection in /search?q=)
  3. A05:2021 - Security Misconfiguration (Debug mode enabled, missing security headers, stack traces)
  4. A06:2021 - Vulnerable/Outdated Components (Werkzeug 2.2.2 CVE-2023-30861, Jinja2 3.1.2)
  5. A07:2021 - Authentication/Session Weakness (Plaintext passwords, static secret, insecure cookies)
  6. A09:2021 - Security Logging & Monitoring Failures (Plaintext credential logging, no audit trail)

Default URL: http://127.0.0.1:5000
==============================================================================
"""

import os
import sys
import logging
import importlib.util
_db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.py")
_spec = importlib.util.spec_from_file_location("vuln_database", _db_file)
_vuln_db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vuln_db)
get_db_connection = _vuln_db.get_db_connection
init_db = _vuln_db.init_db
DB_PATH = _vuln_db.DB_PATH

from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, session, abort

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
)

# Blueprints matching templates url_for namespaces
public_bp = Blueprint("public", __name__)
auth_bp = Blueprint("auth", __name__)
user_bp = Blueprint("user", __name__)
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A05: Security Misconfiguration)
# Debug mode is explicitly enabled to expose Werkzeug interactive debugging
# console and internal stack traces.
# ==============================================================================
app.config["DEBUG"] = True
app.config["TESTING"] = True
app.config["SECURITY_MODE"] = "vulnerable"

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A07: Authentication & Session Weakness)
# 1. Hardcoded, predictable secret key allows offline session cookie forgery.
# 2. SESSION_COOKIE_HTTPONLY is False, allowing JavaScript access to session cookie (XSS -> Account Takeover).
# 3. SESSION_COOKIE_SAMESITE is None, making session cookies vulnerable to CSRF.
# ==============================================================================
app.secret_key = "super_secret_hardcoded_lab_key_do_not_use_in_prod"
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [VULN-LOG] %(message)s"
)

# ------------------------------------------------------------------------------
# Context Processors & Middleware
# ------------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    total_items = sum(cart.values()) if isinstance(cart, dict) else 0
    return {
        "current_mode": "vulnerable",
        "cart_count": total_items
    }

@app.after_request
def apply_headers(response):
    # ==============================================================================
    # INTENTIONALLY VULNERABLE FOR SECURITY LAB (A05: Missing Security Headers)
    # Intentionally omits X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy.
    # Exposes detailed server software banner to scanner/crawlers.
    # ==============================================================================
    response.headers["Server"] = "Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)"
    return response

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A05: Verbose Error / Traceback Leak)
# ==============================================================================
@app.route("/debug/error")
def debug_error():
    """Controlled endpoint to demonstrate unhandled exception stack trace leakage."""
    raise RuntimeError("LAB_ERROR: Unhandled exception in vulnerable mode! Werkzeug traceback console active.")

# ------------------------------------------------------------------------------
# Public Routes
# ------------------------------------------------------------------------------
@public_bp.route("/")
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products LIMIT 3")
    featured = cursor.fetchall()
    conn.close()
    return render_template("index.html", featured_products=featured)

@public_bp.route("/products")
def products():
    category = request.args.get("category")
    conn = get_db_connection()
    cursor = conn.cursor()
    if category:
        cursor.execute("SELECT * FROM products WHERE category = ?", (category,))
    else:
        cursor.execute("SELECT * FROM products")
    all_products = cursor.fetchall()
    conn.close()
    return render_template("products.html", products=all_products, selected_category=category)

@public_bp.route("/product/<int:product_id>", endpoint="product_details")
@public_bp.route("/product/<int:product_id>", endpoint="product_detail")
@public_bp.route("/products/<int:product_id>")
def product_details(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    if not product:
        flash("Product not found.", "warning")
        return redirect(url_for("public.products"))
    return render_template("product_details.html", product=product)

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A03: Injection - SQL Injection)
# User input from 'q' parameter is directly concatenated into the raw SQL string
# via Python f-string formatting without sanitization or parameter binding.
# Safe demonstration payloads:
#   ' OR '1'='1
#   ' UNION SELECT id, username, email, password, role, 0.0, bio FROM users --
# ==============================================================================
@public_bp.route("/search")
def search():
    query = request.args.get("q", "").strip()
    debug_query = None
    results = []
    if query:
        conn = get_db_connection()
        cursor = conn.cursor()
        raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
        debug_query = raw_sql
        try:
            cursor.execute(raw_sql)
            results = cursor.fetchall()
        except Exception as e:
            flash(f"SQL Execution Error: {e}", "danger")
            results = []
        conn.close()
    return render_template("search.html", products=results, query=query, debug_query=debug_query)

@public_bp.route("/toggle-mode")
def toggle_mode():
    flash("This is the standalone VULNERABLE version. Run fixed/app.py for the remediated version.", "warning")
    return redirect(request.referrer or url_for("public.index"))

# ------------------------------------------------------------------------------
# Authentication Routes
# ------------------------------------------------------------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            flash("Username or email already in use.", "warning")
            return render_template("register.html")

        # ==============================================================================
        # INTENTIONALLY VULNERABLE FOR SECURITY LAB (A07: Plaintext Password Storage)
        # Passwords are saved in cleartext into SQLite without cryptographic hashing.
        # ==============================================================================
        cursor.execute("""
        INSERT INTO users (username, email, password, password_algo, role, bio)
        VALUES (?, ?, ?, 'plaintext', 'customer', ?)
        """, (username, email, password, bio))
        conn.commit()
        conn.close()

        flash("Registration successful! You may now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ==============================================================================
        # INTENTIONALLY VULNERABLE FOR SECURITY LAB (A09: Insecure Credential Logging)
        # Raw plaintext passwords are logged directly into application log streams.
        # ==============================================================================
        app.logger.warning(f"[INSECURE LOG] Login attempt for user='{username}' with raw password='{password}'")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user["password"] == password:
            # ==============================================================================
            # INTENTIONALLY VULNERABLE FOR SECURITY LAB (A07: Session Fixation)
            # Existing session is not cleared or regenerated upon authentication.
            # ==============================================================================
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")
            if user["role"] == "admin":
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("public.products"))
        else:
            # Verbose user enumeration feedback
            if not user:
                flash("User does not exist in the database.", "danger")
            else:
                flash("Incorrect password for specified user.", "danger")
            return render_template("login.html")

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("public.index"))

# ------------------------------------------------------------------------------
# Authenticated User Routes (A01: Broken Access Control / IDOR)
# ------------------------------------------------------------------------------
def check_logged_in():
    if "user_id" not in session:
        flash("Please log in to access this page.", "warning")
        return False
    return True

@user_bp.route("/profile")
def profile_self():
    if not check_logged_in():
        return redirect(url_for("auth.login"))
    return redirect(url_for("user.profile", user_id=session.get("user_id")))

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A01: Broken Access Control - IDOR)
# The endpoint checks if user is logged in, but fails to verify that the logged-in
# user owns the profile (session['user_id'] == user_id).
# Any user can view other users' profile data by changing the ID in the URL.
# ==============================================================================
@user_bp.route("/profile/<int:user_id>")
def profile(user_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, bio, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("Profile not found.", "warning")
        return redirect(url_for("public.index"))

    return render_template("profile.html", user=user)

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A01: IDOR Modification)
# Allows changing any user's profile biography without authorization check.
# ==============================================================================
@user_bp.route("/profile/<int:user_id>/update", methods=["POST"])
def update_profile(user_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    new_bio = request.form.get("bio", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (new_bio, user_id))
    conn.commit()
    conn.close()

    flash("Profile updated successfully.", "success")
    return redirect(url_for("user.profile", user_id=user_id))

@user_bp.route("/cart")
def cart():
    cart_items = session.get("cart", {})
    conn = get_db_connection()
    cursor = conn.cursor()
    items = []
    total = 0.0
    for prod_id_str, qty in cart_items.items():
        cursor.execute("SELECT * FROM products WHERE id = ?", (int(prod_id_str),))
        prod = cursor.fetchone()
        if prod:
            subtotal = prod["price"] * qty
            total += subtotal
            items.append({"product": prod, "quantity": qty, "subtotal": subtotal})
    conn.close()
    return render_template("cart.html", items=items, total=total)

@user_bp.route("/cart/add/<int:product_id>")
def add_to_cart(product_id):
    if "cart" not in session:
        session["cart"] = {}
    cart = session["cart"]
    prod_id_str = str(product_id)
    cart[prod_id_str] = cart.get(prod_id_str, 0) + 1
    session.modified = True
    flash("Item added to cart.", "success")
    return redirect(request.referrer or url_for("public.products"))

@user_bp.route("/cart/remove/<int:product_id>")
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    prod_id_str = str(product_id)
    if prod_id_str in cart:
        del cart[prod_id_str]
        session["cart"] = cart
        session.modified = True
        flash("Item removed from cart.", "info")
    return redirect(url_for("user.cart"))

@user_bp.route("/cart/clear")
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("Shopping cart cleared.", "info")
    return redirect(url_for("user.cart"))

@user_bp.route("/checkout", methods=["GET", "POST"])
@user_bp.route("/cart/checkout", methods=["GET", "POST"])
def checkout():
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    cart = session.get("cart", {})
    if not cart:
        flash("Your shopping cart is empty.", "warning")
        return redirect(url_for("public.products"))

    if request.method == "GET":
        return redirect(url_for("user.cart"))

    shipping_address = request.form.get("address", "").strip()
    if not shipping_address:
        flash("Please provide a shipping address.", "danger")
        return redirect(url_for("user.cart"))

    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    total_amount = 0.0
    items_to_insert = []
    for prod_id_str, qty in cart.items():
        cursor.execute("SELECT * FROM products WHERE id = ?", (int(prod_id_str),))
        prod = cursor.fetchone()
        if prod:
            price = prod["price"]
            total_amount += price * qty
            items_to_insert.append((int(prod_id_str), qty, price))

    cursor.execute("""
    INSERT INTO orders (user_id, total_amount, shipping_address, status)
    VALUES (?, ?, ?, 'Processing')
    """, (user_id, total_amount, shipping_address))
    new_order_id = cursor.lastrowid

    for pid, qty, uprice in items_to_insert:
        cursor.execute("""
        INSERT INTO order_items (order_id, product_id, quantity, unit_price)
        VALUES (?, ?, ?, ?)
        """, (new_order_id, pid, qty, uprice))

    conn.commit()
    conn.close()

    session["cart"] = {}
    session.modified = True
    flash(f"Order #{new_order_id} placed successfully!", "success")
    return redirect(url_for("user.order_detail", order_id=new_order_id))

@user_bp.route("/orders")
def orders():
    if not check_logged_in():
        return redirect(url_for("auth.login"))
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,))
    user_orders = cursor.fetchall()
    conn.close()
    return render_template("orders.html", orders=user_orders)

# ==============================================================================
# INTENTIONALLY VULNERABLE FOR SECURITY LAB (A01: Broken Access Control - IDOR on Orders)
# Fails to verify that current user owns the order (order['user_id'] == session['user_id']).
# Any customer can view other customers' orders, addresses, and receipts.
# ==============================================================================
@user_bp.route("/order/<int:order_id>")
def order_detail(order_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found.", "warning")
        return redirect(url_for("user.orders"))

    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (order["user_id"],))
    customer = cursor.fetchone()

    cursor.execute("""
    SELECT oi.*, p.name AS product_name
    FROM order_items oi
    JOIN products p ON oi.product_id = p.id
    WHERE oi.order_id = ?
    """, (order_id,))
    items = cursor.fetchall()
    conn.close()

    return render_template("order_detail.html", order=order, customer=customer, items=items)

# ------------------------------------------------------------------------------
# Administrative Routes (A01: Broken Function-Level Authorization)
# ------------------------------------------------------------------------------
def check_admin_vuln():
    # ==============================================================================
    # INTENTIONALLY VULNERABLE FOR SECURITY LAB (A01: Broken Admin Authorization)
    # Only checks if user is logged in, NOT whether role == 'admin'.
    # Standard customer accounts can access the admin dashboard and operations.
    # ==============================================================================
    if "user_id" not in session:
        flash("Authentication required to access admin area.", "warning")
        return False
    return True

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user["password"] == password:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome to Admin Portal, {user['username']}!", "success")
            return redirect(url_for("admin.dashboard"))
        else:
            flash("Invalid administrator credentials.", "danger")
            return render_template("admin_login.html")

    return render_template("admin_login.html")

@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM products")
    product_count = cursor.fetchone()[0]
    cursor.execute("SELECT COALESCE(SUM(total_amount), 0) FROM orders")
    total_sales = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 5")
    recent_orders = cursor.fetchall()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        product_count=product_count,
        total_sales=total_sales,
        recent_orders=recent_orders
    )

@admin_bp.route("/products")
def products():
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    all_prods = cursor.fetchall()
    conn.close()
    return render_template("admin_products.html", products=all_prods)

@admin_bp.route("/products/add", methods=["POST"])
def add_product():
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    name = request.form.get("name", "").strip()
    category = request.form.get("category", "").strip()
    price = float(request.form.get("price", 0.0))
    stock = int(request.form.get("stock", 0))
    desc = request.form.get("description", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO products (name, category, price, stock, description)
    VALUES (?, ?, ?, ?, ?)
    """, (name, category, price, stock, desc))
    conn.commit()
    conn.close()

    flash(f"Product '{name}' added successfully.", "success")
    return redirect(url_for("admin.products"))

@admin_bp.route("/products/delete/<int:product_id>")
def delete_product(product_id):
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()

    flash(f"Product #{product_id} deleted successfully.", "info")
    return redirect(url_for("admin.products"))

@admin_bp.route("/users")
def users():
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, password, password_algo, created_at FROM users ORDER BY id ASC")
    all_users = cursor.fetchall()
    conn.close()
    return render_template("admin_users.html", users=all_users)

@admin_bp.route("/users/delete/<int:user_id>")
def delete_user(user_id):
    if not check_admin_vuln():
        return redirect(url_for("admin.admin_login"))

    if user_id == session.get("user_id"):
        flash("Cannot delete your own active administrator account.", "danger")
        return redirect(url_for("admin.users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash(f"User account #{user_id} deleted.", "info")
    return redirect(url_for("admin.users"))

# Register Blueprints
app.register_blueprint(public_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

if __name__ == "__main__":
    init_db()
    print("\n" + "="*70)
    print("  SecureShop — Intentionally Vulnerable Version (Security Lab)")
    print("  Host: 127.0.0.1:5000")
    print("  Debug Mode: True (Interactive Debugger Exposed)")
    print("  Database: SQLite (vulnerable/database.db)")
    print("="*70 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
